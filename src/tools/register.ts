/** LLM tool registration for pi-security-review. */

import { Type } from "typebox";
import { getConfigPath, loadConfig } from "../config/load.ts";
import type { SecurityReviewConfig } from "../config/schema.ts";
import { resolveDiffScope } from "../git/diff.ts";
import { detectGitRoot, getCurrentBranch, getGitHubRemote } from "../git/repo.ts";
import { getWorkingTreeStatus } from "../git/status.ts";
import { buildCommentBody, publishSecurityReviewComment } from "../github/comments.ts";
import { filterFindings } from "../security/filters.ts";
import { normalizePayload } from "../security/findings.ts";
import { renderSarifLikeJson, renderSecurityReviewMarkdown } from "../security/report.ts";
import {
  readLatestJson,
  readLatestMarkdown,
  writeLatestJson,
  writeLatestMarkdown,
} from "../store/reportStore.ts";
import { buildSecurityReviewContext } from "./buildContext.ts";

export const MAX_TOOL_CHARS = 50_000;
export const MAX_TOOL_LINES = 2_000;

export interface SecurityReviewToolContext {
  cwd: string;
  hasUI?: boolean;
  model?: { provider?: string; id?: string; model?: string };
}

export interface ToolResult {
  content: Array<{ type: "text"; text: string }>;
  details: Record<string, unknown>;
}

interface ToolDefinition<TParams extends Record<string, unknown>> {
  name: string;
  label: string;
  description: string;
  promptSnippet: string;
  promptGuidelines: string[];
  parameters: unknown;
  execute(
    toolCallId: string,
    params: TParams,
    signal: AbortSignal | undefined,
    onUpdate: ((update: Partial<ToolResult>) => void) | undefined,
    ctx: SecurityReviewToolContext,
  ): Promise<ToolResult>;
}

export function registerSecurityReviewTools(pi: {
  registerTool?<T extends Record<string, unknown>>(tool: ToolDefinition<T>): void;
}): void {
  if (!pi.registerTool) return;

  pi.registerTool(statsTool());
  pi.registerTool(analyzeDiffTool());
  pi.registerTool(buildContextTool());
  pi.registerTool(modelProfilesTool());
  pi.registerTool(filterFindingsTool());
  pi.registerTool(renderReportTool());
  pi.registerTool(githubCommentTool());
}

function statsTool(): ToolDefinition<Record<string, never>> {
  return {
    name: "security_review_stats",
    label: "Security Review Stats",
    description:
      "Show pi-security-review health for current repo: git state, config, latest report, active model, model profiles, and GitHub remote.",
    promptSnippet: "security_review_stats checks pi-security-review status before other tools.",
    promptGuidelines: [
      "Use security_review_stats before other security-review tools when repo/config/report state is uncertain.",
      "Use security_review_stats to check latest report availability before security_review_github_comment.",
    ],
    parameters: Type.Object({}),
    execute: async (_id, _params, _signal, onUpdate, ctx) => {
      onUpdate?.({ content: [{ type: "text", text: "Checking security-review status..." }] });
      const repoRoot = await requireRepoRoot(ctx.cwd);
      const loaded = await loadConfig(repoRoot);
      const [status, branch, github, latestMarkdown, latestJson] = await Promise.all([
        getWorkingTreeStatus(repoRoot),
        getCurrentBranch(repoRoot),
        getGitHubRemote(repoRoot),
        readLatestMarkdown(repoRoot).catch(() => undefined),
        readLatestJson(repoRoot).catch((error) => ({ parseWarning: (error as Error).message })),
      ]);
      return textResult({
        repoRoot,
        branch,
        config: { path: loaded.path, exists: loaded.exists, enabled: loaded.config.enabled },
        git: status,
        github,
        activeModel: getActiveModelId(ctx),
        modelProfiles: loaded.config.modelProfiles,
        latestReport: {
          markdownAvailable: Boolean(latestMarkdown),
          jsonAvailable: Boolean(latestJson),
          parseWarning:
            latestJson && typeof latestJson === "object" && "parseWarning" in latestJson
              ? latestJson.parseWarning
              : undefined,
        },
      });
    },
  };
}

function analyzeDiffTool(): ToolDefinition<{
  base?: string;
  head?: string;
  from?: string;
  to?: string;
  paths?: string[];
}> {
  return {
    name: "security_review_analyze_diff",
    label: "Analyze Security Review Diff",
    description:
      "Resolve current or explicit diff scope using pi-security-review filtering and return bounded file/diff metadata.",
    promptSnippet:
      "security_review_analyze_diff analyzes current or explicit diff scope for security review.",
    promptGuidelines: [
      "Use security_review_analyze_diff before asking for a security review when scope is unclear.",
    ],
    parameters: Type.Object({
      base: Type.Optional(Type.String()),
      head: Type.Optional(Type.String()),
      from: Type.Optional(Type.String()),
      to: Type.Optional(Type.String()),
      paths: Type.Optional(Type.Array(Type.String())),
    }),
    execute: async (_id, params, _signal, _onUpdate, ctx) =>
      withConfig(ctx, async ({ repoRoot, config }) => {
        const scope = await resolveDiffScope(repoRoot, config, params);
        return textResult({
          type: scope.type,
          base: scope.base,
          head: scope.head,
          files: scope.files,
          fileCount: scope.files.length,
          diffBytes: Buffer.byteLength(scope.diff, "utf8"),
          truncated: scope.truncated,
          warnings: scope.warnings,
          diff: scope.diff,
        });
      }),
  };
}

function buildContextTool(): ToolDefinition<{
  base?: string;
  head?: string;
  from?: string;
  to?: string;
  paths?: string[];
  model?: string;
  scanInstructions?: string;
  filterInstructions?: string;
  scanInstructionsFile?: string;
  filterInstructionsFile?: string;
  scanInstructionsText?: string;
  filterInstructionsText?: string;
}> {
  return {
    name: "security_review_build_context",
    label: "Build Security Review Context",
    description:
      "Build bounded provider-neutral security-review context for current or explicit diff scope.",
    promptSnippet:
      "security_review_build_context builds bounded context payload for prompt/report generation.",
    promptGuidelines: [
      "Use security_review_build_context when you need exact bounded context before writing a security review prompt.",
    ],
    parameters: Type.Object({
      base: Type.Optional(Type.String()),
      head: Type.Optional(Type.String()),
      from: Type.Optional(Type.String()),
      to: Type.Optional(Type.String()),
      paths: Type.Optional(Type.Array(Type.String())),
      model: Type.Optional(Type.String()),
      scanInstructions: Type.Optional(Type.String()),
      filterInstructions: Type.Optional(Type.String()),
      scanInstructionsFile: Type.Optional(Type.String()),
      filterInstructionsFile: Type.Optional(Type.String()),
      scanInstructionsText: Type.Optional(Type.String()),
      filterInstructionsText: Type.Optional(Type.String()),
    }),
    execute: async (_id, params, _signal, _onUpdate, ctx) =>
      withConfig(ctx, async ({ repoRoot, config }) => {
        const built = await buildSecurityReviewContext({
          repoRoot,
          config,
          base: params.base,
          head: params.head,
          from: params.from,
          to: params.to,
          paths: params.paths,
          activeModel: getActiveModelId(ctx),
          requestedModel: params.model,
          customSecurityScanInstructionsText:
            params.scanInstructionsText ?? params.scanInstructions,
          falsePositiveFilteringInstructionsText:
            params.filterInstructionsText ?? params.filterInstructions,
          customSecurityScanInstructionsFile: params.scanInstructionsFile,
          falsePositiveFilteringInstructionsFile: params.filterInstructionsFile,
        });
        return textResult(built.payload, {
          contextTruncated: built.truncated,
          contextTotalBytes: built.totalBytes,
          contextOutputBytes: built.outputBytes,
        });
      }),
  };
}

function modelProfilesTool(): ToolDefinition<Record<string, never>> {
  return {
    name: "security_review_model_profiles",
    label: "Security Review Model Profiles",
    description: "Return configured security-review model profiles and active agent pipeline.",
    promptSnippet: "security_review_model_profiles inspects security-review model profile config.",
    promptGuidelines: [
      "Use security_review_model_profiles before selecting security-review role/model metadata.",
    ],
    parameters: Type.Object({}),
    execute: async (_id, _params, _signal, _onUpdate, ctx) =>
      withConfig(ctx, async ({ config }) =>
        textResult({ modelProfiles: config.modelProfiles, agentPipeline: config.agentPipeline }),
      ),
  };
}

function filterFindingsTool(): ToolDefinition<{
  findings: string;
  confidenceThreshold?: number;
  severityThreshold?: "high" | "medium";
  enableHardExclusions?: boolean;
}> {
  return {
    name: "security_review_filter_findings",
    label: "Filter Security Findings",
    description:
      "Normalize and deterministically filter security findings using pi-security-review hard exclusions, confidence, and severity thresholds.",
    promptSnippet: "security_review_filter_findings filters findings using deterministic rules.",
    promptGuidelines: [
      "Use security_review_filter_findings before rendering reports from model-produced findings.",
    ],
    parameters: Type.Object({
      findings: Type.String({
        description: "JSON array of findings or marker payload with findings.",
      }),
      confidenceThreshold: Type.Optional(Type.Number()),
      severityThreshold: Type.Optional(Type.Union([Type.Literal("high"), Type.Literal("medium")])),
      enableHardExclusions: Type.Optional(Type.Boolean()),
    }),
    execute: async (_id, params, _signal, _onUpdate, ctx) =>
      withConfig(ctx, async ({ config }) => {
        const parsed = parseJson(params.findings, "findings");
        const inputFindings = Array.isArray(parsed)
          ? parsed
          : Array.isArray((parsed as Record<string, unknown>).findings)
            ? ((parsed as Record<string, unknown>).findings as unknown[])
            : [];
        return textResult(
          filterFindings(inputFindings, {
            config,
            confidenceThreshold: params.confidenceThreshold,
            severityThreshold: params.severityThreshold,
            enableHardExclusions: params.enableHardExclusions,
          }),
        );
      }),
  };
}

function renderReportTool(): ToolDefinition<{
  payload: string;
  format?: "markdown" | "json" | "sarif";
  title?: string;
  scope?: string;
  persistLatest?: boolean;
}> {
  return {
    name: "security_review_render_report",
    label: "Render Security Review Report",
    description:
      "Render normalized security-review marker payload as Markdown, JSON, or valid SARIF 2.1.0 JSON, and persist latest report by default.",
    promptSnippet: "security_review_render_report renders findings into bounded report output.",
    promptGuidelines: [
      "Use security_review_render_report after security_review_filter_findings to produce final report text.",
      "By default this tool writes .pi/security-review/latest-report.md and latest-report.json; set persistLatest: false to render only.",
    ],
    parameters: Type.Object({
      payload: Type.String({
        description: "JSON marker payload with findings, excludedFindings, and analysisSummary.",
      }),
      format: Type.Optional(
        Type.Union([Type.Literal("markdown"), Type.Literal("json"), Type.Literal("sarif")]),
      ),
      title: Type.Optional(Type.String()),
      scope: Type.Optional(Type.String()),
      persistLatest: Type.Optional(Type.Boolean({ default: true })),
    }),
    execute: async (_id, params, _signal, _onUpdate, ctx) =>
      withConfig(ctx, async ({ repoRoot }) => {
        const payload = normalizePayload(parseJson(params.payload, "payload"));
        const markdown = renderSecurityReviewMarkdown(payload, {
          title: params.title,
          scope: params.scope,
        });
        let markdownPath: string | undefined;
        let jsonPath: string | undefined;
        if (params.persistLatest !== false) {
          markdownPath = await writeLatestMarkdown(repoRoot, markdown);
          jsonPath = await writeLatestJson(repoRoot, {
            version: 1,
            generatedAt: new Date().toISOString(),
            repoRoot,
            summary: payload.analysisSummary,
            findings: payload.findings,
            excludedFindings: payload.excludedFindings,
            metadata: payload.metadata ?? {},
          });
        }

        const details = {
          persisted: params.persistLatest !== false,
          latestMarkdownPath: markdownPath,
          latestJsonPath: jsonPath,
        };
        if (params.format === "json") return textResult(payload, details);
        if (params.format === "sarif") return textResult(renderSarifLikeJson(payload), details);
        return textResult(markdown, details);
      }),
  };
}

function githubCommentTool(): ToolDefinition<{
  reportMarkdown?: string;
  reportPayload?: string;
  pr?: number;
  post?: boolean;
  approve?: boolean;
  updateExisting?: boolean;
  inline?: boolean;
}> {
  return {
    name: "security_review_github_comment",
    label: "Security Review GitHub Comment",
    description:
      "Preview or post a GitHub PR security-review comment. DRY-RUN by default; posting requires post: true and approve: true.",
    promptSnippet:
      "security_review_github_comment previews latest report as GitHub PR comment; posting requires post: true and approve: true.",
    promptGuidelines: [
      "Use security_review_github_comment only after report content is finalized.",
      "security_review_github_comment is dry-run by default; never post unless user explicitly approved post: true and approve: true.",
    ],
    parameters: Type.Object({
      reportMarkdown: Type.Optional(Type.String()),
      reportPayload: Type.Optional(Type.String()),
      pr: Type.Optional(Type.Number()),
      post: Type.Optional(Type.Boolean({ default: false })),
      approve: Type.Optional(Type.Boolean({ default: false })),
      updateExisting: Type.Optional(Type.Boolean({ default: false })),
      inline: Type.Optional(Type.Boolean({ default: false })),
    }),
    execute: async (_id, params, _signal, _onUpdate, ctx) =>
      withConfig(ctx, async ({ repoRoot, config }) => {
        const payload = params.reportPayload
          ? normalizePayload(parseJson(params.reportPayload, "reportPayload"))
          : undefined;
        const latestJson =
          !payload && params.inline
            ? await readLatestJson(repoRoot).catch(() => undefined)
            : undefined;
        const markdown =
          params.reportMarkdown ??
          (payload ? renderSecurityReviewMarkdown(payload) : await readLatestMarkdown(repoRoot));
        if (!markdown)
          throw new Error("security_review_github_comment refused: latest report missing.");
        if (params.post !== true) {
          const body = buildCommentBody(markdown, config);
          return textResult(
            [
              "--- GitHub PR comment ---",
              "mode: dry-run",
              `PR: ${params.pr ?? "not specified"}`,
              "",
              body,
            ].join("\n"),
            { dryRun: true, post: false, approve: params.approve === true, mode: "dry-run" },
          );
        }
        if (params.approve !== true)
          throw new Error(
            "security_review_github_comment refused: posting requires post: true and approve: true.",
          );
        const remote = await getGitHubRemote(repoRoot);
        if (!remote)
          throw new Error("security_review_github_comment refused: GitHub remote not detected.");
        const result = await publishSecurityReviewComment({
          repoRoot,
          remote,
          config,
          markdown,
          pr: params.pr,
          dryRun: params.post !== true,
          approve: params.approve === true,
          updateExisting: params.updateExisting === true,
          inline: params.inline === true,
          inlineFindings:
            payload?.findings ??
            (Array.isArray((latestJson as { findings?: unknown[] } | undefined)?.findings)
              ? ((latestJson as { findings: any[] }).findings as any)
              : undefined),
        });
        if (!result.ok)
          throw new Error(
            `security_review_github_comment refused: ${result.error ?? "unknown error"}`,
          );
        return textResult(
          [
            "--- GitHub PR comment ---",
            `mode: ${result.mode}`,
            `PR: ${result.pr}`,
            result.url ? `url: ${result.url}` : undefined,
            "",
            result.body,
          ]
            .filter(Boolean)
            .join("\n"),
          {
            dryRun: result.mode === "dry-run",
            post: params.post === true,
            approve: params.approve === true,
            mode: result.mode,
            url: result.url,
          },
        );
      }),
  };
}

async function withConfig<T>(
  ctx: SecurityReviewToolContext,
  fn: (args: { repoRoot: string; config: SecurityReviewConfig }) => Promise<T>,
): Promise<T> {
  const repoRoot = await requireRepoRoot(ctx.cwd);
  const loaded = await loadConfig(repoRoot);
  if (!loaded.config.enabled)
    throw new Error(`pi-security-review disabled by config: ${getConfigPath(repoRoot)}`);
  return fn({ repoRoot, config: loaded.config });
}

async function requireRepoRoot(cwd: string): Promise<string> {
  const repoRoot = await detectGitRoot(cwd);
  if (!repoRoot)
    throw new Error("Not inside a git repository. Run pi-security-review from a git repo.");
  return repoRoot;
}

function parseJson(text: string, label: string): unknown {
  try {
    return JSON.parse(text);
  } catch (error) {
    throw new Error(`Invalid ${label} JSON: ${(error as Error).message}`);
  }
}

function textResult(value: unknown, details: Record<string, unknown> = {}): ToolResult {
  const raw = typeof value === "string" ? value : JSON.stringify(value, null, 2);
  const lines = raw.split("\n");
  const lineTruncated = lines.length > MAX_TOOL_LINES;
  const byLine = lineTruncated
    ? `${lines.slice(0, MAX_TOOL_LINES).join("\n")}\n[truncated: max lines]`
    : raw;
  const charTruncated = byLine.length > MAX_TOOL_CHARS;
  const text = charTruncated
    ? `${byLine.slice(0, MAX_TOOL_CHARS)}\n[truncated: max chars]`
    : byLine;
  return {
    content: [{ type: "text", text }],
    details: {
      ...details,
      truncated: lineTruncated || charTruncated,
      maxChars: MAX_TOOL_CHARS,
      maxLines: MAX_TOOL_LINES,
    },
  };
}

function getActiveModelId(ctx: SecurityReviewToolContext): string | undefined {
  if (!ctx.model) return undefined;
  const provider = ctx.model.provider;
  const id = ctx.model.id ?? ctx.model.model;
  return provider && id ? `${provider}/${id}` : undefined;
}
