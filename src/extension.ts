import { spawnSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { stat } from "node:fs/promises";
import { join } from "node:path";
import { ensureDefaultConfig, getConfigPath, loadConfig } from "./config/load.ts";
import type { SecurityReviewConfig } from "./config/schema.ts";
import { getGitHubRemote } from "./git/repo.ts";
import { buildCommentBody, publishSecurityReviewComment } from "./github/comments.ts";
import { filterFindings } from "./security/filters.ts";
import {
  parseSecurityReviewMarkdown,
  type SecurityReviewMarkerPayload,
} from "./security/findings.ts";
import { buildSecurityPrompt } from "./security/prompt.ts";
import { renderSecurityReviewMarkdown } from "./security/report.ts";
import {
  readLatestJson,
  readLatestMarkdown,
  writeLatestJson,
  writeLatestMarkdown,
} from "./store/reportStore.ts";
import { buildSecurityReviewContext } from "./tools/buildContext.ts";
import { registerSecurityReviewTools } from "./tools/register.ts";

interface ExtensionAPI {
  registerCommand(
    name: string,
    command: {
      description: string;
      handler(args: string, ctx: SecurityReviewCommandContext): Promise<void>;
    },
  ): void;
  on?(
    event: string,
    handler: (payload: unknown, ctx: SecurityReviewEventContext) => void | Promise<void>,
  ): void;
  sendUserMessage?(
    message: string,
    options?: { deliverAs?: "steer" | "followUp" },
  ): void | Promise<void>;
  setModel?(model: unknown): Promise<boolean> | boolean;
  registerTool?(tool: any): void;
}

interface SecurityReviewCommandContext extends SecurityReviewEventContext {
  waitForIdle?(): Promise<void>;
  isIdle?(): boolean;
  sendUserMessage?(
    message: string,
    options?: { deliverAs?: "steer" | "followUp" },
  ): void | Promise<void>;
  modelRegistry?: { find(provider: string, model: string): unknown };
  model?: { provider?: string; id?: string; model?: string };
}

interface SecurityReviewEventContext {
  cwd: string;
  hasUI?: boolean;
  ui?: SecurityReviewUI;
}

interface SecurityReviewUI {
  notify?(message: string, level?: "info" | "warning" | "error"): void;
  setStatus?(key: string, value: string | undefined): void;
  editor?(title: string, content: string): void | Promise<void>;
  setEditorText?(content: string): void;
}

type FooterState = "ready" | "disabled" | "no-git" | "reviewing";

const COMMANDS = [
  ["security-review-status", "Show pi-security-review health and current safe status."],
  ["security-review-config", "Show or create pi-security-review repo-local config."],
  ["security-review", "Queue focused security review prompt for current diff/scope."],
  ["security-review-panel", "Show latest security review report when available."],
  [
    "security-review-comment",
    "Preview or post latest security-review report as a gated GitHub PR comment.",
  ],
  ["security-review-ci-help", "Show CI usage guidance for pi-security-review."],
] as const;

let latestQueuedReview:
  | {
      repoRoot: string;
      queuedAt: string;
      promptChars: number;
      model?: string;
      agents?: Array<{ role: string; model?: string; thinkingLevel?: string | null }>;
    }
  | undefined;

export default async function securityReviewExtension(pi: ExtensionAPI): Promise<void> {
  registerSecurityReviewTools(pi);

  for (const [name, description] of COMMANDS) {
    pi.registerCommand(name, {
      description,
      handler: async (args, ctx) => handleCommand(pi, name, args, ctx),
    });
  }

  pi.on?.("session_start", async (_event, ctx) => {
    const state = readFooterState(ctx.cwd);
    notify(ctx, `pi-security-review loaded (${state}). Use /security-review-status.`, "info");
    setStatus(ctx, state);
  });

  pi.on?.("message_end", async (payload, ctx) => {
    const text = extractResponseText(payload);
    if (!text) return;

    const parsed = parseSecurityReviewMarkdown(text);
    if (!parsed.marker) return;
    const repoRoot = findGitRoot(ctx.cwd) ?? latestQueuedReview?.repoRoot;
    if (!repoRoot) return;

    const loaded = await loadConfig(repoRoot).catch(() => undefined);
    const filteredPayload = parsed.marker?.value
      ? applyDeterministicCaptureFilters(parsed.marker.value, loaded?.config)
      : undefined;
    const structured = filteredPayload
      ? {
          version: 1,
          generatedAt: new Date().toISOString(),
          repoRoot,
          summary: filteredPayload.analysisSummary,
          findings: filteredPayload.findings,
          excludedFindings: filteredPayload.excludedFindings,
          metadata: {
            ...filteredPayload.metadata,
            model: filteredPayload.metadata?.model ?? latestQueuedReview?.model,
            agents: filteredPayload.metadata?.agents ?? latestQueuedReview?.agents,
            promptChars: filteredPayload.metadata?.promptChars ?? latestQueuedReview?.promptChars,
            parseWarning: parsed.warning,
          },
        }
      : {
          version: 1,
          generatedAt: new Date().toISOString(),
          repoRoot,
          summary: {
            filesReviewed: 0,
            highSeverity: 0,
            mediumSeverity: 0,
            lowSeverity: 0,
            reviewCompleted: false,
          },
          findings: [],
          excludedFindings: [],
          metadata: {
            parseWarning: parsed.warning ?? "Security-review marker missing parsed payload.",
          },
        };

    const markdown = filteredPayload
      ? renderSecurityReviewMarkdown(filteredPayload, { title: "Security Review" })
      : parsed.markdown.trim();
    await writeLatestMarkdown(repoRoot, markdown);
    await writeLatestJson(repoRoot, structured);
    notify(
      ctx,
      `security-review report captured: ${join(repoRoot, ".pi", "security-review")}`,
      parsed.warning ? "warning" : "info",
    );
    setStatus(ctx, "ready");
  });
}

async function handleCommand(
  pi: ExtensionAPI,
  name: (typeof COMMANDS)[number][0],
  args: string,
  ctx: SecurityReviewCommandContext,
): Promise<void> {
  await ctx.waitForIdle?.();

  switch (name) {
    case "security-review-status":
      return showStatus(ctx);
    case "security-review-config":
      return showConfig(ctx, args);
    case "security-review":
      return runSecurityReview(pi, ctx, args);
    case "security-review-panel":
      return showPanelPlaceholder(ctx);
    case "security-review-comment":
      return showCommentPlaceholder(ctx, args);
    case "security-review-ci-help":
      return showCiHelp(ctx);
  }
}

async function showStatus(ctx: SecurityReviewCommandContext): Promise<void> {
  const repoRoot = findGitRoot(ctx.cwd);
  const state = readFooterState(ctx.cwd);
  setStatus(ctx, state);

  if (!repoRoot) {
    notify(
      ctx,
      [
        "pi-security-review status",
        `state: ${state}`,
        "repoRoot: not detected",
        "config: unavailable outside git repo",
        "latestReport: unavailable outside git repo",
        `activeModel: ${getActiveModelId(ctx) ?? "unknown"}`,
        "configuredModelProfiles: unavailable outside git repo",
        "githubRemote: unavailable outside git repo",
        "ghAuth: unavailable outside git repo",
        "networkWrite: disabled",
      ].join("\n"),
      "warning",
    );
    return;
  }

  let configStatus = "unknown";
  let profileSummary = "unknown";
  try {
    const loaded = await loadConfig(repoRoot);
    configStatus = `${loaded.path} (${loaded.exists ? "exists" : "missing, defaults active"}, ${loaded.config.enabled ? "enabled" : "disabled"})`;
    profileSummary = formatModelProfiles(loaded.config.modelProfiles);
  } catch (error) {
    configStatus = `invalid: ${(error as Error).message}`;
  }

  const remote = await getGitHubRemote(repoRoot).catch(() => undefined);
  const latestReport = await getLatestReportStatus(repoRoot);

  notify(
    ctx,
    [
      "pi-security-review status",
      `state: ${state}`,
      `repoRoot: ${repoRoot}`,
      `config: ${configStatus}`,
      `latestReport: ${latestReport}`,
      `activeModel: ${getActiveModelId(ctx) ?? "unknown"}`,
      `configuredModelProfiles: ${profileSummary}`,
      `githubRemote: ${remote ? `${remote.owner}/${remote.repo} (${remote.url})` : "not detected"}`,
      `ghAuth: ${getGhAuthStatus(repoRoot)}`,
      "networkWrite: disabled",
    ].join("\n"),
    state === "no-git" ? "warning" : "info",
  );
}

async function showConfig(ctx: SecurityReviewCommandContext, args: string): Promise<void> {
  const repoRoot = findGitRoot(ctx.cwd);
  if (!repoRoot) {
    notify(ctx, "security-review config unavailable: not inside git repo.", "warning");
    return;
  }

  try {
    if (args.trim() === "--create") {
      const result = await ensureDefaultConfig(repoRoot);
      notify(
        ctx,
        `security-review config ${result.created ? "created" : "already exists"}: ${result.path}`,
        "info",
      );
      return;
    }

    const loaded = await loadConfig(repoRoot);
    notify(
      ctx,
      [
        "security-review config",
        `path: ${loaded.path}`,
        `exists: ${loaded.exists}`,
        `enabled: ${loaded.config.enabled}`,
        `reportDir: ${join(repoRoot, ".pi", "security-review")}`,
      ].join("\n"),
      "info",
    );
  } catch (error) {
    notify(ctx, (error as Error).message, "error");
  }
}

async function runSecurityReview(
  pi: ExtensionAPI,
  ctx: SecurityReviewCommandContext,
  rawArgs: string,
): Promise<void> {
  const repoRoot = findGitRoot(ctx.cwd);
  if (!repoRoot) {
    notify(
      ctx,
      "security-review cannot run: not inside git repo. No network write performed.",
      "warning",
    );
    return;
  }

  let flags: ReviewFlags;
  try {
    flags = parseReviewArgs(rawArgs);
  } catch (error) {
    notify(ctx, (error as Error).message, "error");
    return;
  }

  const loaded = await loadConfig(repoRoot);
  if (!loaded.config.enabled) {
    notify(ctx, "security-review disabled by config. No network write performed.", "warning");
    return;
  }

  const activeModel = getActiveModelId(ctx);
  const modelSwitch = await applyTemporaryModelOverride(pi, ctx, flags.model);
  if (!modelSwitch.ok) {
    notify(ctx, modelSwitch.error, "error");
    return;
  }

  try {
    const context = await buildSecurityReviewContext({
      repoRoot,
      config: loaded.config,
      base: flags.base,
      head: flags.head,
      from: flags.from,
      to: flags.to,
      paths: flags.paths,
      activeModel: modelSwitch.selectedModel ?? activeModel,
      requestedModel: flags.model,
      customSecurityScanInstructionsText: flags.scanInstructionsText,
      falsePositiveFilteringInstructionsText: flags.filterInstructionsText,
      customSecurityScanInstructionsFile: flags.scanInstructionsFile,
      falsePositiveFilteringInstructionsFile: flags.filterInstructionsFile,
    });

    const prompt = buildSecurityPrompt({
      context: context.payload,
      config: loaded.config,
      customSecurityScanInstructions: context.payload.customInstructions.scan?.text,
      falsePositiveFilteringInstructions: context.payload.customInstructions.filter?.text,
    });

    const send = pi.sendUserMessage ?? ctx.sendUserMessage;
    if (typeof send !== "function") {
      notify(
        ctx,
        "security-review cannot queue prompt: Pi sendUserMessage API unavailable.",
        "error",
      );
      return;
    }

    const busy = typeof ctx.isIdle === "function" ? !ctx.isIdle() : false;
    await send(prompt.text, busy ? { deliverAs: "followUp" } : undefined);
    latestQueuedReview = {
      repoRoot,
      queuedAt: new Date().toISOString(),
      promptChars: prompt.text.length,
      model: modelSwitch.selectedModel ?? activeModel,
      agents: context.payload.model.agents,
    };
    setStatus(ctx, "reviewing");
    notify(
      ctx,
      [
        `security-review prompt queued (${busy ? "follow-up" : "direct"})`,
        `scope: ${context.payload.scope.type}`,
        `files: ${context.payload.filesReviewed.length}`,
        `model: ${modelSwitch.selectedModel ?? activeModel ?? "active Pi model"}`,
        context.truncated ? "warning: context truncated" : undefined,
        ...flags.warnings.map((warning) => `warning: ${warning}`),
        ...context.warnings.map((warning) => `warning: ${warning}`),
      ]
        .filter(Boolean)
        .join("\n"),
      context.warnings.length > 0 || flags.warnings.length > 0 ? "warning" : "info",
    );
  } finally {
    if (modelSwitch.restore) await modelSwitch.restore();
  }
}

interface ReviewFlags {
  base?: string;
  head?: string;
  from?: string;
  to?: string;
  model?: string;
  scanInstructionsText?: string;
  filterInstructionsText?: string;
  scanInstructionsFile?: string;
  filterInstructionsFile?: string;
  warnings: string[];
  paths: string[];
}

function applyDeterministicCaptureFilters(
  payload: SecurityReviewMarkerPayload,
  config?: SecurityReviewConfig,
): SecurityReviewMarkerPayload {
  const filtered = filterFindings(payload.findings, { config });
  const summary = {
    ...payload.analysisSummary,
    highSeverity: filtered.summary.highSeverity,
    mediumSeverity: filtered.summary.mediumSeverity,
    lowSeverity: filtered.summary.lowSeverity,
    findingsTotal: filtered.summary.keptFindings,
    excludedFindings: filtered.summary.excludedFindings + payload.excludedFindings.length,
  };
  const metadata = {
    ...payload.metadata,
    filtering: {
      deterministic: {
        executed: true,
        total: filtered.summary.totalFindings,
        kept: filtered.summary.keptFindings,
        excluded: filtered.summary.excludedFindings,
        stages: {
          hard_rules: filtered.summary.hardExcluded,
          confidence: filtered.summary.confidenceExcluded,
          severity: filtered.summary.severityExcluded,
        },
        exclusionBreakdown: filtered.summary.exclusionBreakdown,
      },
      model: {
        executed: false,
        status: config?.enableModelFiltering
          ? "deferred: model filter role not executed in capture hook"
          : "disabled/deferred",
      },
    },
  };
  return {
    ...payload,
    findings: filtered.findings,
    excludedFindings: [...payload.excludedFindings, ...filtered.excludedFindings],
    analysisSummary: summary,
    metadata,
  };
}

function parseReviewArgs(rawArgs: string): ReviewFlags {
  const tokens = rawArgs.match(/(?:[^\s"']+|"[^"]*"|'[^']*')+/gu) ?? [];
  const args = tokens.map((token) => token.replace(/^(["'])(.*)\1$/u, "$2"));
  const flags: ReviewFlags = { paths: [], warnings: [] };
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    const next = args[index + 1];
    if (arg === "--base") {
      flags.base = requireOptionValue(arg, next);
      index += 1;
    } else if (arg === "--head") {
      flags.head = requireOptionValue(arg, next);
      index += 1;
    } else if (arg === "--from") {
      flags.from = requireOptionValue(arg, next);
      index += 1;
    } else if (arg === "--to") {
      flags.to = requireOptionValue(arg, next);
      index += 1;
    } else if (arg === "--model") {
      flags.model = requireOptionValue(arg, next);
      index += 1;
    } else if (arg === "--scan-instructions-file") {
      flags.scanInstructionsFile = requireOptionValue(arg, next);
      index += 1;
    } else if (arg === "--filter-instructions-file") {
      flags.filterInstructionsFile = requireOptionValue(arg, next);
      index += 1;
    } else if (arg === "--scan-instructions-text") {
      flags.scanInstructionsText = requireOptionValue(arg, next);
      index += 1;
    } else if (arg === "--filter-instructions-text") {
      flags.filterInstructionsText = requireOptionValue(arg, next);
      index += 1;
    } else if (arg === "--scan-instructions") {
      flags.scanInstructionsText = requireOptionValue(arg, next);
      flags.warnings.push(
        "--scan-instructions is deprecated and treated as inline text; use --scan-instructions-text or --scan-instructions-file.",
      );
      index += 1;
    } else if (arg === "--filter-instructions") {
      flags.filterInstructionsText = requireOptionValue(arg, next);
      flags.warnings.push(
        "--filter-instructions is deprecated and treated as inline text; use --filter-instructions-text or --filter-instructions-file.",
      );
      index += 1;
    } else if (arg?.startsWith("-")) throw new Error(`Unknown /security-review option: ${arg}`);
    else if (arg) flags.paths.push(arg);
  }
  return flags;
}

function requireOptionValue(option: string, value: string | undefined): string {
  if (!value || value.startsWith("-"))
    throw new Error(`Missing value for /security-review ${option}.`);
  return value;
}

async function applyTemporaryModelOverride(
  pi: ExtensionAPI,
  ctx: SecurityReviewCommandContext,
  requested?: string,
): Promise<
  { ok: true; selectedModel?: string; restore?: () => Promise<void> } | { ok: false; error: string }
> {
  if (!requested) return { ok: true };
  const slash = requested.indexOf("/");
  if (slash <= 0 || slash === requested.length - 1) {
    return { ok: false, error: "security-review --model must use provider/model form." };
  }
  if (typeof pi.setModel !== "function" || !ctx.modelRegistry?.find) {
    return {
      ok: false,
      error:
        "security-review --model unavailable in this Pi host: model registry/setModel API missing.",
    };
  }
  const provider = requested.slice(0, slash);
  const modelId = requested.slice(slash + 1);
  const model = ctx.modelRegistry.find(provider, modelId);
  if (!model) return { ok: false, error: `security-review model not found: ${requested}` };
  const previous = ctx.model;
  const switched = await pi.setModel(model);
  if (!switched)
    return {
      ok: false,
      error: `security-review model unavailable or unauthenticated: ${requested}`,
    };
  return {
    ok: true,
    selectedModel: requested,
    restore: previous
      ? async () => {
          await pi.setModel?.(previous);
        }
      : undefined,
  };
}

async function showPanelPlaceholder(ctx: SecurityReviewCommandContext): Promise<void> {
  const repoRoot = findGitRoot(ctx.cwd);
  if (!repoRoot) {
    notify(ctx, "No security review report available: not inside git repo.", "warning");
    return;
  }

  try {
    const markdown = await readLatestMarkdown(repoRoot);
    const json = await readLatestJson(repoRoot).catch((error) => ({
      parseWarning: (error as Error).message,
    }));
    if (!markdown) {
      notify(ctx, "No security review report available yet.", "info");
      return;
    }
    const warning = json && "parseWarning" in json ? `\n\nWarning: ${json.parseWarning}` : "";
    if (ctx.ui?.editor) {
      await ctx.ui.editor("pi-security-review latest report", `${markdown}${warning}`);
      return;
    }
    notify(ctx, `${markdown}${warning}`, "info");
  } catch (error) {
    notify(ctx, (error as Error).message, "error");
  }
}

async function showCommentPlaceholder(
  ctx: SecurityReviewCommandContext,
  args: string,
): Promise<void> {
  const repoRoot = findGitRoot(ctx.cwd);
  if (!repoRoot) {
    notify(ctx, "security-review comment refused: not inside git repo.", "warning");
    return;
  }

  let flags: CommentFlags;
  try {
    flags = parseCommentArgs(args);
  } catch (error) {
    notify(ctx, (error as Error).message, "error");
    return;
  }

  const markdown = await readLatestMarkdown(repoRoot);
  if (!markdown) {
    notify(
      ctx,
      "security-review comment refused: latest report missing. Run /security-review first.",
      "warning",
    );
    return;
  }

  const loaded = await loadConfig(repoRoot);
  if (flags.dryRun) {
    const body = buildCommentBody(markdown, loaded.config);
    notify(
      ctx,
      [
        "security-review comment dry-run",
        `pr: ${flags.pr ?? "not specified"}`,
        "mode: dry-run",
        "",
        body,
      ].join("\n"),
      "info",
    );
    return;
  }

  const remote = await getGitHubRemote(repoRoot);
  if (!remote) {
    notify(ctx, "security-review comment refused: GitHub remote not detected.", "warning");
    return;
  }

  const latestJson = flags.inline
    ? await readLatestJson(repoRoot).catch(() => undefined)
    : undefined;
  const result = await publishSecurityReviewComment({
    repoRoot,
    remote,
    config: loaded.config,
    markdown,
    pr: flags.pr,
    dryRun: flags.dryRun,
    approve: flags.yes,
    updateExisting: flags.updateExisting,
    inline: flags.inline,
    inlineFindings: Array.isArray((latestJson as { findings?: unknown[] } | undefined)?.findings)
      ? ((latestJson as { findings: any[] }).findings as any)
      : undefined,
  });

  if (!result.ok) {
    notify(ctx, `security-review comment refused: ${result.error ?? "unknown error"}`, "error");
    return;
  }

  const lines = [
    result.mode === "dry-run"
      ? "security-review comment dry-run"
      : "security-review comment posted",
    `pr: ${result.pr}`,
    `mode: ${result.mode}`,
    result.url ? `url: ${result.url}` : undefined,
    result.inlineCount !== undefined ? `inlineComments: ${result.inlineCount}` : undefined,
    result.fallbackCount !== undefined ? `inlineFallbacks: ${result.fallbackCount}` : undefined,
    result.warnings.length ? `warnings: ${result.warnings.join("; ")}` : undefined,
    "",
    result.body,
  ].filter(Boolean);
  notify(ctx, lines.join("\n"), result.mode === "dry-run" ? "info" : "warning");
}

interface CommentFlags {
  dryRun: boolean;
  pr?: number;
  yes: boolean;
  updateExisting: boolean;
  inline: boolean;
}

function parseCommentArgs(rawArgs: string): CommentFlags {
  const tokens = rawArgs.match(/(?:[^\s"']+|"[^"]*"|'[^']*')+/gu) ?? [];
  const args = tokens.map((token) => token.replace(/^(["'])(.*)\1$/u, "$2"));
  const flags: CommentFlags = { dryRun: true, yes: false, updateExisting: false, inline: false };
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    const next = args[index + 1];
    if (arg === "--dry-run") flags.dryRun = true;
    else if (arg === "--pr") {
      const value = Number.parseInt(requireOptionValue(arg, next), 10);
      if (!Number.isInteger(value) || value <= 0)
        throw new Error("/security-review-comment --pr must be a positive integer.");
      flags.pr = value;
      index += 1;
    } else if (arg === "--yes") {
      flags.yes = true;
      flags.dryRun = false;
    } else if (arg === "--update-existing") flags.updateExisting = true;
    else if (arg === "--inline") flags.inline = true;
    else if (arg?.startsWith("-"))
      throw new Error(`Unknown /security-review-comment option: ${arg}`);
  }
  return flags;
}

function showCiHelp(ctx: SecurityReviewCommandContext): void {
  notify(
    ctx,
    [
      "pi-security-review CI help",
      "artifact mode: bun run security-review:ci -- --base origin/main --head HEAD --output security-review-results.json --markdown security-review-report.md",
      "final report mode: add --final-report <path> and optional --fail-on-high/--fail-on-medium.",
      "comment mode: requires --comment --yes --pr <number> plus --final-report unless maintainer override --allow-artifact-comment.",
      "default: no model call and no GitHub/network write.",
    ].join("\n"),
    "info",
  );
}

function readFooterState(cwd: string): FooterState {
  const repoRoot = findGitRoot(cwd);
  if (!repoRoot) return "no-git";
  const configPath = getConfigPath(repoRoot);
  if (isDisabled(configPath)) return "disabled";
  return "ready";
}

function findGitRoot(cwd: string): string | undefined {
  const result = spawnSync("git", ["rev-parse", "--show-toplevel"], {
    cwd,
    encoding: "utf8",
    timeout: 2000,
  });
  if (result.status !== 0) return undefined;
  const root = result.stdout.trim();
  return root.length > 0 ? root : undefined;
}

async function getLatestReportStatus(repoRoot: string): Promise<string> {
  const markdownPath = join(repoRoot, ".pi", "security-review", "latest-report.md");
  try {
    const info = await stat(markdownPath);
    return `${markdownPath} (${info.mtime.toISOString()})`;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return "none";
    return `unavailable: ${(error as Error).message}`;
  }
}

function formatModelProfiles(
  profiles: Record<
    string,
    { provider: string | null; model: string | null; thinkingLevel: string | null }
  >,
): string {
  return Object.entries(profiles)
    .map(([name, profile]) => {
      const model =
        profile.provider && profile.model ? `${profile.provider}/${profile.model}` : "active";
      const thinking = profile.thinkingLevel ? `, thinking=${profile.thinkingLevel}` : "";
      return `${name}=${model}${thinking}`;
    })
    .join(", ");
}

function getGhAuthStatus(cwd: string): string {
  const result = spawnSync("gh", ["auth", "status"], { cwd, encoding: "utf8", timeout: 3_000 });
  if ((result.error as NodeJS.ErrnoException | undefined)?.code === "ENOENT")
    return "gh not installed";
  if (result.status === 0) return "authenticated";
  const output = `${result.stderr || result.stdout}`.trim().split("\n")[0];
  return output ? `not authenticated (${output})` : "not authenticated";
}

function isDisabled(configPath: string): boolean {
  if (!existsSync(configPath)) return false;
  try {
    const parsed = JSON.parse(readFileSync(configPath, "utf8")) as { enabled?: unknown };
    return parsed.enabled === false;
  } catch {
    return false;
  }
}

function setStatus(ctx: SecurityReviewEventContext, state: FooterState): void {
  ctx.ui?.setStatus?.("security-review", `security-review: ${state}`);
}

function notify(
  ctx: SecurityReviewEventContext,
  message: string,
  level: "info" | "warning" | "error" = "info",
): void {
  if (ctx.ui?.notify) {
    ctx.ui.notify(message, level);
    return;
  }
  if (ctx.ui?.setEditorText) ctx.ui.setEditorText(message);
}

function getActiveModelId(ctx: SecurityReviewCommandContext): string | undefined {
  if (!ctx.model) return undefined;
  const provider = ctx.model.provider;
  const id = ctx.model.id ?? ctx.model.model;
  return provider && id ? `${provider}/${id}` : undefined;
}

function extractResponseText(payload: unknown): string | undefined {
  const text = collectTextFragments(payload, new Set()).join("").trim();
  return text.length > 0 ? text : undefined;
}

function collectTextFragments(value: unknown, seen: Set<unknown>): string[] {
  if (typeof value === "string") return [value];
  if (!value || typeof value !== "object") return [];
  if (seen.has(value)) return [];
  seen.add(value);

  if (Array.isArray(value)) return value.flatMap((item) => collectTextFragments(item, seen));

  const record = value as Record<string, unknown>;
  const direct = [record.text, record.content]
    .flatMap((item) => collectTextFragments(item, seen))
    .filter((item) => item.length > 0);
  if (direct.length > 0) return direct;

  const nestedKeys = ["message", "response", "output", "result", "data", "choices"];
  return nestedKeys.flatMap((key) => collectTextFragments(record[key], seen));
}
