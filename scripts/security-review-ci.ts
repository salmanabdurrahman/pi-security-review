#!/usr/bin/env bun
/** Headless CI entrypoint for pi-security-review. */

import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { loadConfig } from "../src/config/load.ts";
import type { SecurityReviewConfig } from "../src/config/schema.ts";
import { detectGitRoot, getGitHubRemote } from "../src/git/repo.ts";
import { publishSecurityReviewComment } from "../src/github/comments.ts";
import {
  buildSecurityReviewMarkerJson,
  parseSecurityReviewMarkdown,
  type SecurityReviewMarkerPayload,
} from "../src/security/findings.ts";
import { buildSecurityPrompt } from "../src/security/prompt.ts";
import { redactSecretLikeValues, redactSecretsInValue } from "../src/security/redaction.ts";
import { renderSecurityReviewMarkdown } from "../src/security/report.ts";
import { writeLatestJson, writeLatestMarkdown } from "../src/store/reportStore.ts";
import { buildSecurityReviewContext, type PullRequestMetadata } from "../src/tools/buildContext.ts";
import { execFile } from "../src/util/exec.ts";

interface CiFlags {
  base?: string;
  head?: string;
  output?: string;
  markdown?: string;
  pr?: number;
  comment: boolean;
  yes: boolean;
  model?: string;
  finalReport?: string;
  scanInstructionsFile?: string;
  filterInstructionsFile?: string;
  scanInstructionsText?: string;
  filterInstructionsText?: string;
  include: string[];
  exclude: string[];
  paths: string[];
  allowArtifactComment: boolean;
  failOnHigh: boolean;
  failOnMedium: boolean;
  help: boolean;
  errors: string[];
}

interface CiResult {
  ok: boolean;
  repoRoot?: string;
  outputPath?: string;
  markdownPath?: string;
  filesReviewed: number;
  highSeverity: number;
  mediumSeverity: number;
  commentMode?: string;
  mode?: "artifact-only" | "external-final-report";
  warnings: string[];
  errors: string[];
}

function parseArgs(args: string[]): CiFlags {
  const flags: CiFlags = {
    comment: false,
    yes: false,
    include: [],
    exclude: [],
    paths: [],
    allowArtifactComment: false,
    failOnHigh: false,
    failOnMedium: false,
    help: false,
    errors: [],
  };

  for (let i = 0; i < args.length; i++) {
    const arg = args[i] as string;
    const next = args[i + 1];
    switch (arg) {
      case "--base":
        if (next && !next.startsWith("--")) {
          flags.base = next;
          i++;
        } else flags.errors.push("Missing value for --base.");
        break;
      case "--head":
        if (next && !next.startsWith("--")) {
          flags.head = next;
          i++;
        } else flags.errors.push("Missing value for --head.");
        break;
      case "--output":
        if (next && !next.startsWith("--")) {
          flags.output = next;
          i++;
        } else flags.errors.push("Missing value for --output.");
        break;
      case "--markdown":
        if (next && !next.startsWith("--")) {
          flags.markdown = next;
          i++;
        } else flags.errors.push("Missing value for --markdown.");
        break;
      case "--pr":
        if (next && !next.startsWith("--")) {
          const pr = Number(next);
          if (Number.isInteger(pr) && pr > 0) flags.pr = pr;
          else flags.errors.push(`Invalid --pr value: ${next}`);
          i++;
        } else flags.errors.push("Missing value for --pr.");
        break;
      case "--comment":
        flags.comment = true;
        break;
      case "--yes":
      case "-y":
        flags.yes = true;
        break;
      case "--model":
        if (next && !next.startsWith("--")) {
          flags.model = next;
          i++;
        } else flags.errors.push("Missing value for --model.");
        break;
      case "--final-report":
        if (next && !next.startsWith("--")) {
          flags.finalReport = next;
          i++;
        } else flags.errors.push("Missing value for --final-report.");
        break;
      case "--scan-instructions-file":
        if (next && !next.startsWith("--")) {
          flags.scanInstructionsFile = next;
          i++;
        } else flags.errors.push("Missing value for --scan-instructions-file.");
        break;
      case "--filter-instructions-file":
        if (next && !next.startsWith("--")) {
          flags.filterInstructionsFile = next;
          i++;
        } else flags.errors.push("Missing value for --filter-instructions-file.");
        break;
      case "--scan-instructions-text":
        if (next && !next.startsWith("--")) {
          flags.scanInstructionsText = next;
          i++;
        } else flags.errors.push("Missing value for --scan-instructions-text.");
        break;
      case "--filter-instructions-text":
        if (next && !next.startsWith("--")) {
          flags.filterInstructionsText = next;
          i++;
        } else flags.errors.push("Missing value for --filter-instructions-text.");
        break;
      case "--include":
        if (next && !next.startsWith("--")) {
          flags.include.push(...splitList(next));
          i++;
        } else flags.errors.push("Missing value for --include.");
        break;
      case "--exclude":
        if (next && !next.startsWith("--")) {
          flags.exclude.push(...splitList(next));
          i++;
        } else flags.errors.push("Missing value for --exclude.");
        break;
      case "--exclude-directories":
        if (next && !next.startsWith("--")) {
          flags.exclude.push(...splitList(next).map(directoryToGlob));
          i++;
        } else flags.errors.push("Missing value for --exclude-directories.");
        break;
      case "--paths":
        if (next && !next.startsWith("--")) {
          flags.paths.push(...splitList(next));
          i++;
          while (args[i + 1] && !args[i + 1]?.startsWith("--")) {
            flags.paths.push(args[i + 1] as string);
            i++;
          }
        } else flags.errors.push("Missing value for --paths.");
        break;
      case "--allow-artifact-comment":
        flags.allowArtifactComment = true;
        break;
      case "--fail-on-high":
        flags.failOnHigh = true;
        break;
      case "--fail-on-medium":
        flags.failOnMedium = true;
        break;
      case "--help":
      case "-h":
      case "--ci-help":
        flags.help = true;
        break;
      default:
        flags.errors.push(`Unknown flag: ${arg}`);
    }
  }

  return flags;
}

function splitList(value: string): string[] {
  return value
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}

function directoryToGlob(value: string): string {
  const cleaned = value.replace(/\\/gu, "/").replace(/^\.\//u, "").replace(/\/+$/u, "");
  return cleaned.includes("*") ? cleaned : `${cleaned}/**`;
}

function applyScopeOverrides(config: SecurityReviewConfig, flags: CiFlags): SecurityReviewConfig {
  if (flags.include.length === 0 && flags.exclude.length === 0) return config;
  return {
    ...config,
    include: flags.include.length > 0 ? flags.include : config.include,
    exclude: flags.exclude.length > 0 ? [...config.exclude, ...flags.exclude] : config.exclude,
  };
}

async function readPullRequestMetadata(
  repoRoot: string,
  prNumber: number | undefined,
): Promise<PullRequestMetadata | undefined> {
  const fromEvent = await readPullRequestMetadataFromEvent();
  if (fromEvent) return fromEvent;
  const repository = process.env.GITHUB_REPOSITORY;
  if (!prNumber || !process.env.GH_TOKEN || !repository) return undefined;
  const result = await execFile(
    "gh",
    [
      "api",
      `repos/${repository}/pulls/${prNumber}`,
      "--jq",
      "{number,title,user:.user.login,baseRef:.base.ref,headRef:.head.ref,baseSha:.base.sha,headSha:.head.sha,changedFiles:.changed_files,additions,deletions,body}",
    ],
    { cwd: repoRoot, timeoutMs: 10_000, maxOutputBytes: 128 * 1024 },
  );
  if (result.status !== 0 || !result.stdout.trim()) return undefined;
  return metadataFromUnknown(JSON.parse(result.stdout));
}

async function readPullRequestMetadataFromEvent(): Promise<PullRequestMetadata | undefined> {
  const eventPath = process.env.GITHUB_EVENT_PATH;
  if (!eventPath) return undefined;
  const event = JSON.parse(await readFile(eventPath, "utf8"));
  const pr = event.pull_request;
  return pr ? metadataFromUnknown(pr) : undefined;
}

function metadataFromUnknown(value: any): PullRequestMetadata {
  return {
    number: numberValue(value.number),
    title: stringValue(value.title),
    author: stringValue(value.author ?? value.user?.login),
    baseRef: stringValue(value.baseRef ?? value.base?.ref),
    headRef: stringValue(value.headRef ?? value.head?.ref),
    baseSha: stringValue(value.baseSha ?? value.base?.sha),
    headSha: stringValue(value.headSha ?? value.head?.sha),
    changedFiles: numberValue(value.changedFiles ?? value.changed_files),
    additions: numberValue(value.additions),
    deletions: numberValue(value.deletions),
    bodyExcerpt: stringValue(value.body),
  };
}

function stringValue(value: unknown): string | undefined {
  return typeof value === "string" ? value : undefined;
}

function numberValue(value: unknown): number | undefined {
  return typeof value === "number" && Number.isFinite(value) ? value : undefined;
}

function printHelp(): void {
  console.log(`pi-security-review: CI script

Usage:
  bun run security-review:ci -- [flags]

Flags:
  --base <ref>          Base ref for git diff
  --head <ref>          Head ref for git diff
  --output <path>       JSON artifact path (default .pi/security-review/ci-context.json)
  --markdown <path>     Markdown artifact path (default .pi/security-review/ci-report.md)
  --pr <number>         Pull request number for optional comment
  --comment             Post PR comment (requires --yes)
  --yes                 Explicit approval for GitHub comment mutation
  --model <provider/model>  Record requested Pi model metadata
  --final-report <path> Read final model output/report marker from external runner
  --scan-instructions-file <path> Repo-relative custom scan instructions file
  --filter-instructions-file <path> Repo-relative custom false-positive filter file
  --scan-instructions-text <text> Inline custom scan instructions
  --filter-instructions-text <text> Inline custom false-positive filter instructions
  --include <glob[,glob]> Review include override (repeatable)
  --exclude <glob[,glob]> Review exclude override (repeatable)
  --paths <path...> Focus review paths
  --exclude-directories <dir[,dir]> Upstream-compatible exclude alias
  --allow-artifact-comment Allow commenting artifact-only context (maintainer override)
  --fail-on-high        Exit non-zero when final report has HIGH findings
  --fail-on-medium      Exit non-zero when final report has MEDIUM or HIGH findings
  --ci-help             Show help

Modes:
  Artifact-only mode builds bounded diff context and provider-neutral prompt. It does not call a model and needs only contents: read.
  External-final-report mode reads a model-produced marker from --final-report and applies fail/comment gates to that final report.
  PR comment mode requires --comment --yes, gh auth, pull-requests: write, trusted PR context, and a final model report unless --allow-artifact-comment is set.
`);
}

async function main(): Promise<CiResult> {
  const flags = parseArgs(process.argv.slice(2));
  if (flags.help) {
    printHelp();
    process.exit(0);
  }
  if (flags.errors.length > 0) return emptyResult(flags.errors);
  if (flags.comment && !flags.yes) {
    return emptyResult(["GitHub comment mutation requires both --comment and --yes."]);
  }
  if (flags.comment && !flags.pr) return emptyResult(["--comment requires --pr <number>."]);
  if (flags.comment && !flags.finalReport && !flags.allowArtifactComment) {
    return emptyResult([
      "Refusing to comment artifact-only security context as final security result. Provide --final-report <path> or maintainer override --allow-artifact-comment.",
    ]);
  }

  let config: SecurityReviewConfig;
  let contextResult: Awaited<ReturnType<typeof buildSecurityReviewContext>>;
  try {
    const repoRoot = await detectGitRoot(process.cwd());
    if (!repoRoot) throw new Error("Current directory is not inside a git repository.");
    const loaded = await loadConfig(repoRoot);
    config = applyScopeOverrides(loaded.config, flags);
    const prMetadata = await readPullRequestMetadata(repoRoot, flags.pr);
    contextResult = await buildSecurityReviewContext({
      repoRoot,
      config,
      base: flags.base,
      head: flags.head,
      paths: flags.paths,
      requestedModel: flags.model,
      activeModel: flags.model,
      customSecurityScanInstructionsText: flags.scanInstructionsText,
      falsePositiveFilteringInstructionsText: flags.filterInstructionsText,
      customSecurityScanInstructionsFile: flags.scanInstructionsFile,
      falsePositiveFilteringInstructionsFile: flags.filterInstructionsFile,
      prMetadata,
    });
  } catch (error) {
    return emptyResult([(error as Error).message]);
  }

  const repoRoot = contextResult.payload.repo.root;
  const prompt = buildSecurityPrompt({
    context: contextResult.payload,
    config,
    customSecurityScanInstructions: contextResult.payload.customInstructions.scan?.text,
    falsePositiveFilteringInstructions: contextResult.payload.customInstructions.filter?.text,
  });

  const artifactPayload: SecurityReviewMarkerPayload = {
    findings: [],
    excludedFindings: [],
    analysisSummary: {
      filesReviewed: contextResult.payload.filesReviewed.length,
      highSeverity: 0,
      mediumSeverity: 0,
      lowSeverity: 0,
      reviewCompleted: false,
      diffTruncated: contextResult.payload.truncation.diffTruncated,
      contextTruncated: contextResult.payload.truncation.contextTruncated,
      findingsTotal: 0,
      excludedFindings: 0,
      warnings: [
        "CI artifact-only mode generated context and prompt only; no model review was executed.",
        ...contextResult.warnings,
      ],
    },
    metadata: {
      model: flags.model,
      promptChars: prompt.text.length,
      contextTruncated: contextResult.payload.truncation.contextTruncated,
      codeReviewGraphUsed: contextResult.payload.codeReviewGraph.available,
      generatedAt: contextResult.payload.generatedAt,
      pullRequest: contextResult.payload.pullRequest,
      mode: "artifact-only",
    },
  };

  let markerPayload = artifactPayload;
  let mode: CiResult["mode"] = "artifact-only";
  const warnings = [...contextResult.warnings];
  let markdownTitle = "Security Review CI Context";

  if (flags.finalReport) {
    const finalText = await readFile(flags.finalReport, "utf8");
    const parsed = parseSecurityReviewMarkdown(finalText);
    if (parsed.warning) return emptyResult([parsed.warning], repoRoot);
    if (!parsed.marker?.value) {
      return emptyResult(
        [`Final report missing security-review JSON marker: ${flags.finalReport}`],
        repoRoot,
      );
    }
    markerPayload = {
      ...parsed.marker.value,
      metadata: {
        ...parsed.marker.value.metadata,
        model: parsed.marker.value.metadata?.model ?? flags.model,
        promptChars: prompt.text.length,
        generatedAt: parsed.marker.value.metadata?.generatedAt ?? contextResult.payload.generatedAt,
        pullRequest: contextResult.payload.pullRequest,
        mode: "external-final-report",
      },
    };
    mode = "external-final-report";
    markdownTitle = "Security Review CI Final Report";
    if (parsed.markdown.trim().length > 0)
      warnings.push(
        "Final report Markdown supplied; JSON marker was normalized and re-rendered for stored artifacts.",
      );
  }

  const markdown = `${renderSecurityReviewMarkdown(markerPayload, {
    title: markdownTitle,
    scope: contextResult.payload.scope.type,
    generatedAt: contextResult.payload.generatedAt,
    model: flags.model,
    contextTruncated: contextResult.payload.truncation.contextTruncated,
    diffTruncated: contextResult.payload.truncation.diffTruncated,
    codeReviewGraphUsed: contextResult.payload.codeReviewGraph.available,
  })}${mode === "artifact-only" ? "\n\n## Next step\n\nRun the prompt from the JSON artifact with any Pi-configured provider/model, then store the model output marker as the final report.\n" : ""}\n\n${buildSecurityReviewMarkerJson(markerPayload)}\n`;

  const outputPath = flags.output ?? join(repoRoot, ".pi", "security-review", "ci-context.json");
  const markdownPath = flags.markdown ?? join(repoRoot, ".pi", "security-review", "ci-report.md");
  await writeJson(outputPath, {
    version: 1,
    generatedAt: contextResult.payload.generatedAt,
    mode,
    context: contextResult.payload,
    prompt: prompt.text,
    report: markerPayload,
  });
  await writeText(markdownPath, markdown);
  await writeLatestMarkdown(repoRoot, markdown);
  await writeLatestJson(repoRoot, {
    version: 1,
    generatedAt: contextResult.payload.generatedAt,
    repoRoot,
    summary: markerPayload.analysisSummary,
    findings: markerPayload.findings,
    excludedFindings: markerPayload.excludedFindings,
    metadata: markerPayload.metadata,
  });

  let commentMode: string | undefined;
  if (flags.comment) {
    const remote = contextResult.payload.repo.github ?? (await getGitHubRemote(repoRoot));
    if (!remote) return emptyResult(["GitHub remote not detected; cannot comment."], repoRoot);
    const comment = await publishSecurityReviewComment({
      repoRoot,
      remote,
      config,
      markdown,
      pr: flags.pr,
      dryRun: false,
      approve: flags.yes,
      updateExisting: true,
    });
    commentMode = comment.mode;
    warnings.push(...comment.warnings);
    if (!comment.ok) return emptyResult([comment.error ?? "GitHub comment failed."], repoRoot);
  }

  return {
    ok: true,
    repoRoot,
    outputPath,
    markdownPath,
    filesReviewed: markerPayload.analysisSummary.filesReviewed,
    highSeverity: markerPayload.analysisSummary.highSeverity,
    mediumSeverity: markerPayload.analysisSummary.mediumSeverity,
    mode,
    commentMode,
    warnings,
    errors: [],
  };
}

function emptyResult(errors: string[], repoRoot?: string): CiResult {
  return {
    ok: false,
    repoRoot,
    filesReviewed: 0,
    highSeverity: 0,
    mediumSeverity: 0,
    warnings: [],
    errors,
  };
}

async function writeJson(path: string, value: unknown): Promise<void> {
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, `${JSON.stringify(redactSecretsInValue(value), null, 2)}\n`, "utf8");
}

async function writeText(path: string, value: string): Promise<void> {
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, redactSecretLikeValues(value), "utf8");
}

const result = await main();
const lines = [
  "pi-security-review: CI result",
  `ok: ${result.ok}`,
  `repoRoot: ${result.repoRoot ?? "unknown"}`,
  `filesReviewed: ${result.filesReviewed}`,
  `highSeverity: ${result.highSeverity}`,
  `mediumSeverity: ${result.mediumSeverity}`,
];
if (result.outputPath) lines.push(`output: ${result.outputPath}`);
if (result.markdownPath) lines.push(`markdown: ${result.markdownPath}`);
if (result.mode) lines.push(`mode: ${result.mode}`);
if (result.commentMode) lines.push(`comment: ${result.commentMode}`);
for (const warning of result.warnings) lines.push(`warning: ${warning}`);
for (const error of result.errors) lines.push(`error: ${error}`);
console.log(lines.join("\n"));

if (!result.ok) process.exit(1);
const failOnHigh = process.argv.includes("--fail-on-high");
const failOnMedium = process.argv.includes("--fail-on-medium");
if (failOnHigh && result.highSeverity > 0) process.exit(1);
if (failOnMedium && (result.highSeverity > 0 || result.mediumSeverity > 0)) process.exit(1);
