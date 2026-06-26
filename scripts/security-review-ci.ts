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
import { buildSecurityReviewContext } from "../src/tools/buildContext.ts";

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
    config = loaded.config;
    contextResult = await buildSecurityReviewContext({
      repoRoot,
      config,
      base: flags.base,
      head: flags.head,
      requestedModel: flags.model,
      activeModel: flags.model,
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
