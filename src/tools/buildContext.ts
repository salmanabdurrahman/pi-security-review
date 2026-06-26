/** Build bounded security review context for commands and tools. */

import { readFile } from "node:fs/promises";
import { isAbsolute, join, normalize, relative } from "node:path";
import { loadConfig } from "../config/load.ts";
import type { SecurityReviewConfig, ThinkingLevel } from "../config/schema.ts";
import { type ResolveDiffOptions, type ResolvedDiffScope, resolveDiffScope } from "../git/diff.ts";
import { detectGitRoot, getCurrentBranch, getGitHubRemote } from "../git/repo.ts";
import { getWorkingTreeStatus } from "../git/status.ts";
import { agentMetadata, resolveSecurityReviewAgents } from "../security/agents.ts";

export interface BuildSecurityReviewContextOptions extends ResolveDiffOptions {
  cwd?: string;
  repoRoot?: string;
  config?: SecurityReviewConfig;
  activeModel?: string;
  requestedModel?: string;
  requestedModelProfile?: string;
  thinkingLevelActual?: ThinkingLevel | string | null;
  customSecurityScanInstructionsText?: string | null;
  falsePositiveFilteringInstructionsText?: string | null;
  customSecurityScanInstructionsFile?: string | null;
  falsePositiveFilteringInstructionsFile?: string | null;
  codeReviewGraphContext?: unknown;
  codeReviewGraphAvailable?: boolean;
  codeReviewGraphWarning?: string;
  prMetadata?: PullRequestMetadata;
  generatedAt?: string;
}

export interface SecurityReviewContext {
  version: 1;
  generatedAt: string;
  repo: {
    root: string;
    branch?: string;
    github?: { owner: string; repo: string; url: string };
  };
  scope: ResolvedDiffScope;
  filesReviewed: string[];
  skippedFiles: Array<{ path: string; reason: string }>;
  gitStatus: {
    clean: boolean;
    stagedCount: number;
    unstagedCount: number;
    untrackedCount: number;
  };
  model: {
    activeModel?: string;
    requestedModel?: string;
    requestedModelProfile: string;
    requestedProvider?: string | null;
    requestedProfileModel?: string | null;
    thinkingLevelRequested?: ThinkingLevel;
    thinkingLevelActual?: ThinkingLevel | string | null;
    agents: Array<{ role: string; model?: string; thinkingLevel?: string | null }>;
    warnings: string[];
  };
  customInstructions: {
    scan?: InstructionContext;
    filter?: InstructionContext;
  };
  pullRequest?: PullRequestMetadata;
  codeReviewGraph: {
    enabled: boolean;
    available: boolean;
    bestEffort: true;
    warning?: string;
    context?: unknown;
  };
  truncation: {
    diffTruncated: boolean;
    contextTruncated: boolean;
    maxDiffBytes: number;
    maxContextChars: number;
  };
  warnings: string[];
}

export interface InstructionContext {
  source: "inline" | "file";
  path?: string;
  text: string;
}

export interface PullRequestMetadata {
  number?: number;
  title?: string;
  author?: string;
  baseRef?: string;
  headRef?: string;
  baseSha?: string;
  headSha?: string;
  changedFiles?: number;
  additions?: number;
  deletions?: number;
  bodyExcerpt?: string;
}

export interface BuiltSecurityReviewContext {
  payload: SecurityReviewContext;
  text: string;
  truncated: boolean;
  totalBytes: number;
  outputBytes: number;
  warnings: string[];
}

export async function buildSecurityReviewContext(
  options: BuildSecurityReviewContextOptions = {},
): Promise<BuiltSecurityReviewContext> {
  const repoRoot = options.repoRoot ?? (await detectGitRoot(options.cwd ?? process.cwd()));
  if (!repoRoot) {
    throw new Error("Cannot build security review context: not inside a git repository.");
  }

  const loadedConfig = options.config ? undefined : await loadConfig(repoRoot);
  const config = options.config ?? loadedConfig?.config;
  if (!config) throw new Error("Cannot build security review context: config unavailable.");

  const [scope, status, branch, github, scanInstruction, filterInstruction] = await Promise.all([
    resolveDiffScope(repoRoot, config, options),
    getWorkingTreeStatus(repoRoot),
    getCurrentBranch(repoRoot),
    getGitHubRemote(repoRoot),
    resolveInstruction(repoRoot, {
      inlineText: options.customSecurityScanInstructionsText,
      filePath: options.customSecurityScanInstructionsFile ?? config.customSecurityScanInstructions,
    }),
    resolveInstruction(repoRoot, {
      inlineText: options.falsePositiveFilteringInstructionsText,
      filePath:
        options.falsePositiveFilteringInstructionsFile ?? config.falsePositiveFilteringInstructions,
    }),
  ]);

  const model = buildModelMetadata(config, options);
  const crg = buildCodeReviewGraphContext(config, options);
  const filesReviewed = scope.files.filter((file) => !file.skipped).map((file) => file.path);
  const skippedFiles = scope.files
    .filter((file): file is typeof file & { skipped: string } => Boolean(file.skipped))
    .map((file) => ({ path: file.path, reason: file.skipped }));

  const warnings = [...scope.warnings, ...model.warnings, ...(crg.warning ? [crg.warning] : [])];

  const payload: SecurityReviewContext = {
    version: 1,
    generatedAt: options.generatedAt ?? new Date().toISOString(),
    repo: {
      root: repoRoot,
      branch,
      github,
    },
    scope,
    filesReviewed,
    skippedFiles,
    gitStatus: {
      clean: status.clean,
      stagedCount: status.staged.length,
      unstagedCount: status.unstaged.length,
      untrackedCount: status.untracked.length,
    },
    model,
    customInstructions: {
      scan: scanInstruction,
      filter: filterInstruction,
    },
    pullRequest: options.prMetadata ? sanitizePullRequestMetadata(options.prMetadata) : undefined,
    codeReviewGraph: crg,
    truncation: {
      diffTruncated: scope.truncated,
      contextTruncated: false,
      maxDiffBytes: config.maxDiffBytes,
      maxContextChars: config.maxContextChars,
    },
    warnings,
  };

  return fitContextToLimit(payload, config.maxContextChars);
}

function sanitizePullRequestMetadata(metadata: PullRequestMetadata): PullRequestMetadata {
  return {
    number: metadata.number,
    title: truncateText(metadata.title, 300),
    author: truncateText(metadata.author, 120),
    baseRef: truncateText(metadata.baseRef, 120),
    headRef: truncateText(metadata.headRef, 120),
    baseSha: truncateText(metadata.baseSha, 80),
    headSha: truncateText(metadata.headSha, 80),
    changedFiles: metadata.changedFiles,
    additions: metadata.additions,
    deletions: metadata.deletions,
    bodyExcerpt: truncateText(metadata.bodyExcerpt, 2000),
  };
}

function truncateText(value: string | undefined, maxChars: number): string | undefined {
  if (value === undefined) return undefined;
  return value.length > maxChars ? `${value.slice(0, maxChars)}…` : value;
}

function buildModelMetadata(
  config: SecurityReviewConfig,
  options: BuildSecurityReviewContextOptions,
): SecurityReviewContext["model"] {
  const warnings: string[] = [];
  const requestedModelProfile =
    options.requestedModelProfile ?? config.agentPipeline[0] ?? "auditor";
  const agents = resolveSecurityReviewAgents(config);
  for (const agent of agents) warnings.push(...agent.warnings);
  const profile = config.modelProfiles[requestedModelProfile] ?? config.modelProfiles.default;
  if (!profile)
    warnings.push(`Model profile ${requestedModelProfile} not found; active model will be used.`);

  let requestedProvider = profile?.provider;
  let requestedProfileModel = profile?.model;
  if (options.requestedModel) {
    const parsed = parseRequestedModel(options.requestedModel);
    if (parsed) {
      requestedProvider = parsed.provider;
      requestedProfileModel = parsed.model;
    } else {
      warnings.push(`Requested model ${options.requestedModel} is not in provider/model form.`);
    }
  }

  return {
    activeModel: options.activeModel,
    requestedModel: options.requestedModel,
    requestedModelProfile,
    requestedProvider,
    requestedProfileModel,
    thinkingLevelRequested: profile?.thinkingLevel,
    thinkingLevelActual: options.thinkingLevelActual,
    agents: agentMetadata(agents),
    warnings,
  };
}

function parseRequestedModel(value: string): { provider: string; model: string } | undefined {
  const slash = value.indexOf("/");
  if (slash <= 0 || slash === value.length - 1) return undefined;
  return { provider: value.slice(0, slash), model: value.slice(slash + 1) };
}

function buildCodeReviewGraphContext(
  config: SecurityReviewConfig,
  options: BuildSecurityReviewContextOptions,
): SecurityReviewContext["codeReviewGraph"] {
  const enabled = config.optionalIntegrations.codeReviewGraph;
  if (!enabled) {
    return {
      enabled,
      available: false,
      bestEffort: true,
      warning: "Code review graph integration disabled by config.",
    };
  }
  if (options.codeReviewGraphContext !== undefined || options.codeReviewGraphAvailable === true) {
    return {
      enabled,
      available: true,
      bestEffort: true,
      context: options.codeReviewGraphContext,
      warning: options.codeReviewGraphWarning,
    };
  }
  return {
    enabled,
    available: false,
    bestEffort: true,
    warning:
      options.codeReviewGraphWarning ??
      "Code review graph context unavailable in this run; continuing with git diff context only.",
  };
}

const MAX_CUSTOM_INSTRUCTION_BYTES = 64 * 1024;

async function resolveInstruction(
  repoRoot: string,
  options: { inlineText?: string | null; filePath?: string | null },
): Promise<InstructionContext | undefined> {
  if (options.inlineText?.trim()) {
    assertInstructionSize(options.inlineText, "inline custom instructions");
    return { source: "inline", text: options.inlineText.trim() };
  }
  if (!options.filePath) return undefined;

  const safePath = resolveRepoRelativePath(repoRoot, options.filePath);
  if (isSecretLikeInstructionPath(safePath)) {
    throw new Error(`Refusing to read secret-like instruction path: ${options.filePath}`);
  }
  const text = (await readFile(join(repoRoot, safePath), "utf8")).trim();
  assertInstructionSize(text, `custom instruction file ${safePath}`);
  return text.length > 0 ? { source: "file", path: safePath, text } : undefined;
}

function assertInstructionSize(text: string, label: string): void {
  const bytes = Buffer.byteLength(text, "utf8");
  if (bytes > MAX_CUSTOM_INSTRUCTION_BYTES) {
    throw new Error(
      `Refusing ${label}: ${bytes} bytes exceeds limit ${MAX_CUSTOM_INSTRUCTION_BYTES}.`,
    );
  }
}

function resolveRepoRelativePath(repoRoot: string, path: string): string {
  if (isAbsolute(path)) throw new Error(`Instruction path must be repo-relative: ${path}`);
  const normalized = normalize(path).replace(/\\/gu, "/");
  if (normalized.startsWith("../") || normalized === "..") {
    throw new Error(`Instruction path must stay inside repo: ${path}`);
  }
  const abs = join(repoRoot, normalized);
  const rel = relative(repoRoot, abs).replace(/\\/gu, "/");
  if (rel.startsWith("../") || rel === ".." || isAbsolute(rel)) {
    throw new Error(`Instruction path must stay inside repo: ${path}`);
  }
  return rel;
}

function isSecretLikeInstructionPath(path: string): boolean {
  return (
    /(^|\/)(\.env(?:\..*)?|.*(?:secret|token|credential|private[-_]?key).*)$/iu.test(path) ||
    /\.(pem|key|p12|pfx|crt|cer)$/iu.test(path)
  );
}

function fitContextToLimit(
  payload: SecurityReviewContext,
  maxContextChars: number,
): BuiltSecurityReviewContext {
  const initialText = JSON.stringify(payload, null, 2);
  const totalBytes = Buffer.byteLength(initialText, "utf8");
  if (totalBytes <= maxContextChars) {
    return {
      payload,
      text: initialText,
      truncated: false,
      totalBytes,
      outputBytes: totalBytes,
      warnings: payload.warnings,
    };
  }

  const cloned: SecurityReviewContext = structuredClone(payload);
  const marker = "\n[... security review context diff truncated to fit maxContextChars ...]\n";
  const overheadText = JSON.stringify(
    { ...cloned, scope: { ...cloned.scope, diff: marker } },
    null,
    2,
  );
  const availableDiffBytes = Math.max(0, maxContextChars - Buffer.byteLength(overheadText, "utf8"));
  cloned.scope.diff = truncateUtf8(cloned.scope.diff, availableDiffBytes, marker);
  cloned.truncation.contextTruncated = true;
  cloned.warnings = [
    ...cloned.warnings,
    `Context truncated from ${totalBytes} bytes to fit maxContextChars=${maxContextChars}.`,
  ];

  const text = JSON.stringify(cloned, null, 2);
  return {
    payload: cloned,
    text,
    truncated: true,
    totalBytes,
    outputBytes: Buffer.byteLength(text, "utf8"),
    warnings: cloned.warnings,
  };
}

function truncateUtf8(text: string, maxBytes: number, marker: string): string {
  if (Buffer.byteLength(text, "utf8") <= maxBytes) return text;
  const markerBytes = Buffer.byteLength(marker, "utf8");
  const budget = Math.max(0, maxBytes - markerBytes);
  let low = 0;
  let high = text.length;
  while (low < high) {
    const mid = Math.ceil((low + high) / 2);
    if (Buffer.byteLength(text.slice(0, mid), "utf8") <= budget) low = mid;
    else high = mid - 1;
  }
  return `${text.slice(0, low)}${marker}`;
}
