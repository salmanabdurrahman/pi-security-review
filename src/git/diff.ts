/** Deterministic git diff scope and file filtering. */

import { lstat, readFile } from "node:fs/promises";
import { join } from "node:path";
import type { SecurityReviewConfig } from "../config/schema.ts";
import { execGit } from "../util/exec.ts";
import { buildRange, findFallbackBaseRef, validateGitRef } from "./refs.ts";
import { getWorkingTreeStatus } from "./status.ts";

export type ScopeType = "explicit" | "unstaged" | "staged" | "branch";
export type FileStatus = "added" | "modified" | "deleted" | "renamed";

export interface DiffFile {
  path: string;
  oldPath?: string;
  status: FileStatus;
  binary: boolean;
  skipped?: string;
}

export interface ResolvedDiffScope {
  type: ScopeType;
  base?: string;
  head?: string;
  diff: string;
  files: DiffFile[];
  truncated: boolean;
  warnings: string[];
}

export interface ResolveDiffOptions {
  base?: string;
  head?: string;
  from?: string;
  to?: string;
  paths?: string[];
}

export async function resolveDiffScope(
  repoRoot: string,
  config: SecurityReviewConfig,
  options: ResolveDiffOptions = {},
): Promise<ResolvedDiffScope> {
  if (options.base || options.head || options.from || options.to || options.paths?.length) {
    return await branchOrExplicitDiff(repoRoot, config, options, "explicit");
  }

  const unstaged = await gitDiff(repoRoot, [
    "diff",
    "--no-color",
    "--no-ext-diff",
    "--find-renames",
  ]);
  const untrackedFiles = await collectUntrackedFiles(repoRoot, config);
  if (unstaged.length > 0 || untrackedFiles.diff.length > 0) {
    return buildScope(
      "unstaged",
      config,
      `${unstaged}${untrackedFiles.diff}`,
      undefined,
      undefined,
      [...parseDiffFiles(unstaged), ...untrackedFiles.files],
    );
  }

  const staged = await gitDiff(repoRoot, [
    "diff",
    "--cached",
    "--no-color",
    "--no-ext-diff",
    "--find-renames",
  ]);
  if (staged.length > 0)
    return buildScope("staged", config, staged, undefined, undefined, parseDiffFiles(staged));

  const base = await findFallbackBaseRef(repoRoot);
  if (base) return await branchOrExplicitDiff(repoRoot, config, { base, head: "HEAD" }, "branch");

  return {
    type: "unstaged",
    diff: "",
    files: [],
    truncated: false,
    warnings: ["No git diff or eligible untracked files found."],
  };
}

export function parseDiffFiles(diff: string): DiffFile[] {
  const files: DiffFile[] = [];
  let current: DiffFile | undefined;
  for (const line of diff.split(/\r?\n/u)) {
    if (line.startsWith("diff --git ")) {
      if (current) files.push(current);
      const match = /^diff --git a\/(.+) b\/(.+)$/u.exec(line);
      current = match
        ? {
            path: normalizePath(match[2] ?? ""),
            oldPath: normalizePath(match[1] ?? ""),
            status: "modified",
            binary: false,
          }
        : undefined;
      continue;
    }
    if (!current) continue;
    if (line.startsWith("new file mode")) current.status = "added";
    if (line.startsWith("deleted file mode")) current.status = "deleted";
    if (line.startsWith("rename from ")) {
      current.status = "renamed";
      current.oldPath = normalizePath(line.slice("rename from ".length));
    }
    if (line.startsWith("rename to "))
      current.path = normalizePath(line.slice("rename to ".length));
    if (line.startsWith("Binary files ")) current.binary = true;
  }
  if (current) files.push(current);
  return files.filter((file) => file.path.length > 0);
}

function buildScope(
  type: ScopeType,
  config: SecurityReviewConfig,
  rawDiff: string,
  base: string | undefined,
  head: string | undefined,
  rawFiles: DiffFile[],
): ResolvedDiffScope {
  const warnings: string[] = [];
  const filtered = filterFiles(rawFiles, config);
  const allowed = new Set(filtered.files.filter((file) => !file.skipped).map((file) => file.path));
  let diff = filterDiffByPaths(rawDiff, allowed);
  let truncated = false;
  if (filtered.files.filter((file) => !file.skipped).length > config.maxFiles)
    warnings.push(`File count exceeds maxFiles=${config.maxFiles}; extra files skipped.`);
  if (Buffer.byteLength(diff, "utf8") > config.maxDiffBytes) {
    diff = diff.slice(0, config.maxDiffBytes);
    truncated = true;
    warnings.push(`Diff truncated at maxDiffBytes=${config.maxDiffBytes}.`);
  }
  return {
    type,
    base,
    head,
    diff,
    files: filtered.files,
    truncated,
    warnings: [...warnings, ...filtered.warnings],
  };
}

function filterFiles(
  files: DiffFile[],
  config: SecurityReviewConfig,
): { files: DiffFile[]; warnings: string[] } {
  const warnings: string[] = [];
  const result: DiffFile[] = [];
  let kept = 0;
  for (const file of dedupeFiles(files)) {
    const reason = skipReason(file, config);
    if (!reason && kept >= config.maxFiles) {
      result.push({ ...file, skipped: "max_files" });
      continue;
    }
    if (!reason) kept += 1;
    if (reason) warnings.push(`Skipped ${file.path}: ${reason}.`);
    result.push(reason ? { ...file, skipped: reason } : file);
  }
  return { files: result, warnings };
}

function skipReason(file: DiffFile, config: SecurityReviewConfig): string | undefined {
  if (file.binary) return "binary";
  if (isSecretLikePath(file.path)) return "secret_like_path";
  if (matchesAny(file.path, config.exclude)) return "excluded_path";
  if (!matchesAny(file.path, config.include)) return "not_included";
  if (isGeneratedOrVendorPath(file.path)) return "generated_or_vendor";
  if (config.excludeDocumentation && isDocumentationPath(file.path)) return "documentation";
  if (config.excludeTestsByDefault && isTestPath(file.path)) return "test";
  return undefined;
}

async function branchOrExplicitDiff(
  repoRoot: string,
  config: SecurityReviewConfig,
  options: ResolveDiffOptions,
  type: ScopeType,
): Promise<ResolvedDiffScope> {
  const base = options.from ?? options.base;
  const head = options.to ?? options.head ?? "HEAD";
  const args = ["diff", "--no-color", "--no-ext-diff", "--find-renames"];
  if (base) args.push(buildRange(base, head));
  if (!base && head) args.push(validateGitRef(head));
  if (options.paths?.length) args.push("--", ...options.paths.map(normalizePath));
  const diff = await gitDiff(repoRoot, args);
  return buildScope(type, config, diff, base, head, parseDiffFiles(diff));
}

async function gitDiff(repoRoot: string, args: string[]): Promise<string> {
  const result = await execGit(repoRoot, args, {
    timeoutMs: 10_000,
    maxOutputBytes: 2 * 1024 * 1024,
  });
  return result.status === 0 ? result.stdout : "";
}

async function collectUntrackedFiles(
  repoRoot: string,
  config: SecurityReviewConfig,
): Promise<{ diff: string; files: DiffFile[] }> {
  const status = await getWorkingTreeStatus(repoRoot);
  const files: DiffFile[] = [];
  const chunks: string[] = [];
  for (const path of status.untracked) {
    const file: DiffFile = { path, status: "added", binary: false };
    const reason = skipReason(file, config);
    files.push(reason ? { ...file, skipped: reason } : file);
    if (reason) continue;
    try {
      const stat = await lstat(join(repoRoot, path));
      if (!stat.isFile()) continue;
      const content = await readFile(join(repoRoot, path), "utf8");
      chunks.push(
        `diff --git a/${path} b/${path}\nnew file mode 100644\n--- /dev/null\n+++ b/${path}\n@@ -0,0 +1,${content.split(/\r?\n/u).length} @@\n${content
          .split(/\r?\n/u)
          .map((line) => `+${line}`)
          .join("\n")}\n`,
      );
    } catch {
      file.skipped = "unreadable_or_binary";
    }
  }
  return { diff: chunks.join(""), files };
}

function filterDiffByPaths(diff: string, allowed: Set<string>): string {
  if (allowed.size === 0) return "";
  return diff
    .split(/(?=^diff --git )/gmu)
    .filter((section) => {
      const file = parseDiffFiles(section)[0];
      return file ? allowed.has(file.path) : false;
    })
    .join("");
}

function dedupeFiles(files: DiffFile[]): DiffFile[] {
  const seen = new Map<string, DiffFile>();
  for (const file of files) seen.set(file.path, { ...seen.get(file.path), ...file });
  return [...seen.values()].sort((left, right) => left.path.localeCompare(right.path));
}

function matchesAny(path: string, patterns: string[]): boolean {
  return patterns.some((pattern) => globToRegExp(pattern).test(path));
}

function globToRegExp(pattern: string): RegExp {
  if (pattern === "**/*") return /^.+$/u;
  let escaped = pattern.replace(/[.+^${}()|[\]\\]/gu, "\\$&");
  escaped = escaped.replace(/^\*\*\//u, "(?:.*/)?");
  escaped = escaped.replace(/\*\*/gu, ".*").replace(/\*/gu, "[^/]*");
  return new RegExp(`^${escaped}$`, "u");
}

function isGeneratedOrVendorPath(path: string): boolean {
  return (
    /(^|\/)(node_modules|vendor|third_party|dist|build|coverage)\//u.test(path) ||
    /(?:\.generated\.|\.min\.js$)/u.test(path)
  );
}

function isDocumentationPath(path: string): boolean {
  return /(^|\/)(docs?|documentation)\//iu.test(path) || /\.(md|mdx|rst|txt)$/iu.test(path);
}

function isTestPath(path: string): boolean {
  return (
    /(^|\/)(__tests__|test|tests|spec)\//iu.test(path) ||
    /(?:\.test|\.spec)\.[cm]?[jt]sx?$/iu.test(path)
  );
}

function isSecretLikePath(path: string): boolean {
  return (
    /(^|\/)(\.env(?:\..*)?|.*(?:secret|token|credential|private[-_]?key).*)$/iu.test(path) ||
    /\.(pem|key|p12|pfx|crt|cer)$/iu.test(path)
  );
}

function normalizePath(path: string): string {
  return path.replace(/\\/gu, "/").replace(/^\.\//u, "").replace(/^a\//u, "").replace(/^b\//u, "");
}
