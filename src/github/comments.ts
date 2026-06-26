/** GitHub PR comment rendering/posting for pi-security-review. */

import type { SecurityReviewConfig } from "../config/schema.ts";
import type { GitHubRemote } from "../git/repo.ts";
import type { SecurityFinding } from "../security/findings.ts";
import { redactSecretLikeValues } from "../security/redaction.ts";
import { checkGhAuth, checkGhAvailable, type GhApiResult, ghApi } from "./ghCli.ts";

export interface CommentOptions {
  repoRoot: string;
  remote: GitHubRemote;
  config: SecurityReviewConfig;
  markdown: string;
  pr?: number;
  dryRun?: boolean;
  approve?: boolean;
  updateExisting?: boolean;
  inlineFindings?: SecurityFinding[];
  inline?: boolean;
  headSha?: string;
  ghClient?: GhClient;
}

export interface CommentResult {
  ok: boolean;
  mode:
    | "dry-run"
    | "created"
    | "updated"
    | "inline-created"
    | "summary-with-inline-fallback"
    | "error";
  body: string;
  pr?: number;
  url?: string;
  commentId?: number;
  inlineCount?: number;
  fallbackCount?: number;
  error?: string;
  warnings: string[];
}

interface IssueComment {
  id: number;
  html_url?: string;
  body?: string;
  user?: { type?: string; login?: string };
}

interface PullRequestReviewComment {
  id: number;
  html_url?: string;
  body?: string;
  user?: { type?: string; login?: string };
  path?: string;
  line?: number;
}

interface PullRequestFile {
  filename: string;
  patch?: string;
}

interface PullRequest {
  head?: { sha?: string };
}

interface ReviewResponse {
  id?: number;
  html_url?: string;
}

interface GhClient {
  api<T = unknown>(options: {
    endpoint: string;
    method?: "GET" | "POST" | "PATCH";
    input?: unknown;
  }): Promise<GhApiResult<T>>;
}

interface InlineReviewComment {
  path: string;
  line: number;
  side: "RIGHT";
  body: string;
}

const INLINE_MARKER_PREFIX = "<!-- pi-security-review-inline:";

export function buildCommentBody(markdown: string, config: SecurityReviewConfig): string {
  return redactSecretLikeValues(`${config.github.commentMarker}\n\n${markdown.trim()}\n`);
}

export function buildInlineCommentBody(finding: SecurityFinding): string {
  return redactSecretLikeValues(
    [
      `${INLINE_MARKER_PREFIX}${finding.id} -->`,
      `### Security Finding: ${finding.title}`,
      "",
      `**Severity:** ${finding.severity}`,
      `**Category:** ${finding.category}`,
      `**Confidence:** ${finding.confidence}`,
      "",
      finding.description,
      finding.exploitScenario ? `\n**Exploit scenario:** ${finding.exploitScenario}` : undefined,
      finding.recommendation ? `\n**Recommendation:** ${finding.recommendation}` : undefined,
    ]
      .filter(Boolean)
      .join("\n"),
  );
}

export function buildInlineReviewComments(args: {
  findings: SecurityFinding[];
  prFiles: PullRequestFile[];
  existingComments?: PullRequestReviewComment[];
}): {
  comments: InlineReviewComment[];
  skipped: Array<{ finding: SecurityFinding; reason: string }>;
} {
  const changedLines = new Map(
    args.prFiles.map((file) => [file.filename, parseChangedLines(file.patch ?? "")]),
  );
  const existingMarkers = new Set(
    (args.existingComments ?? [])
      .map((comment) => extractInlineMarker(comment.body ?? ""))
      .filter((id): id is string => Boolean(id)),
  );
  const comments: InlineReviewComment[] = [];
  const skipped: Array<{ finding: SecurityFinding; reason: string }> = [];

  for (const finding of args.findings) {
    if (!finding.line) {
      skipped.push({ finding, reason: "finding has no line" });
      continue;
    }
    if (existingMarkers.has(finding.id)) {
      skipped.push({ finding, reason: "duplicate inline marker exists" });
      continue;
    }
    const lines = changedLines.get(finding.file);
    if (!lines) {
      skipped.push({ finding, reason: "file is not in PR diff" });
      continue;
    }
    if (!lines.has(finding.line)) {
      skipped.push({ finding, reason: "line is not a changed line in PR diff" });
      continue;
    }
    comments.push({
      path: finding.file,
      line: finding.line,
      side: "RIGHT",
      body: buildInlineCommentBody(finding),
    });
  }

  return { comments, skipped };
}

export async function publishSecurityReviewComment(
  options: CommentOptions,
): Promise<CommentResult> {
  const body = buildCommentBody(options.markdown, options.config);
  const pr = options.pr;
  const dryRun = options.dryRun !== false;
  const updateExisting = options.updateExisting ?? options.config.github.updateExistingComment;
  const warnings: string[] = [];

  if (!pr || !Number.isInteger(pr) || pr <= 0) {
    return { ok: false, mode: "error", body, pr, error: "GitHub PR number is required.", warnings };
  }

  if (dryRun) return { ok: true, mode: "dry-run", body, pr, warnings };
  if (options.approve !== true) {
    return {
      ok: false,
      mode: "error",
      body,
      pr,
      error: "Posting requires explicit approval.",
      warnings,
    };
  }

  if (!options.ghClient) {
    const available = await checkGhAvailable(options.repoRoot);
    if (!available.available)
      return {
        ok: false,
        mode: "error",
        body,
        pr,
        error: available.error ?? "gh CLI not available.",
        warnings,
      };
    const auth = await checkGhAuth(options.repoRoot);
    if (!auth.authenticated)
      return {
        ok: false,
        mode: "error",
        body,
        pr,
        error: auth.error ?? "gh CLI not authenticated.",
        warnings,
      };
  }

  const client = options.ghClient ?? defaultGhClient(options.repoRoot);
  if (options.inline && options.inlineFindings?.length) {
    const inline = await publishInlineReviewComments({ ...options, pr, body, client, warnings });
    if (inline.ok && inline.inlineCount && inline.inlineCount > 0) return inline;
    warnings.push("Inline review comments unavailable; falling back to issue-level summary.");
  }

  return publishIssueLevelComment({ ...options, pr, body, updateExisting, client, warnings });
}

async function publishInlineReviewComments(
  options: CommentOptions & { pr: number; body: string; client: GhClient; warnings: string[] },
): Promise<CommentResult> {
  const [filesResult, existingResult] = await Promise.all([
    options.client.api<PullRequestFile[]>({
      endpoint: `/repos/${options.remote.owner}/${options.remote.repo}/pulls/${options.pr}/files?per_page=100`,
    }),
    options.client.api<PullRequestReviewComment[]>({
      endpoint: `/repos/${options.remote.owner}/${options.remote.repo}/pulls/${options.pr}/comments?per_page=100`,
    }),
  ]);
  if (!filesResult.ok) return errorResult(options, filesResult.error ?? "Failed to read PR files.");
  if (!existingResult.ok)
    return errorResult(options, existingResult.error ?? "Failed to read PR review comments.");

  const prepared = buildInlineReviewComments({
    findings: options.inlineFindings ?? [],
    prFiles: filesResult.data ?? [],
    existingComments: existingResult.data ?? [],
  });
  for (const skipped of prepared.skipped) {
    options.warnings.push(`${skipped.finding.id}: ${skipped.reason}`);
  }
  if (prepared.comments.length === 0) {
    return {
      ok: true,
      mode: "summary-with-inline-fallback",
      body: options.body,
      pr: options.pr,
      inlineCount: 0,
      fallbackCount: prepared.skipped.length,
      warnings: options.warnings,
    };
  }

  const headSha = options.headSha ?? (await getPullRequestHeadSha(options));
  if (!headSha) return errorResult(options, "Cannot determine PR head SHA for inline review.");

  const review = await options.client.api<ReviewResponse>({
    endpoint: `/repos/${options.remote.owner}/${options.remote.repo}/pulls/${options.pr}/reviews`,
    method: "POST",
    input: { commit_id: headSha, event: "COMMENT", comments: prepared.comments },
  });
  if (!review.ok) {
    options.warnings.push(review.error ?? "Inline review creation failed.");
    return {
      ok: true,
      mode: "summary-with-inline-fallback",
      body: options.body,
      pr: options.pr,
      inlineCount: 0,
      fallbackCount: prepared.comments.length + prepared.skipped.length,
      warnings: options.warnings,
    };
  }

  return {
    ok: true,
    mode: "inline-created",
    body: options.body,
    pr: options.pr,
    url: review.data?.html_url,
    inlineCount: prepared.comments.length,
    fallbackCount: prepared.skipped.length,
    warnings: options.warnings,
  };
}

async function publishIssueLevelComment(
  options: CommentOptions & {
    pr: number;
    body: string;
    updateExisting: boolean;
    client: GhClient;
    warnings: string[];
  },
): Promise<CommentResult> {
  let existing: IssueComment | undefined;
  if (options.updateExisting) {
    const comments = await options.client.api<IssueComment[]>({
      endpoint: `/repos/${options.remote.owner}/${options.remote.repo}/issues/${options.pr}/comments?per_page=100`,
    });
    if (!comments.ok)
      return {
        ok: false,
        mode: "error",
        body: options.body,
        pr: options.pr,
        error: comments.error,
        warnings: options.warnings,
      };
    existing = (comments.data ?? []).find(
      (comment) =>
        comment.user?.type === "Bot" && comment.body?.includes(options.config.github.commentMarker),
    );
  }

  if (existing) {
    const updated = await options.client.api<IssueComment>({
      endpoint: `/repos/${options.remote.owner}/${options.remote.repo}/issues/comments/${existing.id}`,
      method: "PATCH",
      input: { body: options.body },
    });
    if (!updated.ok)
      return {
        ok: false,
        mode: "error",
        body: options.body,
        pr: options.pr,
        error: updated.error,
        warnings: options.warnings,
      };
    return {
      ok: true,
      mode: "updated",
      body: options.body,
      pr: options.pr,
      commentId: updated.data?.id ?? existing.id,
      url: updated.data?.html_url ?? existing.html_url,
      warnings: options.warnings,
    };
  }

  const created = await options.client.api<IssueComment>({
    endpoint: `/repos/${options.remote.owner}/${options.remote.repo}/issues/${options.pr}/comments`,
    method: "POST",
    input: { body: options.body },
  });
  if (!created.ok)
    return {
      ok: false,
      mode: "error",
      body: options.body,
      pr: options.pr,
      error: created.error,
      warnings: options.warnings,
    };
  return {
    ok: true,
    mode: "created",
    body: options.body,
    pr: options.pr,
    commentId: created.data?.id,
    url: created.data?.html_url,
    warnings: options.warnings,
  };
}

async function getPullRequestHeadSha(
  options: CommentOptions & { pr: number; client: GhClient },
): Promise<string | undefined> {
  const pr = await options.client.api<PullRequest>({
    endpoint: `/repos/${options.remote.owner}/${options.remote.repo}/pulls/${options.pr}`,
  });
  return pr.ok ? pr.data?.head?.sha : undefined;
}

function defaultGhClient(repoRoot: string): GhClient {
  return {
    api: (options) => ghApi({ repoRoot, ...options }),
  };
}

function parseChangedLines(patch: string): Set<number> {
  const lines = new Set<number>();
  let newLine = 0;
  for (const line of patch.split("\n")) {
    const hunk = /^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@/u.exec(line);
    if (hunk) {
      newLine = Number(hunk[1]);
      continue;
    }
    if (line.startsWith("+++")) continue;
    if (line.startsWith("+")) {
      lines.add(newLine);
      newLine += 1;
      continue;
    }
    if (line.startsWith("-")) continue;
    if (newLine > 0) newLine += 1;
  }
  return lines;
}

function extractInlineMarker(body: string): string | undefined {
  return /<!--\s*pi-security-review-inline:([^\s>]+)\s*-->/u.exec(body)?.[1];
}

function errorResult(
  options: { body: string; pr: number; warnings: string[] },
  error: string,
): CommentResult {
  return {
    ok: false,
    mode: "error",
    body: options.body,
    pr: options.pr,
    error,
    warnings: options.warnings,
  };
}
