import { expect, test } from "bun:test";
import { DEFAULT_CONFIG } from "../src/config/schema.ts";
import {
  buildCommentBody,
  buildInlineCommentBody,
  buildInlineReviewComments,
  publishSecurityReviewComment,
} from "../src/github/comments.ts";
import type { SecurityFinding } from "../src/security/findings.ts";

const finding: SecurityFinding = {
  id: "sr-001",
  file: "src/auth.ts",
  line: 12,
  severity: "HIGH",
  category: "authorization",
  title: "Tenant bypass",
  description: "API trusts tenant id from request body.",
  exploitScenario: "Attacker submits another tenant id and reads data.",
  recommendation: "Derive tenant from authenticated session.",
  confidence: 0.95,
  status: "open",
};

test("inline comments only target changed PR diff lines", () => {
  const result = buildInlineReviewComments({
    findings: [finding, { ...finding, id: "sr-002", line: 9 }],
    prFiles: [
      {
        filename: "src/auth.ts",
        patch: "@@ -10,3 +10,4 @@\n context\n unchanged\n+added line\n",
      },
    ],
  });

  expect(result.comments).toHaveLength(1);
  expect(result.comments.at(0)).toMatchObject({ path: "src/auth.ts", line: 12, side: "RIGHT" });
  expect(result.comments.at(0)?.body).toContain("pi-security-review-inline:sr-001");
  expect(result.skipped).toHaveLength(1);
  expect(result.skipped.at(0)?.reason).toContain("line is not a changed line");
});

test("inline comments skip duplicate finding markers", () => {
  const result = buildInlineReviewComments({
    findings: [finding],
    prFiles: [
      {
        filename: "src/auth.ts",
        patch: "@@ -12,1 +12,1 @@\n+added line\n",
      },
    ],
    existingComments: [{ id: 1, body: "<!-- pi-security-review-inline:sr-001 -->" }],
  });

  expect(result.comments).toHaveLength(0);
  expect(result.skipped).toHaveLength(1);
  expect(result.skipped.at(0)?.reason).toContain("duplicate");
});

test("inline comments fall back when finding file is absent from PR diff", () => {
  const result = buildInlineReviewComments({
    findings: [finding],
    prFiles: [{ filename: "src/other.ts", patch: "@@ -1,0 +1,1 @@\n+ok\n" }],
  });

  expect(result.comments).toHaveLength(0);
  expect(result.skipped.at(0)?.reason).toContain("file is not in PR diff");
});

test("comment bodies redact secret-like values", () => {
  const body = buildCommentBody(
    "# Security Review\n\nFinding echoed bearer token Bearer abcdefghijklmnopqrstuvwxyz123456.",
    DEFAULT_CONFIG,
  );
  expect(body).toContain("[REDACTED_SECRET]");
  expect(body).not.toContain("abcdefghijklmnopqrstuvwxyz123456");

  const inline = buildInlineCommentBody({
    ...finding,
    description: "Model echoed GitHub token ghp_abcdefghijklmnopqrstuvwxyz123456.",
  });
  expect(inline).toContain("[REDACTED_SECRET]");
  expect(inline).not.toContain("ghp_abcdefghijklmnopqrstuvwxyz123456");
});

test("publishes issue-level summary by default with mock GitHub client", async () => {
  const calls: Array<{ endpoint: string; method?: string; input?: unknown }> = [];
  const result = await publishSecurityReviewComment({
    repoRoot: "/tmp/repo",
    remote: { owner: "acme", repo: "app", url: "https://github.com/acme/app.git" },
    config: DEFAULT_CONFIG,
    markdown: "# Security Review\n\nNo findings.",
    pr: 7,
    dryRun: false,
    approve: true,
    updateExisting: false,
    ghClient: {
      api: async (call) => {
        calls.push(call);
        return {
          ok: true,
          data: { id: 11, html_url: "https://example.test/c/11" },
          stdout: "{}",
          stderr: "",
        } as any;
      },
    },
  });

  expect(result.mode).toBe("created");
  expect(calls).toHaveLength(1);
  expect(calls.at(0)?.endpoint).toBe("/repos/acme/app/issues/7/comments");
});

test("publishes inline review comments with mock GitHub client", async () => {
  const calls: Array<{ endpoint: string; method?: string; input?: any }> = [];
  const result = await publishSecurityReviewComment({
    repoRoot: "/tmp/repo",
    remote: { owner: "acme", repo: "app", url: "https://github.com/acme/app.git" },
    config: DEFAULT_CONFIG,
    markdown: "# Security Review\n\nFinding found.",
    pr: 7,
    dryRun: false,
    approve: true,
    inline: true,
    inlineFindings: [finding],
    ghClient: {
      api: async (call) => {
        calls.push(call);
        if (call.endpoint.endsWith("/files?per_page=100")) {
          return {
            ok: true,
            data: [{ filename: "src/auth.ts", patch: "@@ -12,0 +12,1 @@\n+added line\n" }],
            stdout: "[]",
            stderr: "",
          } as any;
        }
        if (call.endpoint.endsWith("/comments?per_page=100")) {
          return { ok: true, data: [], stdout: "[]", stderr: "" } as any;
        }
        if (call.endpoint.endsWith("/pulls/7")) {
          return { ok: true, data: { head: { sha: "abc123" } }, stdout: "{}", stderr: "" } as any;
        }
        return {
          ok: true,
          data: { id: 12, html_url: "https://example.test/r/12" },
          stdout: "{}",
          stderr: "",
        } as any;
      },
    },
  });

  expect(result.mode).toBe("inline-created");
  expect(result.inlineCount).toBe(1);
  const reviewCall = calls.find((call) => call.endpoint.endsWith("/reviews"));
  expect(reviewCall?.input.comments.at(0)?.body).toContain("pi-security-review-inline:sr-001");
});
