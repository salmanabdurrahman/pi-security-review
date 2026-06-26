import { afterEach, expect, test } from "bun:test";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import extension from "../index.ts";
import { execFile } from "../src/util/exec.ts";

const temps: string[] = [];

afterEach(async () => {
  for (const dir of temps.splice(0)) await rm(dir, { recursive: true, force: true });
});

test("exports extension bootstrap", () => {
  expect(typeof extension).toBe("function");
});

test("registers phase 2 commands and session status", async () => {
  const commands = new Map<
    string,
    { description: string; handler: (args: string, ctx: any) => Promise<void> }
  >();
  const events = new Map<string, (payload: unknown, ctx: any) => Promise<void> | void>();

  await extension({
    registerCommand(
      name: string,
      command: { description: string; handler: (args: string, ctx: any) => Promise<void> },
    ) {
      commands.set(name, command);
    },
    on(event: string, handler: (payload: unknown, ctx: any) => Promise<void> | void) {
      events.set(event, handler);
    },
  });

  expect([...commands.keys()].sort()).toEqual([
    "security-review",
    "security-review-ci-help",
    "security-review-comment",
    "security-review-config",
    "security-review-panel",
    "security-review-status",
  ]);
  expect(events.has("session_start")).toBe(true);
});

test("security-review queues prompt and captures marker report", async () => {
  const repo = await tempRepo();
  await writeFile(join(repo, "auth.ts"), "export const ok = true;\n", "utf8");
  await execFile("git", ["add", "auth.ts"], { cwd: repo });
  await execFile("git", ["commit", "-m", "init"], { cwd: repo });
  await writeFile(join(repo, "auth.ts"), "export const ok = false;\n", "utf8");

  const commands = new Map<string, { handler: (args: string, ctx: any) => Promise<void> }>();
  const events = new Map<string, (payload: unknown, ctx: any) => Promise<void> | void>();
  const sent: string[] = [];

  await extension({
    registerCommand(name: string, command: { handler: (args: string, ctx: any) => Promise<void> }) {
      commands.set(name, command);
    },
    on(event: string, handler: (payload: unknown, ctx: any) => Promise<void> | void) {
      events.set(event, handler);
    },
    sendUserMessage(message: string) {
      sent.push(message);
    },
  });

  await commands.get("security-review")?.handler("auth.ts", {
    cwd: repo,
    isIdle: () => true,
    ui: { notify() {}, setStatus() {} },
    model: { provider: "local", id: "qwen" },
  });

  expect(sent).toHaveLength(1);
  expect(sent[0]).toContain("# /security-review");
  expect(sent[0]).toContain("auth.ts");

  await events.get("message_end")?.(
    {
      text: [
        "# Security Review",
        "",
        "No high-confidence HIGH/MEDIUM findings found.",
        "",
        "<!-- pi-security-review-json -->",
        JSON.stringify({
          findings: [],
          excludedFindings: [],
          analysisSummary: {
            filesReviewed: 1,
            highSeverity: 0,
            mediumSeverity: 0,
            lowSeverity: 0,
            reviewCompleted: true,
          },
        }),
        "<!-- /pi-security-review-json -->",
      ].join("\n"),
    },
    { cwd: repo, ui: { notify() {}, setStatus() {} } },
  );

  const markdown = await readFile(join(repo, ".pi", "security-review", "latest-report.md"), "utf8");
  const json = JSON.parse(
    await readFile(join(repo, ".pi", "security-review", "latest-report.json"), "utf8"),
  );
  expect(markdown).toContain("# Security Review");
  expect(markdown).not.toContain("pi-security-review-json");
  expect(json.summary.reviewCompleted).toBe(true);
});

test("capture hook stores deterministic-filtered model output", async () => {
  const repo = await tempRepo();
  const events = new Map<string, (payload: unknown, ctx: any) => Promise<void> | void>();

  await extension({
    registerCommand() {},
    on(event: string, handler: (payload: unknown, ctx: any) => Promise<void> | void) {
      events.set(event, handler);
    },
  });

  await events.get("message_end")?.(
    {
      text: [
        "# Security Review",
        "",
        "Model included noisy findings.",
        "",
        "<!-- pi-security-review-json -->",
        JSON.stringify({
          findings: [
            {
              id: "sr-keep",
              file: "src/api.ts",
              line: 7,
              severity: "HIGH",
              category: "auth_bypass",
              title: "Tenant authorization bypass",
              description: "Server-side authorization check can be bypassed.",
              exploitScenario:
                "Attacker requests another tenant invoice and receives private data.",
              recommendation: "Check tenant access before returning invoice.",
              confidence: 0.95,
              status: "open",
            },
            {
              id: "sr-low",
              file: "src/api.ts",
              severity: "LOW",
              category: "rate_limit",
              title: "Missing rate limit",
              description: "Add rate limiting to endpoint.",
              exploitScenario: "Many requests overwhelm service.",
              recommendation: "Add rate limits.",
              confidence: 0.9,
              status: "open",
            },
            {
              id: "sr-docs",
              file: "docs/security.md",
              severity: "HIGH",
              category: "docs",
              title: "Documentation mentions insecure option",
              description: "Docs-only issue.",
              exploitScenario: "Reader follows docs.",
              recommendation: "Update docs.",
              confidence: 0.9,
              status: "open",
            },
            {
              id: "sr-confidence",
              file: "src/api.ts",
              severity: "HIGH",
              category: "unknown",
              title: "Possible issue",
              description: "Maybe exploitable.",
              exploitScenario: "No concrete path.",
              recommendation: "Investigate.",
              confidence: 0.2,
              status: "open",
            },
          ],
          excludedFindings: [],
          analysisSummary: {
            filesReviewed: 3,
            highSeverity: 3,
            mediumSeverity: 0,
            lowSeverity: 1,
            reviewCompleted: true,
          },
        }),
        "<!-- /pi-security-review-json -->",
      ].join("\n"),
    },
    { cwd: repo, ui: { notify() {}, setStatus() {} } },
  );

  const markdown = await readFile(join(repo, ".pi", "security-review", "latest-report.md"), "utf8");
  const json = JSON.parse(
    await readFile(join(repo, ".pi", "security-review", "latest-report.json"), "utf8"),
  );
  expect(json.findings.map((item: any) => item.id)).toEqual(["sr-keep"]);
  expect(json.excludedFindings).toHaveLength(3);
  expect(json.metadata.filtering.deterministic).toMatchObject({
    executed: true,
    total: 4,
    kept: 1,
    excluded: 3,
  });
  expect(json.metadata.filtering.model.executed).toBe(false);
  expect(markdown).toContain("Tenant authorization bypass");
  expect(markdown).not.toContain("Missing rate limit in");
});

test("security-review-comment previews latest report by default", async () => {
  const repo = await tempRepo();
  await mkdir(join(repo, ".pi", "security-review"), { recursive: true });
  await writeFile(
    join(repo, ".pi", "security-review", "latest-report.md"),
    "# Security Review\n\nNo findings.\n",
    "utf8",
  );

  const commands = new Map<string, { handler: (args: string, ctx: any) => Promise<void> }>();
  const notifications: string[] = [];

  await extension({
    registerCommand(name: string, command: { handler: (args: string, ctx: any) => Promise<void> }) {
      commands.set(name, command);
    },
  });

  await commands.get("security-review-comment")?.handler("--pr 12", {
    cwd: repo,
    ui: {
      notify(message: string) {
        notifications.push(message);
      },
    },
  });

  const output = notifications.join("\n");
  expect(output).toContain("security-review comment dry-run");
  expect(output).toContain("pr: 12");
  expect(output).toContain("<!-- pi-security-review -->");
  expect(output).toContain("# Security Review");
});

test("security-review-comment refuses missing report", async () => {
  const repo = await tempRepo();
  const commands = new Map<string, { handler: (args: string, ctx: any) => Promise<void> }>();
  const notifications: string[] = [];

  await extension({
    registerCommand(name: string, command: { handler: (args: string, ctx: any) => Promise<void> }) {
      commands.set(name, command);
    },
  });

  await commands.get("security-review-comment")?.handler("--pr 12 --yes", {
    cwd: repo,
    ui: {
      notify(message: string) {
        notifications.push(message);
      },
    },
  });

  expect(notifications.join("\n")).toContain("latest report missing");
});

test("status command includes repo health fields", async () => {
  const repo = await tempRepo();
  await mkdir(join(repo, ".pi", "security-review"), { recursive: true });
  await writeFile(
    join(repo, ".pi", "security-review.json"),
    JSON.stringify({
      modelProfiles: { auditor: { provider: "local", model: "qwen", thinkingLevel: "high" } },
    }),
    "utf8",
  );
  await writeFile(
    join(repo, ".pi", "security-review", "latest-report.md"),
    "# Security Review\n",
    "utf8",
  );

  const commands = new Map<string, { handler: (args: string, ctx: any) => Promise<void> }>();
  const notifications: string[] = [];

  await extension({
    registerCommand(name: string, command: { handler: (args: string, ctx: any) => Promise<void> }) {
      commands.set(name, command);
    },
  });

  await commands.get("security-review-status")?.handler("", {
    cwd: repo,
    ui: {
      notify(message: string) {
        notifications.push(message);
      },
      setStatus() {},
    },
    model: { provider: "local", id: "qwen" },
  });

  const output = notifications.join("\n");
  expect(output).toContain("repoRoot:");
  expect(output).toContain("latestReport:");
  expect(output).toContain("activeModel: local/qwen");
  expect(output).toContain("configuredModelProfiles: auditor=local/qwen, thinking=high");
  expect(output).toContain("githubRemote:");
  expect(output).toContain("ghAuth:");
});

test("panel shows no report and malformed json warning with UI fallback", async () => {
  const repo = await tempRepo();
  const commands = new Map<string, { handler: (args: string, ctx: any) => Promise<void> }>();
  const notifications: string[] = [];
  const editor: string[] = [];

  await extension({
    registerCommand(name: string, command: { handler: (args: string, ctx: any) => Promise<void> }) {
      commands.set(name, command);
    },
  });

  await commands.get("security-review-panel")?.handler("", {
    cwd: repo,
    ui: {
      notify(message: string) {
        notifications.push(message);
      },
    },
  });
  expect(notifications.join("\n")).toContain("No security review report available yet.");

  await mkdir(join(repo, ".pi", "security-review"), { recursive: true });
  await writeFile(
    join(repo, ".pi", "security-review", "latest-report.md"),
    "# Security Review\n",
    "utf8",
  );
  await writeFile(join(repo, ".pi", "security-review", "latest-report.json"), "{", "utf8");
  await commands.get("security-review-panel")?.handler("", {
    cwd: repo,
    ui: {
      notify() {},
      editor(_title: string, content: string) {
        editor.push(content);
      },
    },
  });
  expect(editor.at(-1)).toContain("Warning: Invalid security-review latest report JSON");
});

test("status command does not crash outside git repo", async () => {
  const commands = new Map<string, { handler: (args: string, ctx: any) => Promise<void> }>();
  const notifications: string[] = [];
  const statuses: string[] = [];

  await extension({
    registerCommand(name: string, command: { handler: (args: string, ctx: any) => Promise<void> }) {
      commands.set(name, command);
    },
  });

  const status = commands.get("security-review-status");
  expect(status).toBeDefined();

  await status?.handler("", {
    cwd: "/tmp",
    ui: {
      notify(message: string) {
        notifications.push(message);
      },
      setStatus(_key: string, value: string) {
        statuses.push(value);
      },
    },
  });

  expect(notifications.join("\n")).toContain("pi-security-review status");
  expect(statuses.at(-1)).toBe("security-review: no-git");
});

async function tempRepo(): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), "pi-sr-extension-"));
  temps.push(dir);
  await execFile("git", ["init"], { cwd: dir });
  await execFile("git", ["config", "user.email", "test@example.com"], { cwd: dir });
  await execFile("git", ["config", "user.name", "Test"], { cwd: dir });
  return dir;
}
