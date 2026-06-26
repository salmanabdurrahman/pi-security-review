import { afterEach, expect, test } from "bun:test";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import extension from "../index.ts";
import { execFile } from "../src/util/exec.ts";

const temps: string[] = [];

afterEach(async () => {
  for (const dir of temps.splice(0)) await rm(dir, { recursive: true, force: true });
});

test("registers security-review LLM tools", async () => {
  const tools = new Map<string, any>();
  await extension({
    registerCommand() {},
    registerTool(tool: any) {
      tools.set(tool.name, tool);
    },
  });

  expect([...tools.keys()].sort()).toEqual([
    "security_review_analyze_diff",
    "security_review_build_context",
    "security_review_filter_findings",
    "security_review_github_comment",
    "security_review_model_profiles",
    "security_review_render_report",
    "security_review_stats",
  ]);

  for (const tool of tools.values()) {
    expect(tool.parameters).toBeDefined();
    expect(tool.promptSnippet).toContain(tool.name);
    expect(tool.promptGuidelines.join("\n")).toContain(tool.name);
  }
});

test("security_review_github_comment is gated and dry-run by default", async () => {
  const repo = await tempRepo();
  await writeFile(join(repo, "auth.ts"), "export const ok = true;\n", "utf8");
  await execFile("git", ["add", "auth.ts"], { cwd: repo });
  await execFile("git", ["commit", "-m", "init"], { cwd: repo });

  const tools = new Map<string, any>();
  await extension({
    registerCommand() {},
    registerTool(tool: any) {
      tools.set(tool.name, tool);
    },
  });
  const tool = tools.get("security_review_github_comment");

  const preview = await tool.execute(
    "1",
    { reportMarkdown: "# Security Review\n\nNo findings.", pr: 7 },
    undefined,
    undefined,
    { cwd: repo },
  );
  expect(preview.content[0].text).toContain("dry-run");
  expect(preview.content[0].text).toContain("<!-- pi-security-review -->");
  expect(preview.details.dryRun).toBe(true);

  await expect(
    tool.execute(
      "2",
      { reportMarkdown: "# Security Review", pr: 7, post: true },
      undefined,
      undefined,
      { cwd: repo },
    ),
  ).rejects.toThrow("post: true and approve: true");
  await expect(
    tool.execute(
      "3",
      { reportMarkdown: "# Security Review", pr: 7, post: true, approve: true },
      undefined,
      undefined,
      { cwd: repo },
    ),
  ).rejects.toThrow("GitHub remote not detected");
});

test("security_review_filter_findings and render_report produce bounded output", async () => {
  const repo = await tempRepo();
  await writeFile(join(repo, "auth.ts"), "export const ok = true;\n", "utf8");
  await execFile("git", ["add", "auth.ts"], { cwd: repo });
  await execFile("git", ["commit", "-m", "init"], { cwd: repo });

  const tools = new Map<string, any>();
  await extension({
    registerCommand() {},
    registerTool(tool: any) {
      tools.set(tool.name, tool);
    },
  });

  const findings = [
    {
      id: "sr-1",
      file: "src/auth.ts",
      severity: "HIGH",
      category: "authorization",
      title: "Missing server-side authorization",
      description: "API allows tenant boundary authorization bypass.",
      exploitScenario: "Attacker changes tenant id in request body to read another tenant.",
      recommendation: "Enforce server-side tenant ownership check.",
      confidence: 0.95,
    },
  ];
  const filtered = await tools
    .get("security_review_filter_findings")
    .execute("1", { findings: JSON.stringify(findings) }, undefined, undefined, { cwd: repo });
  expect(filtered.content[0].text.length).toBeLessThanOrEqual(50_050);
  expect(filtered.content[0].text).toContain("keptFindings");

  const reportPayload = {
    findings,
    excludedFindings: [],
    analysisSummary: {
      filesReviewed: 1,
      highSeverity: 1,
      mediumSeverity: 0,
      lowSeverity: 0,
      reviewCompleted: true,
    },
  };
  const rendered = await tools
    .get("security_review_render_report")
    .execute("2", { payload: JSON.stringify(reportPayload) }, undefined, undefined, { cwd: repo });
  expect(rendered.content[0].text).toContain("# Security Review");
  expect(rendered.content[0].text).toContain("Missing server-side authorization");
});

async function tempRepo(): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), "pi-sr-tools-"));
  temps.push(dir);
  await execFile("git", ["init"], { cwd: dir });
  await execFile("git", ["config", "user.email", "test@example.com"], { cwd: dir });
  await execFile("git", ["config", "user.name", "Test"], { cwd: dir });
  return dir;
}
