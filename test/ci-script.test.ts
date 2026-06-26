import { afterEach, expect, test } from "bun:test";
import { existsSync } from "node:fs";
import { mkdtemp, readdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { execFile } from "../src/util/exec.ts";

const temps: string[] = [];
const scriptPath = resolve(import.meta.dir, "..", "scripts", "security-review-ci.ts");

afterEach(async () => {
  for (const dir of temps.splice(0)) await rm(dir, { recursive: true, force: true });
});

test("GitHub Action surface is artifact-only by default", async () => {
  const actionPath = resolve(import.meta.dir, "..", "action.yml");
  const action = await readFile(actionPath, "utf8");
  expect(action).toContain('name: "Pi Security Review"');
  expect(action).toContain("final-report:");
  expect(action).toContain("comment:");
  expect(action).toContain('default: "false"');
  expect(action).not.toContain("claude-api-key");
  expect(action).not.toContain("openai-api-key");
});

test("repo workflows cover CI and manual publish readiness without publishing", async () => {
  const workflowsDir = resolve(import.meta.dir, "..", ".github", "workflows");
  const workflows = await readdir(workflowsDir);
  expect(workflows).toContain("ci.yml");
  expect(workflows).toContain("publish-readiness.yml");
  const publishReadiness = await readFile(join(workflowsDir, "publish-readiness.yml"), "utf8");
  expect(publishReadiness).toContain("workflow_dispatch");
  expect(publishReadiness).toContain("does not publish");
  expect(publishReadiness).not.toContain("npm publish");
});

test("security-review CI help prints artifact-only mode", async () => {
  const result = await execFile("bun", [scriptPath, "--ci-help"], {
    cwd: import.meta.dir,
    timeoutMs: 20_000,
  });
  expect(result.status).toBe(0);
  expect(result.stdout).toContain("Artifact-only mode");
  expect(result.stdout).toContain("--comment");
});

test("security-review CI writes bounded artifacts without network comment", async () => {
  const repo = await tempRepo();
  await writeFile(join(repo, "src.ts"), "export const ok = true;\n", "utf8");
  await execFile("git", ["add", "src.ts"], { cwd: repo });
  await execFile("git", ["commit", "-m", "init"], { cwd: repo });
  await writeFile(join(repo, "src.ts"), "export const ok = false;\n", "utf8");

  const outputPath = join(repo, "artifacts", "context.json");
  const markdownPath = join(repo, "artifacts", "report.md");
  const result = await execFile(
    "bun",
    [scriptPath, "--output", outputPath, "--markdown", markdownPath, "--model", "local/test"],
    { cwd: repo, timeoutMs: 30_000 },
  );

  expect(result.status).toBe(0);
  expect(result.stdout).toContain("ok: true");
  expect(existsSync(outputPath)).toBe(true);
  expect(existsSync(markdownPath)).toBe(true);

  const context = JSON.parse(await readFile(outputPath, "utf8"));
  expect(context.mode).toBe("artifact-only");
  expect(context.prompt).toContain("# /security-review");
  expect(context.context.model.requestedModel).toBe("local/test");

  const markdown = await readFile(markdownPath, "utf8");
  expect(markdown).toContain("Security Review CI Context");
  expect(markdown).toContain("CI artifact-only mode generated context and prompt only");
});

test("security-review CI refuses comment without yes", async () => {
  const repo = await tempRepo();
  const result = await execFile("bun", [scriptPath, "--comment", "--pr", "1"], {
    cwd: repo,
    timeoutMs: 20_000,
  });
  expect(result.status).toBe(1);
  expect(result.stdout).toContain("GitHub comment mutation requires both --comment and --yes");
});

test("security-review CI refuses artifact-only comment even with yes", async () => {
  const repo = await tempRepo();
  const result = await execFile("bun", [scriptPath, "--comment", "--yes", "--pr", "1"], {
    cwd: repo,
    timeoutMs: 20_000,
  });
  expect(result.status).toBe(1);
  expect(result.stdout).toContain("Refusing to comment artifact-only security context");
});

test("security-review CI reads external final report and applies fail gate", async () => {
  const repo = await tempRepo();
  await writeFile(join(repo, "src.ts"), "export const ok = true;\n", "utf8");
  await execFile("git", ["add", "src.ts"], { cwd: repo });
  await execFile("git", ["commit", "-m", "init"], { cwd: repo });
  await writeFile(join(repo, "src.ts"), "export const ok = false;\n", "utf8");

  const finalReport = join(repo, "final.md");
  await writeFile(
    finalReport,
    `# Final\n\n<!-- pi-security-review-json -->\n{"findings":[{"id":"sr-001","file":"src.ts","line":1,"severity":"HIGH","category":"auth_bypass","title":"Bad auth","description":"desc","exploitScenario":"exploit","recommendation":"fix","confidence":0.95,"status":"open"}],"excludedFindings":[],"analysisSummary":{"filesReviewed":1,"highSeverity":1,"mediumSeverity":0,"lowSeverity":0,"reviewCompleted":true}}\n<!-- /pi-security-review-json -->\n`,
    "utf8",
  );

  const outputPath = join(repo, "artifacts", "final.json");
  const result = await execFile(
    "bun",
    [scriptPath, "--final-report", finalReport, "--output", outputPath, "--fail-on-high"],
    { cwd: repo, timeoutMs: 30_000 },
  );

  expect(result.status).toBe(1);
  expect(result.stdout).toContain("mode: external-final-report");
  expect(result.stdout).toContain("highSeverity: 1");
  const output = JSON.parse(await readFile(outputPath, "utf8"));
  expect(output.mode).toBe("external-final-report");
  expect(output.report.findings).toHaveLength(1);
});

async function tempRepo(): Promise<string> {
  const repo = await mkdtemp(join(tmpdir(), "pi-security-review-ci-"));
  temps.push(repo);
  await execFile("git", ["init"], { cwd: repo });
  await execFile("git", ["config", "user.email", "test@example.com"], { cwd: repo });
  await execFile("git", ["config", "user.name", "Test"], { cwd: repo });
  return repo;
}
