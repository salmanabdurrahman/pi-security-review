import { afterEach, describe, expect, test } from "bun:test";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DEFAULT_CONFIG } from "../src/config/schema.ts";
import { resolveDiffScope } from "../src/git/diff.ts";
import { buildRange, validateGitRef } from "../src/git/refs.ts";
import { parseGitHubRemote } from "../src/git/repo.ts";
import { getWorkingTreeStatus } from "../src/git/status.ts";
import { execFile } from "../src/util/exec.ts";

const temps: string[] = [];

afterEach(async () => {
  for (const dir of temps.splice(0)) await rm(dir, { recursive: true, force: true });
});

describe("git refs", () => {
  test("rejects injection-like refs", () => {
    expect(() => validateGitRef("main;rm -rf .")).toThrow("Unsafe git ref");
    expect(() => validateGitRef("--upload-pack=x")).toThrow("Unsafe git ref");
    expect(() => validateGitRef("main..evil")).toThrow("Unsafe git ref");
    expect(buildRange("origin/main", "HEAD")).toBe("origin/main...HEAD");
  });
});

describe("repo metadata", () => {
  test("parses GitHub remotes", () => {
    expect(parseGitHubRemote("git@github.com:owner/repo.git")).toEqual({
      owner: "owner",
      repo: "repo",
      url: "git@github.com:owner/repo.git",
    });
    expect(parseGitHubRemote("https://github.com/owner/repo")).toEqual({
      owner: "owner",
      repo: "repo",
      url: "https://github.com/owner/repo",
    });
    expect(parseGitHubRemote("https://example.com/owner/repo")).toBeUndefined();
  });
});

describe("status and diff scope", () => {
  test("detects staged, unstaged, untracked and filters secret/docs/tests", async () => {
    const repo = await tempRepo();
    await writeFile(join(repo, "src.ts"), "export const value = 1;\n", "utf8");
    await execFile("git", ["add", "src.ts"], { cwd: repo });
    await execFile("git", ["commit", "-m", "init"], { cwd: repo });

    await writeFile(join(repo, "src.ts"), "export const value = 2;\n", "utf8");
    await mkdir(join(repo, "docs"));
    await writeFile(join(repo, "docs", "guide.md"), "# doc\n", "utf8");
    await writeFile(join(repo, ".env"), "TOKEN=x\n", "utf8");
    await writeFile(join(repo, "util.test.ts"), "test('x', () => {});\n", "utf8");

    const status = await getWorkingTreeStatus(repo);
    expect(status.unstaged).toEqual(["src.ts"]);
    expect(status.untracked).toContain(".env");

    const scope = await resolveDiffScope(repo, DEFAULT_CONFIG);
    expect(scope.type).toBe("unstaged");
    expect(scope.diff).toContain("export const value = 2");
    expect(scope.files.find((file) => file.path === ".env")?.skipped).toBe("secret_like_path");
    expect(scope.files.find((file) => file.path === "docs/guide.md")?.skipped).toBe(
      "documentation",
    );
    expect(scope.files.find((file) => file.path === "util.test.ts")?.skipped).toBe("test");
  });

  test("truncates large diff with metadata", async () => {
    const repo = await tempRepo();
    await writeFile(join(repo, "src.ts"), "a\n", "utf8");
    await execFile("git", ["add", "src.ts"], { cwd: repo });
    await execFile("git", ["commit", "-m", "init"], { cwd: repo });
    await writeFile(join(repo, "src.ts"), `${"x".repeat(200)}\n`, "utf8");

    const scope = await resolveDiffScope(repo, { ...DEFAULT_CONFIG, maxDiffBytes: 40 });
    expect(scope.truncated).toBe(true);
    expect(scope.warnings.join("\n")).toContain("Diff truncated");
  });
});

async function tempRepo(): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), "pi-security-review-"));
  temps.push(dir);
  await execFile("git", ["init"], { cwd: dir });
  await execFile("git", ["config", "user.email", "test@example.com"], { cwd: dir });
  await execFile("git", ["config", "user.name", "Test"], { cwd: dir });
  return dir;
}
