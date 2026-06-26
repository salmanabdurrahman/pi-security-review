/** Git repository metadata helpers. */

import { execFile, execGit } from "../util/exec.ts";

export interface GitHubRemote {
  owner: string;
  repo: string;
  url: string;
}

export async function detectGitRoot(cwd = process.cwd()): Promise<string | undefined> {
  const result = await execFile("git", ["rev-parse", "--show-toplevel"], { cwd, timeoutMs: 5_000 });
  if (result.status !== 0) return undefined;
  const root = result.stdout.trim();
  return root.length > 0 ? root : undefined;
}

export async function getCurrentBranch(repoRoot: string): Promise<string | undefined> {
  const result = await execGit(repoRoot, ["branch", "--show-current"], { timeoutMs: 5_000 });
  if (result.status !== 0) return undefined;
  const branch = result.stdout.trim();
  return branch.length > 0 ? branch : undefined;
}

export async function getGitHubRemote(
  repoRoot: string,
  remote = "origin",
): Promise<GitHubRemote | undefined> {
  const result = await execGit(repoRoot, ["remote", "get-url", remote], { timeoutMs: 5_000 });
  if (result.status !== 0) return undefined;
  return parseGitHubRemote(result.stdout.trim());
}

export function parseGitHubRemote(url: string): GitHubRemote | undefined {
  const match = /github\.com[:/]([^/]+)\/([^/]+?)(?:\.git)?$/u.exec(url);
  if (!match) return undefined;
  const owner = match[1];
  const repo = match[2];
  if (!owner || !repo) return undefined;
  return { owner, repo, url };
}
