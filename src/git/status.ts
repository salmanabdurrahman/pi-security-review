/** Working tree status helpers. */

import { execGit } from "../util/exec.ts";

export interface WorkingTreeStatus {
  clean: boolean;
  staged: string[];
  unstaged: string[];
  untracked: string[];
}

export async function getWorkingTreeStatus(repoRoot: string): Promise<WorkingTreeStatus> {
  const result = await execGit(
    repoRoot,
    ["status", "--porcelain=v1", "-z", "--untracked-files=all"],
    {
      timeoutMs: 5_000,
      maxOutputBytes: 512_000,
    },
  );
  if (result.status !== 0) return { clean: true, staged: [], unstaged: [], untracked: [] };

  const staged: string[] = [];
  const unstaged: string[] = [];
  const untracked: string[] = [];
  const entries = result.stdout.split("\0").filter(Boolean);

  for (let index = 0; index < entries.length; index += 1) {
    const entry = entries[index] ?? "";
    const x = entry[0] ?? " ";
    const y = entry[1] ?? " ";
    const path = normalizeStatusPath(entry.slice(3));

    if (x === "?" && y === "?") {
      untracked.push(path);
      continue;
    }
    if (x === "R" || y === "R") index += 1;
    if (x !== " " && x !== "?") staged.push(path);
    if (y !== " " && y !== "?") unstaged.push(path);
  }

  return {
    clean: staged.length === 0 && unstaged.length === 0 && untracked.length === 0,
    staged: [...new Set(staged)].sort(),
    unstaged: [...new Set(unstaged)].sort(),
    untracked: [...new Set(untracked)].sort(),
  };
}

function normalizeStatusPath(path: string): string {
  return path.replace(/\\/gu, "/").replace(/^\.\//u, "");
}
