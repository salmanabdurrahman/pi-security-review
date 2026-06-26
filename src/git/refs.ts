/** Git ref validation and fallback base ref resolution. */

import { execGit } from "../util/exec.ts";

const SAFE_GIT_REF = /^[A-Za-z0-9][A-Za-z0-9._/@:-]{0,200}$/u;
const FALLBACK_BASE_REFS = [
  "@{upstream}",
  "origin/main",
  "origin/master",
  "main",
  "master",
] as const;

export function validateGitRef(ref: string): string {
  if (ref === "@{upstream}") return ref;
  if (!SAFE_GIT_REF.test(ref) || ref.includes("..") || ref.startsWith("-") || ref.includes("\0")) {
    throw new Error(`Unsafe git ref: ${ref}`);
  }
  return ref;
}

export async function refExists(repoRoot: string, ref: string): Promise<boolean> {
  const safeRef = validateGitRef(ref);
  const result = await execGit(repoRoot, ["rev-parse", "--verify", "--quiet", safeRef], {
    timeoutMs: 5_000,
  });
  return result.status === 0;
}

export async function findFallbackBaseRef(repoRoot: string): Promise<string | undefined> {
  for (const ref of FALLBACK_BASE_REFS) {
    if (await refExists(repoRoot, ref)) return ref;
  }
  return undefined;
}

export function buildRange(base: string, head = "HEAD"): string {
  return `${validateGitRef(base)}...${validateGitRef(head)}`;
}
