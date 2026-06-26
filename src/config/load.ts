/** Repo-local config loader/writer for pi-security-review. */

import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import { DEFAULT_CONFIG, type SecurityReviewConfig, validateAndMergeConfig } from "./schema.ts";

export function getConfigPath(repoRoot: string): string {
  return join(repoRoot, ".pi", "security-review.json");
}

export async function loadConfig(
  repoRoot: string,
): Promise<{ path: string; config: SecurityReviewConfig; exists: boolean }> {
  const path = getConfigPath(repoRoot);
  const raw = await tryReadText(path);

  if (raw === undefined) {
    return { path, config: structuredClone(DEFAULT_CONFIG), exists: false };
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (error) {
    throw new Error(`Invalid security-review config JSON at ${path}: ${(error as Error).message}`);
  }

  return { path, config: validateAndMergeConfig(parsed, path), exists: true };
}

export async function writeConfig(repoRoot: string, config: SecurityReviewConfig): Promise<string> {
  const path = getConfigPath(repoRoot);
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, `${JSON.stringify(config, null, 2)}\n`, "utf8");
  return path;
}

export async function ensureDefaultConfig(
  repoRoot: string,
): Promise<{ path: string; config: SecurityReviewConfig; created: boolean }> {
  const loaded = await loadConfig(repoRoot);
  if (loaded.exists) {
    return { path: loaded.path, config: loaded.config, created: false };
  }

  await writeConfig(repoRoot, loaded.config);
  return { path: loaded.path, config: loaded.config, created: true };
}

async function tryReadText(path: string): Promise<string | undefined> {
  try {
    return await readFile(path, "utf8");
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") {
      return undefined;
    }
    throw error;
  }
}
