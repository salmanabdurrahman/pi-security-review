/** Safe GitHub CLI helpers for PR comments. */

import { execFile } from "../util/exec.ts";

export interface GhAvailability {
  available: boolean;
  version?: string;
  error?: string;
}

export interface GhAuthCheck {
  authenticated: boolean;
  user?: string;
  host?: string;
  error?: string;
}

export interface GhApiOptions {
  repoRoot: string;
  endpoint: string;
  method?: "GET" | "POST" | "PATCH";
  input?: unknown;
  timeoutMs?: number;
}

export interface GhApiResult<T = unknown> {
  ok: boolean;
  data?: T;
  error?: string;
  stdout: string;
  stderr: string;
}

export async function checkGhAvailable(cwd: string): Promise<GhAvailability> {
  try {
    const result = await execFile("gh", ["--version"], { cwd, timeoutMs: 5_000 });
    if (result.status !== 0)
      return {
        available: false,
        error: compact(result.stderr || result.stdout) || "gh not available",
      };
    return { available: true, version: result.stdout.split("\n")[0]?.trim() };
  } catch (error) {
    return { available: false, error: `gh: ${(error as Error).message}` };
  }
}

export async function checkGhAuth(cwd: string): Promise<GhAuthCheck> {
  try {
    const result = await execFile("gh", ["auth", "status"], { cwd, timeoutMs: 10_000 });
    if (result.status !== 0)
      return {
        authenticated: false,
        error: compact(result.stderr || result.stdout) || "not authenticated",
      };
    const text = `${result.stdout}\n${result.stderr}`;
    const user = /account\s+(\S+)/iu.exec(text)?.[1];
    const host = /^\s*([a-z0-9.-]+)\s*$/imu.exec(text)?.[1] ?? "github.com";
    return { authenticated: true, user, host };
  } catch (error) {
    return { authenticated: false, error: `gh: ${(error as Error).message}` };
  }
}

export async function ghApi<T = unknown>(options: GhApiOptions): Promise<GhApiResult<T>> {
  validateEndpoint(options.endpoint);
  const args = ["api", options.endpoint, "--method", options.method ?? "GET"];
  const input = options.input === undefined ? undefined : `${JSON.stringify(options.input)}\n`;
  if (input !== undefined) args.push("--input", "-");

  const result = await execFile("gh", args, {
    cwd: options.repoRoot,
    timeoutMs: options.timeoutMs ?? 20_000,
    input,
  });
  if (result.status !== 0) {
    return {
      ok: false,
      error: compact(result.stderr || result.stdout) || "gh api failed",
      stdout: result.stdout,
      stderr: result.stderr,
    };
  }
  const trimmed = result.stdout.trim();
  if (!trimmed)
    return { ok: true, data: undefined as T, stdout: result.stdout, stderr: result.stderr };
  try {
    return {
      ok: true,
      data: JSON.parse(trimmed) as T,
      stdout: result.stdout,
      stderr: result.stderr,
    };
  } catch (error) {
    return {
      ok: false,
      error: `Invalid gh JSON output: ${(error as Error).message}`,
      stdout: result.stdout,
      stderr: result.stderr,
    };
  }
}

function validateEndpoint(endpoint: string): void {
  if (!endpoint.startsWith("/repos/"))
    throw new Error("GitHub API endpoint must start with /repos/.");
  if (endpoint.includes("\0") || /\s/u.test(endpoint))
    throw new Error("Invalid GitHub API endpoint.");
}

function compact(text: string): string {
  return text.replace(/\s+/gu, " ").trim();
}
