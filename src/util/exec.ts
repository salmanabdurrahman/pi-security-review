/** Safe fixed-argv subprocess helpers. */

import { spawn } from "node:child_process";

export interface ExecResult {
  stdout: string;
  stderr: string;
  status: number | null;
}

export interface ExecOptions {
  cwd?: string;
  timeoutMs?: number;
  maxOutputBytes?: number;
  input?: string;
}

const DEFAULT_TIMEOUT_MS = 10_000;
const DEFAULT_MAX_OUTPUT_BYTES = 1024 * 1024;

export async function execFile(
  command: string,
  args: readonly string[],
  options: ExecOptions = {},
): Promise<ExecResult> {
  if (!command || command.includes("/") || command.includes("\\")) {
    throw new Error("Command must be executable name only.");
  }
  if (args.some((arg) => arg.includes("\0"))) {
    throw new Error("Command argument contains NUL byte.");
  }

  return await new Promise((resolve, reject) => {
    const child = spawn(command, [...args], {
      cwd: options.cwd,
      shell: false,
      stdio: [options.input === undefined ? "ignore" : "pipe", "pipe", "pipe"],
    });
    const maxOutputBytes = options.maxOutputBytes ?? DEFAULT_MAX_OUTPUT_BYTES;
    const stdout: Buffer[] = [];
    const stderr: Buffer[] = [];
    let stdoutBytes = 0;
    let stderrBytes = 0;
    let timedOut = false;

    const timer = setTimeout(() => {
      timedOut = true;
      child.kill("SIGTERM");
    }, options.timeoutMs ?? DEFAULT_TIMEOUT_MS);

    if (options.input !== undefined) {
      child.stdin?.end(options.input);
    }

    child.stdout?.on("data", (chunk: Buffer) => {
      stdoutBytes += chunk.byteLength;
      if (stdoutBytes <= maxOutputBytes) stdout.push(chunk);
    });
    child.stderr?.on("data", (chunk: Buffer) => {
      stderrBytes += chunk.byteLength;
      if (stderrBytes <= maxOutputBytes) stderr.push(chunk);
    });
    child.on("error", (error) => {
      clearTimeout(timer);
      reject(error);
    });
    child.on("close", (status) => {
      clearTimeout(timer);
      if (timedOut) {
        resolve({
          stdout: Buffer.concat(stdout).toString("utf8"),
          stderr: "Command timed out.",
          status: null,
        });
        return;
      }
      resolve({
        stdout: Buffer.concat(stdout).toString("utf8"),
        stderr: Buffer.concat(stderr).toString("utf8"),
        status,
      });
    });
  });
}

export async function execGit(
  repoRoot: string,
  args: readonly string[],
  options: ExecOptions = {},
): Promise<ExecResult> {
  return await execFile("git", args, { cwd: repoRoot, ...options });
}
