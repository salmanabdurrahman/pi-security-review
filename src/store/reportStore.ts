/** Latest report storage for pi-security-review. */

import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { redactSecretLikeValues, redactSecretsInValue } from "../security/redaction.ts";

export const REPORT_DIR = ".pi/security-review";
export const LATEST_MARKDOWN = "latest-report.md";
export const LATEST_JSON = "latest-report.json";

export type LatestReportJson = Record<string, unknown>;

export function getReportDir(repoRoot: string): string {
  return join(repoRoot, REPORT_DIR);
}

export function getLatestMarkdownPath(repoRoot: string): string {
  return join(getReportDir(repoRoot), LATEST_MARKDOWN);
}

export function getLatestJsonPath(repoRoot: string): string {
  return join(getReportDir(repoRoot), LATEST_JSON);
}

export async function readLatestMarkdown(repoRoot: string): Promise<string | undefined> {
  return tryReadText(getLatestMarkdownPath(repoRoot));
}

export async function readLatestJson(repoRoot: string): Promise<LatestReportJson | undefined> {
  const path = getLatestJsonPath(repoRoot);
  const raw = await tryReadText(path);
  if (raw === undefined) return undefined;

  try {
    return JSON.parse(raw) as LatestReportJson;
  } catch (error) {
    throw new Error(
      `Invalid security-review latest report JSON at ${path}: ${(error as Error).message}`,
    );
  }
}

export async function writeLatestMarkdown(repoRoot: string, markdown: string): Promise<string> {
  const path = getLatestMarkdownPath(repoRoot);
  await mkdir(getReportDir(repoRoot), { recursive: true });
  await writeFile(path, redactSecretLikeValues(markdown), "utf8");
  return path;
}

export async function writeLatestJson(repoRoot: string, report: LatestReportJson): Promise<string> {
  assertNoSecretLikeKeys(report, "report");
  const redactedReport = redactSecretsInValue(report);
  const path = getLatestJsonPath(repoRoot);
  await mkdir(getReportDir(repoRoot), { recursive: true });
  await writeFile(path, `${JSON.stringify(redactedReport, null, 2)}\n`, "utf8");
  return path;
}

function assertNoSecretLikeKeys(value: unknown, path: string): void {
  if (Array.isArray(value)) {
    value.forEach((item, index) => {
      assertNoSecretLikeKeys(item, `${path}[${index}]`);
    });
    return;
  }
  if (!value || typeof value !== "object") return;

  for (const [key, child] of Object.entries(value)) {
    if (/api[-_]?key|token|password|secret|private[-_]?key/i.test(key)) {
      throw new Error(`Refusing to store secret-like report field: ${path}.${key}`);
    }
    assertNoSecretLikeKeys(child, `${path}.${key}`);
  }
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
