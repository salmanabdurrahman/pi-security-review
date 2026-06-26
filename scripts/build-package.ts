/**
 * Build package output by copying runtime TypeScript sources into `dist/`.
 *
 * Pi can load TypeScript through runtime loader, so build step preserves source
 * files instead of transpiling. Copy rules stay intentionally strict to keep
 * tests, fixtures, dev scripts and local output out of published
 * package surface.
 */

import { copyFile, mkdir, readdir, rm, stat } from "node:fs/promises";
import { dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT_DIR = process.cwd();
const DIST_DIR = join(ROOT_DIR, "dist");
const scriptPath = fileURLToPath(import.meta.url);
const COPY_ROOTS = ["index.ts", "src", "scripts/security-review-ci.ts"] as const;
const SKIP_SEGMENTS = new Set(["__tests__", "__fixtures__", "fixtures", "benchmark"]);
const SKIP_FILE_PATTERNS = [/\.test\.[cm]?[jt]sx?$/u, /\.spec\.[cm]?[jt]sx?$/u];

async function buildPackage(): Promise<void> {
  await rm(DIST_DIR, { recursive: true, force: true });
  await mkdir(DIST_DIR, { recursive: true });

  for (const root of COPY_ROOTS) {
    const sourcePath = join(ROOT_DIR, root);
    if (!(await pathExists(sourcePath))) {
      continue;
    }

    const sourceStat = await stat(sourcePath);
    if (sourceStat.isDirectory()) {
      await copyDirectory(sourcePath);
      continue;
    }

    await copyIntoDist(sourcePath);
  }
}

async function copyDirectory(directoryPath: string): Promise<void> {
  for (const entry of await readdir(directoryPath, { withFileTypes: true })) {
    const entryPath = join(directoryPath, entry.name);

    if (shouldSkipPath(entryPath)) {
      continue;
    }

    if (entry.isDirectory()) {
      await copyDirectory(entryPath);
      continue;
    }

    if (!entry.isFile() || !shouldCopyFile(entryPath)) {
      continue;
    }

    await copyIntoDist(entryPath);
  }
}

async function copyIntoDist(sourcePath: string): Promise<void> {
  const relativePath = relative(ROOT_DIR, sourcePath);
  const destinationPath = join(DIST_DIR, relativePath);

  await mkdir(dirname(destinationPath), { recursive: true });
  await copyFile(sourcePath, destinationPath);
}

function shouldSkipPath(filePath: string): boolean {
  if (filePath === DIST_DIR || filePath === scriptPath) {
    return true;
  }

  const relativePath = relative(ROOT_DIR, filePath);
  const segments = relativePath.split(/[\\/]/u);

  if (segments[0] === "dist") {
    return true;
  }

  if (segments[0] === "scripts" && relativePath !== "scripts/security-review-ci.ts") {
    return true;
  }

  if (segments.some((segment) => SKIP_SEGMENTS.has(segment))) {
    return true;
  }

  return SKIP_FILE_PATTERNS.some((pattern) => pattern.test(relativePath));
}

function shouldCopyFile(filePath: string): boolean {
  const relativePath = relative(ROOT_DIR, filePath);
  return /\.[cm]?[jt]sx?$/u.test(relativePath);
}

async function pathExists(targetPath: string): Promise<boolean> {
  try {
    await stat(targetPath);
    return true;
  } catch {
    return false;
  }
}

await buildPackage();
console.log("Built dist package:", relative(ROOT_DIR, DIST_DIR));
