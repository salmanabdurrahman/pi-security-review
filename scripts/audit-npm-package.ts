/**
 * Pre-publish guard for npm package contents and dependency metadata.
 */

import { readdir, readFile, stat } from "node:fs/promises";
import { join, relative } from "node:path";
import { $ } from "bun";

interface PackEntry {
  files?: Array<{ path: string }>;
}

interface PackageJson {
  module?: string;
  files?: string[];
  scripts?: Record<string, string>;
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  peerDependencies?: Record<string, string>;
  pi?: { extensions?: string[] };
}

const REQUIRED_PEER_DEPENDENCIES = new Set([
  "@earendil-works/pi-coding-agent",
  "@earendil-works/pi-tui",
  "typebox",
]);
const PUBLIC_DOCS = new Set([
  "docs/PRIVACY_SECURITY.md",
  "docs/CI_GITHUB_ACTIONS.md",
  "docs/PROMPT_CONTRACT.md",
  "docs/RELEASE.md",
]);
const FORBIDDEN_PACK_PATTERNS = [
  /^\.pi\//u,
  /^scripts\/(?!security-review-ci\.ts$)/u,
  /^test\//u,
  /^tasks\//u,
  /^node_modules\//u,
  /^coverage\//u,
  /^\.cache\//u,
  /^docs\/(?!PRIVACY_SECURITY\.md$|CI_GITHUB_ACTIONS\.md$|PROMPT_CONTRACT\.md$|RELEASE\.md$)/u,
  /(^|\/)\.env/u,
  /(^|\/)auth\.json$/u,
  /(^|\/)trust\.json$/u,
  /(^|\/)security-review\//u,
  /(^|\/)latest-report\.(?:json|md)$/u,
  /(^|\/)ci-(?:context|report)\.(?:json|md)$/u,
  /private[-_]?key/iu,
  /\.pem$/iu,
  /\.key$/iu,
  /\.crt$/iu,
  /\.cer$/iu,
  /\.cert$/iu,
  /\.p12$/iu,
  /\.pfx$/iu,
  /\.db(?:-|$|\.)/u,
  /\.sqlite(?:3)?(?:-|$|\.)/u,
  /\.log$/u,
  /\.tgz$/u,
  /\.tar(?:\.gz)?$/u,
];

await $`bun run build`;
await validateDistFreshness();

const packageJson = JSON.parse(await readFile("package.json", "utf8")) as PackageJson;
validateDependencyMetadata(packageJson);

const dryRun = await $`npm pack --dry-run --ignore-scripts --json`.text();
const [pack] = JSON.parse(dryRun) as PackEntry[];
if (!pack) {
  throw new Error("npm pack dry-run returned no package metadata.");
}
const files = pack.files?.map((file) => file.path).sort() ?? [];

if (files.length === 0) {
  throw new Error("npm pack dry-run returned no files.");
}

for (const path of files) {
  if (FORBIDDEN_PACK_PATTERNS.some((pattern) => pattern.test(path))) {
    throw new Error(`Forbidden file in npm pack dry-run: ${path}`);
  }
}

for (const required of [
  "package.json",
  "README.md",
  "LICENSE",
  "action.yml",
  "dist/index.ts",
  "scripts/security-review-ci.ts",
  ...PUBLIC_DOCS,
]) {
  if (!files.includes(required)) {
    throw new Error(`Required file missing from npm pack dry-run: ${required}`);
  }
}

if (packageJson.module !== "./dist/index.ts") {
  throw new Error("package.json module must resolve to packaged ./dist/index.ts.");
}

const ciScript = packageJson.scripts?.["security-review:ci"];
if (ciScript !== "bun scripts/security-review-ci.ts") {
  throw new Error("package.json security-review:ci must point to packaged source script.");
}

const filesWhitelist = packageJson.files ?? [];
if (!filesWhitelist.includes("action.yml")) {
  throw new Error("action.yml missing from package.json files whitelist.");
}

for (const publicDoc of PUBLIC_DOCS) {
  if (!filesWhitelist.includes(publicDoc)) {
    throw new Error(`Public doc missing from package.json files whitelist: ${publicDoc}`);
  }
}

console.log(`npm package audit passed: ${files.length} files`);

async function validateDistFreshness(): Promise<void> {
  const runtimeFiles = [
    "index.ts",
    ...(await collectFiles("src")),
    "scripts/security-review-ci.ts",
  ];
  for (const sourcePath of runtimeFiles.sort()) {
    const distPath = join("dist", sourcePath);
    const [source, built] = await Promise.all([
      readFile(sourcePath, "utf8"),
      readFile(distPath, "utf8").catch(() => undefined),
    ]);
    if (built === undefined) throw new Error(`Build output missing runtime file: ${distPath}`);
    if (built !== source) throw new Error(`Build output stale or mismatched: ${distPath}`);
  }

  const distFiles = await collectFiles("dist");
  for (const distPath of distFiles) {
    const sourcePath = relative("dist", distPath);
    if (!runtimeFiles.includes(sourcePath)) {
      throw new Error(`Unexpected runtime file in dist: ${distPath}`);
    }
  }
}

async function collectFiles(root: string): Promise<string[]> {
  const rootStat = await stat(root).catch(() => undefined);
  if (!rootStat) return [];
  if (rootStat.isFile()) return [root];

  const files: string[] = [];
  for (const entry of await readdir(root, { withFileTypes: true })) {
    const path = join(root, entry.name);
    if (entry.isDirectory()) {
      files.push(...(await collectFiles(path)));
      continue;
    }
    if (entry.isFile()) files.push(path);
  }
  return files;
}

function validateDependencyMetadata(packageJson: PackageJson): void {
  const runtimeDeps = new Set(Object.keys(packageJson.dependencies ?? {}));
  const devDeps = new Set(Object.keys(packageJson.devDependencies ?? {}));
  const peerDeps = new Set(Object.keys(packageJson.peerDependencies ?? {}));

  if (runtimeDeps.size > 0) {
    throw new Error(
      `Runtime dependencies should be empty for MVP, found: ${[...runtimeDeps].join(", ")}`,
    );
  }

  for (const dependency of REQUIRED_PEER_DEPENDENCIES) {
    if (!peerDeps.has(dependency)) {
      throw new Error(`Missing peer dependency: ${dependency}`);
    }
  }

  for (const dependency of ["@biomejs/biome", "@types/bun", "typescript"]) {
    if (runtimeDeps.has(dependency)) {
      throw new Error(`Dev-only dependency listed as runtime dependency: ${dependency}`);
    }
    if (!devDeps.has(dependency)) {
      console.warn(`Warning: expected dev dependency not found: ${dependency}`);
    }
  }

  const extensions = packageJson.pi?.extensions ?? [];
  if (!extensions.includes("./dist/index.ts")) {
    throw new Error("package.json pi.extensions must include ./dist/index.ts.");
  }
}
