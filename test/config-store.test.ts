import { expect, test } from "bun:test";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { ensureDefaultConfig, getConfigPath, loadConfig } from "../src/config/load.ts";
import { DEFAULT_CONFIG, validateAndMergeConfig } from "../src/config/schema.ts";
import {
  getLatestJsonPath,
  getLatestMarkdownPath,
  readLatestJson,
  readLatestMarkdown,
  writeLatestJson,
  writeLatestMarkdown,
} from "../src/store/reportStore.ts";

test("default config validates and can be created", async () => {
  const repo = await mkdtemp(join(tmpdir(), "pi-sr-config-"));
  try {
    const created = await ensureDefaultConfig(repo);
    expect(created.created).toBe(true);
    expect(created.path).toBe(getConfigPath(repo));
    expect(created.config).toEqual(DEFAULT_CONFIG);

    const loaded = await loadConfig(repo);
    expect(loaded.exists).toBe(true);
    expect(loaded.config.enabled).toBe(true);
    expect(loaded.config.agentPipeline).toEqual(["auditor"]);
  } finally {
    await rm(repo, { recursive: true, force: true });
  }
});

test("partial config merges defaults", () => {
  const config = validateAndMergeConfig(
    { enabled: false, confidenceThreshold: 0.9, github: { commentByDefault: true } },
    ".pi/security-review.json",
  );

  expect(config.enabled).toBe(false);
  expect(config.confidenceThreshold).toBe(0.9);
  expect(config.github.commentByDefault).toBe(true);
  expect(config.github.commentMarker).toBe("<!-- pi-security-review -->");
  expect(config.modelProfiles.auditor?.thinkingLevel).toBe("high");
});

test("invalid config error includes path and field", () => {
  expect(() => validateAndMergeConfig({ maxFiles: 0 }, "/repo/.pi/security-review.json")).toThrow(
    "/repo/.pi/security-review.json:maxFiles",
  );
});

test("report store reads and writes latest markdown and json", async () => {
  const repo = await mkdtemp(join(tmpdir(), "pi-sr-store-"));
  try {
    expect(await readLatestMarkdown(repo)).toBeUndefined();
    expect(await readLatestJson(repo)).toBeUndefined();

    await writeLatestMarkdown(repo, "# Security Review\n");
    await writeLatestJson(repo, { version: 1, findings: [] });

    expect(await readFile(getLatestMarkdownPath(repo), "utf8")).toBe("# Security Review\n");
    expect(await readLatestMarkdown(repo)).toBe("# Security Review\n");
    expect(await readLatestJson(repo)).toEqual({ version: 1, findings: [] });
    expect(getLatestJsonPath(repo)).toEndWith(".pi/security-review/latest-report.json");
  } finally {
    await rm(repo, { recursive: true, force: true });
  }
});

test("report store refuses secret-like fields", async () => {
  const repo = await mkdtemp(join(tmpdir(), "pi-sr-secret-"));
  try {
    await expect(writeLatestJson(repo, { token: "nope" })).rejects.toThrow("secret-like");
  } finally {
    await rm(repo, { recursive: true, force: true });
  }
});

test("report store redacts secret-like values before writing", async () => {
  const repo = await mkdtemp(join(tmpdir(), "pi-sr-redact-"));
  try {
    await writeLatestMarkdown(
      repo,
      "# Security Review\n\nBearer ghp_abcdefghijklmnopqrstuvwxyz123456 leaked\n",
    );
    await writeLatestJson(repo, {
      version: 1,
      findings: [
        {
          description: "Authorization header contains Bearer abcdefghijklmnopqrstuvwxyz123456",
          recommendation: "Rotate AWS key AKIAABCDEFGHIJKLMNOP.",
        },
      ],
    });

    expect(await readFile(getLatestMarkdownPath(repo), "utf8")).toContain("[REDACTED_SECRET]");
    const rawJson = await readFile(getLatestJsonPath(repo), "utf8");
    expect(rawJson).toContain("[REDACTED_SECRET]");
    expect(rawJson).not.toContain("AKIAABCDEFGHIJKLMNOP");
  } finally {
    await rm(repo, { recursive: true, force: true });
  }
});

test("malformed latest json reports clear path", async () => {
  const repo = await mkdtemp(join(tmpdir(), "pi-sr-bad-json-"));
  try {
    await writeLatestMarkdown(repo, "# Security Review\n");
    await writeFile(getLatestJsonPath(repo), "{", "utf8");
    await expect(readLatestJson(repo)).rejects.toThrow(getLatestJsonPath(repo));
  } finally {
    await rm(repo, { recursive: true, force: true });
  }
});
