import { mkdir, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { $ } from "bun";
import extension from "../index.ts";

if (typeof extension !== "function") {
  throw new Error(
    `pi-security-review extension export is not a function (actual: ${typeof extension}).`,
  );
}

const commands = new Set<string>();
const tools: string[] = [];
await extension({
  registerCommand(name: string) {
    commands.add(name);
  },
  on() {},
  registerTool(tool: { name?: string }) {
    if (tool?.name) tools.push(tool.name);
  },
});

for (const command of [
  "security-review",
  "security-review-status",
  "security-review-config",
  "security-review-panel",
  "security-review-comment",
  "security-review-ci-help",
]) {
  if (!commands.has(command)) throw new Error(`pi-security-review command missing: ${command}`);
}

const tempRoot = await mkdtemp(join(tmpdir(), "pi-sr-pack-smoke-"));
try {
  await $`bun run build`.quiet();
  const packJson = await $`npm pack --ignore-scripts --json`.text();
  const [pack] = JSON.parse(packJson) as Array<{
    filename?: string;
    files?: Array<{ path: string }>;
  }>;
  if (!pack?.filename) throw new Error("npm pack returned no tarball filename.");
  const files = new Set(pack.files?.map((file) => file.path) ?? []);
  for (const required of ["dist/index.ts", "package.json", "README.md", "LICENSE"]) {
    if (!files.has(required)) throw new Error(`packed package missing required file: ${required}`);
  }

  const installRoot = join(tempRoot, "install");
  await mkdir(installRoot, { recursive: true });
  await $`tar -xzf ${pack.filename} -C ${installRoot}`.quiet();
  const packed = await import(join(installRoot, "package", "dist", "index.ts"));
  if (typeof packed.default !== "function") {
    throw new Error(
      `packed extension export is not a function (actual: ${typeof packed.default}).`,
    );
  }
  await rm(pack.filename, { force: true });
} finally {
  await rm(tempRoot, { recursive: true, force: true });
}

console.log(`pi-security-review smoke passed (${commands.size} commands, ${tools.length} tools)`);
