# Release and Publish Safety

This package should publish through GitHub Actions with npm trusted publishing/OIDC. Do not create long-lived npm publish tokens for CI.

Publishing npm package, creating tags, pushing branches, or creating GitHub Releases requires maintainer approval.

## Maintainer Gates Before Release Tag

Before creating a release tag, maintainer must:

1. Verify public docs match current implementation.
2. Confirm command names, flags, tool names, and action inputs are accurate.
3. Confirm safety claims match defaults: no telemetry, no source edits, no default network writes.
4. Run local quality gates.
5. Run smoke test and CI artifact generation.
6. Verify npm pack dry-run output contains only intended files.
7. Run package audit.
8. Confirm dependency metadata and peer/runtime boundaries.
9. Confirm GitHub Actions workflows are ready for trusted publishing.
10. Confirm no secrets, reports, local cache, or reference materials leak into package.

## Release Checklist

Run before tag:

```bash
bun run check
bun run smoke:security-review
bun run security-review:ci -- --base HEAD --head HEAD
bun run prepublish:audit
bun run pack:dry-run
npm publish --dry-run --ignore-scripts
bun audit
npm view pi-security-review version
```

Expected `npm view` result before first publish: `E404 Not Found`.

Manual Pi smoke:

```bash
pi install .
/reload
/security-review-status
/security-review-config --create
/security-review
/security-review-panel
/security-review-comment --dry-run
```

If manual Pi smoke cannot complete, document blocker in release notes before tag.

## Public Docs to Verify

- `README.md`
- `docs/PRIVACY_SECURITY.md`
- `docs/CI_GITHUB_ACTIONS.md`
- `docs/PROMPT_CONTRACT.md`
- `docs/RELEASE.md`

Docs must accurately describe:

- Provider-neutral model behavior.
- Artifact-only CI not being final security result.
- External final report mode.
- GitHub comment approval gates.
- Prompt-injection limitations.
- Secret redaction and path filtering.
- Package contents.

## Required Package Contents

Published npm package should include:

```text
dist/                         Runtime source copied for Pi runtime
scripts/security-review-ci.ts CI entrypoint used by package/action consumers
action.yml                    Composite GitHub Action metadata
README.md                     Public documentation
LICENSE                       MIT license
package.json                  Package manifest and Pi metadata
docs/
  CI_GITHUB_ACTIONS.md
  PRIVACY_SECURITY.md
  PROMPT_CONTRACT.md
  RELEASE.md
```

The Pi manifest in `package.json` must point to runtime output:

```json
{
  "pi": {
    "extensions": ["./dist/index.ts"]
  }
}
```

## Forbidden Package Contents

`bun run prepublish:audit` must reject:

- `.pi/`
- `references/`
- `node_modules/`
- `test/`
- `tasks/`
- unapproved docs
- stale local reports/cache
- tarballs
- logs
- env files
- private keys
- certificates
- local DB/cache files
- generated artifacts outside whitelist

## Dependency Policy

Current package boundaries:

| Category     | Packages                                                               |
| ------------ | ---------------------------------------------------------------------- |
| Runtime deps | None expected for MVP                                                  |
| Dev deps     | `@biomejs/biome`, `@types/bun`, `typescript`                           |
| Peer deps    | `@earendil-works/pi-coding-agent`, `@earendil-works/pi-tui`, `typebox` |

Rules:

- Runtime dependencies should stay empty unless there is strong maintainer-approved reason.
- Pi packages and TypeBox stay peer dependencies supplied by Pi runtime.
- Dev-only dependencies must not move to runtime deps.
- No heavyweight Git/GitHub wrappers by default; runtime helpers use fixed argv arrays.
- Broad dependency upgrades require explicit maintainer approval.

## Build and Audit Steps

`bun run prepublish:audit` should:

1. Build `dist/`.
2. Verify copied runtime files match current source files.
3. Validate dependency metadata.
4. Run `npm pack --dry-run --ignore-scripts --json`.
5. Validate required files exist in pack output.
6. Reject forbidden files and directories.
7. Validate `module` and `pi.extensions` fields.

`bun run pack:dry-run` should also succeed and show no unexpected files.

## CI Workflows

Recommended CI workflow checks on PR/push:

1. Checkout with `fetch-depth: 0`.
2. Setup Bun.
3. `bun install --frozen-lockfile`.
4. `bun run typecheck`.
5. `bun run lint`.
6. `bun test ./test`.
7. `bun run build`.
8. `bun run smoke:security-review`.
9. `bun run security-review:ci -- --base HEAD --head HEAD`.
10. `bun run prepublish:audit`.
11. Upload dist/artifacts when useful.

Publish workflow should trigger only on tags matching `v*` and use npm trusted publishing/OIDC.

## Trusted Publisher Setup

Configure npm package trusted publisher:

- Publisher: GitHub Actions.
- Repository: `salmanabdurrahman/pi-security-review`.
- Workflow filename: `publish.yml`.
- Allowed action: `npm publish`.

Workflow requirements:

- Node version compatible with npm trusted publishing.
- `id-token: write` permission.
- `contents: read` permission.
- `npm publish --provenance`.
- No long-lived npm token.

## Tagging

After all checks pass and maintainer approves:

```bash
git tag v0.1.0
git push origin v0.1.0
```

Tag push should trigger publish workflow. Do not force-push release tags.

## Versioning

This package follows semver:

- Patch — bug fixes, docs updates, false-positive filter tuning, dependency updates, non-breaking internals.
- Minor — new commands/tools/config options/report formats/backward-compatible CI features.
- Major — breaking command/tool/config schema changes or default behavior changes that affect safety/contracts.

Security-sensitive default changes require explicit release-note callout.

## Release Notes Checklist

Release notes should mention:

- User-visible command/tool/action changes.
- Safety default changes.
- New CI behavior or permissions.
- Prompt contract changes.
- Known limitations and accepted risks.
- Verification commands run.
- Any skipped checks and why.

## Rollback / Deprecation Path

If bad package is published, prefer deprecating version instead of unpublishing once users may have installed it:

```bash
npm deprecate pi-security-review@0.1.0 "Deprecated: use newer fixed version"
```

Then publish patched version.

For unrecoverable issues such as leaked secrets in published tarball:

1. Immediately deprecate affected versions.
2. Contact npm support to unpublish if within allowed window and impact warrants it.
3. Rotate exposed tokens/secrets.
4. Remove leaked material from source/history as appropriate.
5. Publish fixed version and document impact.

## Final Pre-Tag Confirmation

Confirm:

- No telemetry.
- No default network write.
- No source edit/autofix behavior.
- Provider calls run through Pi active model/provider.
- Package stores no API keys/provider secrets/GitHub tokens.
- GitHub comment posting remains approval-gated.
- Artifact-only CI is clearly documented as not a final security result.
- Prompt-injection limitation is documented.
- SARIF export is valid SARIF 2.1.0 structure, not placeholder JSON.
- Packed tarball excludes `.pi/`, `references/`, env files, logs, tarballs, private keys, certs, stale reports, tests, tasks, and unapproved docs.
