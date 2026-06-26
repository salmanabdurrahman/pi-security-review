# pi-security-review

High-signal security review package for Pi. It builds bounded security-review context from local Git diffs, queues a provider-neutral prompt through Pi's active model/provider, captures structured findings, applies deterministic false-positive filters, and can optionally publish gated GitHub PR comments.

The package is local-first, telemetry-free, and designed for interactive Pi review plus headless CI artifact/final-report workflows.

## Table of Contents

- [Overview](#overview)
- [Package Boundary](#package-boundary)
- [Core Capabilities](#core-capabilities)
- [Command Surface](#command-surface)
- [LLM Tools](#llm-tools)
- [Documentation Map](#documentation-map)
- [Tech Stack](#tech-stack)
- [Getting Started](#getting-started)
- [Configuration](#configuration)
- [Review Workflow](#review-workflow)
- [Custom Instructions](#custom-instructions)
- [Reports](#reports)
- [CI/CD](#cicd)
- [Privacy And Security](#privacy-and-security)
- [Development Workflow](#development-workflow)
- [Testing And Verification](#testing-and-verification)
- [Project Structure](#project-structure)
- [Publishing Notes](#publishing-notes)
- [Contribution Guide](#contribution-guide)

## Overview

`pi-security-review` helps Pi focus security review on changed code instead of reading an entire repository. It resolves local, staged, branch, or explicit diff scopes; filters out generated/vendor/secret-like paths; builds a bounded prompt; asks the active Pi model for HIGH/MEDIUM findings only; then stores normalized Markdown and JSON reports under `.pi/security-review/`.

This repository is responsible for:

- Pi extension entrypoint and package manifest.
- Repo-local config schema, defaults, validation, and creation.
- Git repo discovery, working-tree status, GitHub remote detection, and safe diff scope resolution.
- Security prompt generation with explicit exploit-path and no-secret-echo rules.
- Optional custom scan/filter instructions from bounded repo-relative files or inline text.
- Marker parser, normalized finding model, deterministic false-positive filters, Markdown report rendering, and valid SARIF 2.1.0 export.
- Latest report capture via Pi `message_end` hook and report panel replay.
- GitHub PR comment preview/post integration with explicit approval gates and safe marker updates.
- Headless CI context generation, external final report ingestion, fail gates, composite GitHub Action, and CI docs.
- Bounded LLM helper tools for status, diff analysis, context building, filtering, rendering, and GitHub comment preview/post.

## Package Boundary

The package owns security-review context generation and report handling. It does not own model provider credentials, vulnerability remediation, deployment policy, or general SAST replacement.

| Area             | Responsibility                                                                  |
| ---------------- | ------------------------------------------------------------------------------- |
| Pi extension     | Commands, tools, prompt queueing, status UI, latest-report panel                |
| Review core      | Diff scope, context bounds, prompt contract, marker parser, report renderer     |
| Filtering        | Deterministic confidence/severity thresholds and hard false-positive exclusions |
| Integrations     | Optional code-review-graph context, GitHub PR comments, CI artifacts            |
| Safety           | No telemetry, no source edits, no default network writes, secret redaction      |
| Release workflow | Build output, package audit, npm pack dry-run, public docs                      |

## Core Capabilities

| Capability                      | Status                                                                         |
| ------------------------------- | ------------------------------------------------------------------------------ |
| Repo status                     | Implemented through `/security-review-status`                                  |
| Config creation                 | Implemented through `/security-review-config --create`                         |
| Diff scope review               | Implemented through `/security-review` with current, branch, and explicit refs |
| Model override                  | Implemented with `--model provider/model` when Pi host exposes model registry  |
| Custom scan/filter instructions | Implemented through safe file flags and inline text flags                      |
| Report capture                  | Implemented through structured marker parsing on assistant response end        |
| Latest report panel             | Implemented through `/security-review-panel`                                   |
| Deterministic filters           | Implemented for confidence, severity, and known low-signal finding classes     |
| SARIF rendering                 | Implemented through `security_review_render_report` with `format: "sarif"`     |
| GitHub PR comments              | Dry-run default; posting requires explicit approval                            |
| Inline PR comments              | Best-effort, validated against changed PR lines; falls back to summary         |
| CI artifact mode                | Implemented; no model call and no GitHub write by default                      |
| External final report mode      | Implemented with fail gates for HIGH/MEDIUM findings                           |
| Composite GitHub Action         | Implemented through root `action.yml`                                          |

## Command Surface

```text
/security-review-status
/security-review-config [--create]
/security-review [--base <ref>] [--head <ref>] [--from <ref>] [--to <ref>] [--model <provider/model>] [--scan-instructions-file <path>] [--filter-instructions-file <path>] [--scan-instructions-text <text>] [--filter-instructions-text <text>] [focus paths...]
/security-review-panel
/security-review-comment [--dry-run] [--pr <number>] [--yes] [--update-existing] [--inline]
/security-review-ci-help
```

### Command details

**`/security-review-status`** — Show repo root, config status, latest report, active model, configured model profiles, GitHub remote, best-effort `gh` auth status, and default network-write stance. Does not crash outside a Git repo.

**`/security-review-config`** — Show repo-local config state. Add `--create` to write `.pi/security-review.json` with defaults when missing.

**`/security-review`** — Build bounded context for current or explicit diff scope and queue a security prompt through Pi. The prompt asks for concrete HIGH/MEDIUM vulnerabilities introduced or exposed by the supplied changes only.

Examples:

```text
/security-review
/security-review --base origin/main --head HEAD
/security-review --from v0.1.0 --to HEAD src/auth src/api
/security-review --model openai/gpt-5.1-codex
/security-review --scan-instructions-file .github/security-scan.txt
```

**`/security-review-panel`** — Open `.pi/security-review/latest-report.md` in the editor when available, or show notification text fallback. Malformed report JSON warnings are surfaced instead of crashing.

**`/security-review-comment`** — Preview latest report as GitHub PR comment by default. Posting requires `--yes`. Existing marker comments can be updated with `--update-existing`; optional `--inline` comments only on validated changed PR lines and falls back to summary when mapping fails.

```text
/security-review-comment --dry-run --pr 123
/security-review-comment --pr 123 --yes --update-existing
/security-review-comment --pr 123 --yes --inline
```

**`/security-review-ci-help`** — Print short CI guidance.

## LLM Tools

```text
security_review_stats
security_review_analyze_diff
security_review_build_context
security_review_model_profiles
security_review_filter_findings
security_review_render_report
security_review_github_comment
```

Tool outputs are bounded to Pi-style limits before reaching the model: 50 KB or 2,000 lines.

| Tool                              | Purpose                                                |
| --------------------------------- | ------------------------------------------------------ |
| `security_review_stats`           | Show repo/config/latest-report/model/GitHub status     |
| `security_review_analyze_diff`    | Resolve review scope and return bounded diff metadata  |
| `security_review_build_context`   | Build provider-neutral security-review context payload |
| `security_review_model_profiles`  | Inspect configured role/model metadata                 |
| `security_review_filter_findings` | Normalize and deterministically filter model findings  |
| `security_review_render_report`   | Render Markdown, JSON, or valid SARIF 2.1.0 JSON       |
| `security_review_github_comment`  | Preview or post gated GitHub PR comments               |

Mutating tool behavior is safe by default. `security_review_github_comment` previews unless `post: true` and `approve: true` are both set.

## Documentation Map

Use this reading order for review, CI setup, or release handoff:

1. `docs/PRIVACY_SECURITY.md` — local-first behavior, model boundaries, secret handling, GitHub writes, and prompt-injection warning.
2. `docs/PROMPT_CONTRACT.md` — review scope, required finding shape, JSON marker, parser compatibility, and rendering contract.
3. `docs/CI_GITHUB_ACTIONS.md` — artifact-only CI, external final report mode, composite action usage, PR comments, and fork safety.
4. `docs/RELEASE.md` — maintainer gates, package contents, trusted publishing, rollback path, and release checklist.

## Tech Stack

| Area                | Choice                                                                     |
| ------------------- | -------------------------------------------------------------------------- |
| Runtime target      | Pi extension runtime through TypeScript loader                             |
| Development runtime | Bun                                                                        |
| Language            | TypeScript                                                                 |
| Formatter/linter    | Biome                                                                      |
| Schema validation   | TypeBox for tool parameter schemas; local config validator for repo config |
| Test runner         | `bun test`                                                                 |
| GitHub integration  | `gh` CLI/GitHub token at runtime for approved comments                     |
| Publish target      | npm package with Pi manifest and composite GitHub Action metadata          |

## Getting Started

Install published package:

```bash
pi install npm:pi-security-review
/reload
/security-review-status
```

Run first local review:

```text
/security-review-config --create
/security-review
/security-review-panel
/security-review-comment --dry-run
```

Local package smoke:

```bash
bun install
bun run build
pi install .
/reload
/security-review-status
/security-review-config --create
/security-review
```

Direct extension smoke when testing built output without package install:

```bash
pi install ./dist/index.ts
/reload
```

Repo-local files created or used by package:

```text
.pi/security-review.json
.pi/security-review/latest-report.md
.pi/security-review/latest-report.json
.pi/security-review/ci-context.json
.pi/security-review/ci-report.md
```

## Configuration

Default config path:

```text
.pi/security-review.json
```

Create it with `/security-review-config --create`.

Key options:

| Option                                 | Purpose                                                                  |
| -------------------------------------- | ------------------------------------------------------------------------ |
| `enabled`                              | Enable or disable package for repo                                       |
| `include` / `exclude`                  | Control eligible paths                                                   |
| `excludeDocumentation`                 | Exclude docs by default to reduce low-signal findings                    |
| `excludeTestsByDefault`                | Exclude tests by default unless explicitly focused                       |
| `maxDiffBytes`                         | Bound captured diff text                                                 |
| `maxContextChars`                      | Bound prompt/context size                                                |
| `maxFiles`                             | Bound file count                                                         |
| `maxCommits`                           | Bound commit metadata                                                    |
| `confidenceThreshold`                  | Drop findings below confidence threshold, default `0.8`                  |
| `severityThreshold`                    | Keep `medium`+ or `high` only                                            |
| `enableHardExclusions`                 | Enable deterministic false-positive classes                              |
| `enableModelFiltering`                 | Reserved for model-backed filter runner; deterministic filters still run |
| `modelProfiles`                        | Role metadata for default/auditor/filter/reporter                        |
| `agentPipeline`                        | Active role pipeline metadata, default `auditor`                         |
| `customSecurityScanInstructions`       | Optional repo policy text in config                                      |
| `falsePositiveFilteringInstructions`   | Optional filter policy text in config                                    |
| `github.commentByDefault`              | Safe default remains false                                               |
| `github.updateExistingComment`         | Update marker comment when approved                                      |
| `github.commentMarker`                 | PR comment marker, default `<!-- pi-security-review -->`                 |
| `ci.failOnHigh` / `ci.failOnMedium`    | CI policy defaults; CLI flags can gate final report                      |
| `optionalIntegrations.codeReviewGraph` | Include best-effort CRG context when available                           |

Minimal example:

```json
{
  "enabled": true,
  "severityThreshold": "medium",
  "confidenceThreshold": 0.8,
  "github": {
    "commentByDefault": false,
    "updateExistingComment": true,
    "commentMarker": "<!-- pi-security-review -->"
  }
}
```

## Review Workflow

1. Resolve Git repo and config.
2. Resolve diff scope from explicit refs/paths or current working tree.
3. Apply include/exclude and secret-like path filters.
4. Build bounded context with truncation warnings when needed.
5. Add optional custom scan/filter instructions.
6. Add optional code-review-graph context when available.
7. Queue provider-neutral prompt through Pi active model/provider.
8. Capture assistant output marker on `message_end`.
9. Normalize, redact, and deterministically filter findings.
10. Write latest Markdown and JSON reports under `.pi/security-review/`.
11. Optionally preview/post GitHub PR comment after explicit approval.

## Custom Instructions

File mode is preferred for durable organization policy:

```text
/security-review --scan-instructions-file .github/security-scan.txt --filter-instructions-file .github/security-filter.txt
```

Inline mode is useful for one-off review focus:

```text
/security-review --scan-instructions-text "Check tenant boundary bypasses"
```

Instruction file safeguards:

- Repo-relative paths only.
- 64 KiB max file size.
- Absolute paths and `..` traversal refused.
- Secret-like paths refused, including `.env`, token/credential/private-key names, and key/cert files.
- Custom scan instructions extend default security categories.
- Custom filter instructions tune false-positive criteria but do not disable deterministic hard filters.

Legacy aliases `--scan-instructions` and `--filter-instructions` still work as inline text with warnings.

## Reports

Preferred assistant output ends with one marker block:

```markdown
<!-- pi-security-review-json -->

{
"findings": [],
"excludedFindings": [],
"analysisSummary": {
"filesReviewed": 0,
"highSeverity": 0,
"mediumSeverity": 0,
"lowSeverity": 0,
"reviewCompleted": true,
"diffTruncated": false,
"contextTruncated": false
}
}

<!-- /pi-security-review-json -->
```

Parser also best-effort accepts raw JSON, fenced JSON, whitespace marker variants, and reference-style snake_case fields such as `exploit_scenario`, `analysis_summary`, and `files_reviewed`.

Stored outputs:

```text
.pi/security-review/latest-report.md
.pi/security-review/latest-report.json
```

Report handling safeguards:

- Malformed/incomplete output records actionable warnings instead of crashing.
- Common secret-like values are redacted before local write or GitHub comment rendering.
- Deterministic filters run after capture and before report storage/rendering.
- Filtering metadata records kept/excluded counts and stages.
- Model-side filter role is currently deferred unless implemented by a runner.

## CI/CD

Artifact-only mode builds bounded context plus prompt. It does not call a model and is not a final security result:

```bash
bun run security-review:ci -- --base origin/main --head HEAD
```

External final report mode reads model-produced marker output and applies fail gates:

```bash
bun run security-review:ci -- \
  --base origin/main \
  --head HEAD \
  --final-report artifacts/final-security-report.md \
  --fail-on-high \
  --fail-on-medium
```

PR comment mode requires final report and explicit approval:

```bash
bun run security-review:ci -- \
  --base origin/main \
  --head HEAD \
  --final-report artifacts/final-security-report.md \
  --pr 123 \
  --comment \
  --yes
```

Composite action default is artifact-only and has no vendor API key input:

```yaml
- uses: owner/pi-security-review@v0.1.0
  with:
    base: origin/${{ github.base_ref }}
    head: HEAD
```

See `docs/CI_GITHUB_ACTIONS.md` for full workflow templates, permissions, final report mode, comments, and fork safety.

## Privacy And Security

`pi-security-review` is local-first.

- No telemetry.
- No source edits or autofix behavior.
- No GitHub comments or network writes by default.
- No provider API keys stored by this package.
- Runtime helpers use fixed argv arrays, not shell interpolation.
- Secret-like paths and values are filtered/redacted before storage or comments.
- Reports/config live under `.pi/` and are excluded from package output.
- Model prompts are sent only through Pi's active provider/model lifecycle after user runs review.
- AI review is not hardened against prompt injection from changed code/docs/comments/custom instructions.

Use artifact-only mode for untrusted forks. Require maintainer approval before model-backed review or write-permission workflows on external contributions. See `docs/PRIVACY_SECURITY.md`.

## Development Workflow

Install dependencies:

```bash
bun install
```

Run local checks:

```bash
bun run check
```

Build package output:

```bash
bun run build
```

Run npm package dry-run:

```bash
bun run pack:dry-run
```

Run package audit before publish:

```bash
bun run prepublish:audit
```

## Testing And Verification

Fast verification before handoff:

```bash
bun run typecheck
bun run lint
bun test ./test
bun run build
bun run smoke:security-review
bun run pack:dry-run
```

Release verification should also include:

```bash
bun run security-review:ci -- --base HEAD --head HEAD
bun run prepublish:audit
pi install .
/reload
/security-review-status
/security-review-config --create
/security-review
/security-review-panel
/security-review-comment --dry-run
```

## Project Structure

```text
.
|-- action.yml
|-- docs/
|   |-- CI_GITHUB_ACTIONS.md
|   |-- PRIVACY_SECURITY.md
|   |-- PROMPT_CONTRACT.md
|   `-- RELEASE.md
|-- scripts/
|   |-- audit-npm-package.ts
|   |-- build-package.ts
|   |-- security-review-ci.ts
|   `-- smoke-security-review.ts
|-- src/
|   |-- config/
|   |-- git/
|   |-- github/
|   |-- security/
|   |-- store/
|   |-- tools/
|   |-- util/
|   `-- extension.ts
|-- test/
|-- index.ts
|-- package.json
`-- README.md
```

## Publishing Notes

Publish path:

1. Complete maintainer release checklist in `docs/RELEASE.md`.
2. Run `bun run check`.
3. Run `bun run smoke:security-review`.
4. Run `bun run security-review:ci -- --base HEAD --head HEAD`.
5. Run `bun run prepublish:audit`.
6. Run `bun run pack:dry-run`.
7. Create and push release tag only after maintainer approval.
8. Let GitHub Actions publish through npm trusted publishing/OIDC when configured.

The Pi manifest is declared in `package.json`:

```json
{
  "pi": {
    "extensions": ["./dist/index.ts"]
  }
}
```

The npm package whitelist includes runtime `dist`, `scripts/security-review-ci.ts`, `action.yml`, selected public docs, README, license, and package metadata.

## Contribution Guide

Before changing behavior:

- Keep changes small and tied to one security-review capability.
- Add or update tests for behavior changes.
- Keep docs aligned with actual command/tool flags and default safety behavior.
- Preserve no-telemetry, no-default-network-write, and no-source-edit guarantees.
- Do not weaken secret/path filtering or prompt-injection warnings.
- Run relevant verification before handoff and document skipped checks.
