# CI / GitHub Actions

`pi-security-review` provides two CI surfaces:

- Bundled script: `scripts/security-review-ci.ts` via `bun run security-review:ci`.
- Composite GitHub Action: root `action.yml`.

Both are artifact-only by default. They do not call a model, do not post GitHub comments, and do not require vendor API keys unless an external trusted step runs the generated prompt.

## Modes

| Mode                  | What happens                                              | Model call         | GitHub write  | Security-result status |
| --------------------- | --------------------------------------------------------- | ------------------ | ------------- | ---------------------- |
| Artifact-only         | Build bounded context + prompt artifacts                  | No                 | No            | Not final              |
| External final report | Read model-produced marker from file and normalize report | External step only | No by default | Final report input     |
| PR comment            | Post/update PR comment from final report                  | External step only | Yes, explicit | Final report input     |

Do not treat artifact-only zero findings as proof that no vulnerabilities exist.

## Quick Start: Artifact-Only

Use this on pull requests, including untrusted forks. Needs only `contents: read`.

```yaml
name: Security Review Context

on:
  pull_request:

permissions:
  contents: read

jobs:
  security-review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: oven-sh/setup-bun@v2
      - run: bun install --frozen-lockfile
      - run: |
          bun run security-review:ci -- \
            --base origin/${{ github.base_ref }} \
            --head HEAD \
            --output artifacts/security-context.json \
            --markdown artifacts/security-report.md
      - uses: actions/upload-artifact@v4
        with:
          name: pi-security-review
          path: artifacts/
```

The examples use floating major tags for readability (`actions/checkout@v4`, `oven-sh/setup-bun@v2`, `actions/upload-artifact@v4`). For high-trust/release workflows, pin third-party actions to reviewed commit SHAs and rotate intentionally.

## Script Flags

| Flag                       | Description                                                                    |
| -------------------------- | ------------------------------------------------------------------------------ |
| `--base <ref>`             | Base ref for Git diff                                                          |
| `--head <ref>`             | Head ref for Git diff                                                          |
| `--output <path>`          | JSON artifact path, default `.pi/security-review/ci-context.json`              |
| `--markdown <path>`        | Markdown artifact path, default `.pi/security-review/ci-report.md`             |
| `--pr <number>`            | Pull request number for optional comment                                       |
| `--comment`                | Post PR comment; requires `--yes`, `--pr`, and final report unless override    |
| `--yes` / `-y`             | Explicit approval for GitHub comment mutation                                  |
| `--model <provider/model>` | Record intended Pi model metadata in context/prompt                            |
| `--final-report <path>`    | Read model-produced Markdown/JSON marker as final report                       |
| `--allow-artifact-comment` | Maintainer override to comment artifact-only context; avoid for normal results |
| `--fail-on-high`           | Exit non-zero when final report contains HIGH findings                         |
| `--fail-on-medium`         | Exit non-zero when final report contains MEDIUM or HIGH findings               |
| `--ci-help`                | Show help                                                                      |

## Outputs

Default artifact paths:

```text
.pi/security-review/ci-context.json
.pi/security-review/ci-report.md
.pi/security-review/latest-report.md
.pi/security-review/latest-report.json
```

Custom artifact paths:

```bash
bun run security-review:ci -- \
  --base origin/main \
  --head HEAD \
  --output artifacts/security-context.json \
  --markdown artifacts/security-report.md
```

`ci-context.json` contains:

- `mode`
- bounded context payload
- provider-neutral prompt text
- report envelope or final report payload

`ci-report.md` contains rendered Markdown plus JSON marker.

## External Final Report Mode

Use this when a trusted model runner executes the generated prompt and saves the assistant output containing `<!-- pi-security-review-json -->`.

```bash
bun run security-review:ci -- \
  --base origin/main \
  --head HEAD \
  --output artifacts/security-context.json \
  --markdown artifacts/security-context.md

# Trusted runner writes artifacts/final-security-report.md

bun run security-review:ci -- \
  --base origin/main \
  --head HEAD \
  --final-report artifacts/final-security-report.md \
  --output artifacts/security-final.json \
  --markdown artifacts/security-final.md \
  --fail-on-high \
  --fail-on-medium
```

Fail gates apply only to the final model report. They do not treat artifact-only zero findings as success evidence.

## PR Comment Mode

PR comments are off by default. Posting requires:

- `--comment`
- `--yes`
- `--pr <number>`
- `--final-report <path>` unless maintainer passes `--allow-artifact-comment`
- Authenticated `gh` or `GH_TOKEN`/`GITHUB_TOKEN`
- `pull-requests: write` permission

```yaml
permissions:
  contents: read
  pull-requests: write

steps:
  - uses: actions/checkout@v4
    with:
      fetch-depth: 0
  - uses: oven-sh/setup-bun@v2
  - run: bun install --frozen-lockfile
  - run: |
      bun run security-review:ci -- \
        --base origin/${{ github.base_ref }} \
        --head HEAD \
        --final-report artifacts/final-security-report.md \
        --pr ${{ github.event.pull_request.number }} \
        --comment \
        --yes
    env:
      GH_TOKEN: ${{ github.token }}
```

Comment behavior:

- Uses `<!-- pi-security-review -->` marker by default.
- Can update existing marker comment.
- Never deletes comments.
- Redacts common secret-like values before posting.

## Composite Action: Artifact-Only

The root `action.yml` wraps the same CI script. Default mode records prompt/context artifacts and exposes summary outputs. It has no Anthropic/OpenAI/vendor API key input.

```yaml
name: Pi Security Review

on:
  pull_request:

permissions:
  contents: read

jobs:
  security-review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: owner/pi-security-review@v0.1.0
        with:
          base: origin/${{ github.base_ref }}
          head: HEAD
          output: artifacts/security-context.json
          markdown: artifacts/security-report.md
      - uses: actions/upload-artifact@v4
        with:
          name: pi-security-review
          path: artifacts/
```

Action outputs:

| Output           | Description                                  |
| ---------------- | -------------------------------------------- |
| `findings-count` | Kept findings count in artifact/final report |
| `high-count`     | HIGH findings count                          |
| `medium-count`   | MEDIUM findings count                        |
| `mode`           | `artifact-only` or `external-final-report`   |
| `results-file`   | JSON artifact path                           |
| `markdown-file`  | Markdown artifact path                       |

## Composite Action: Final Report Gate

```yaml
permissions:
  contents: read

jobs:
  security-review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: owner/pi-security-review@v0.1.0
        with:
          base: origin/${{ github.base_ref }}
          head: HEAD
          final-report: artifacts/final-security-report.md
          output: artifacts/security-final.json
          markdown: artifacts/security-final.md
          fail-on-high: "true"
          fail-on-medium: "true"
```

Ensure `artifacts/final-security-report.md` is produced by a trusted prior step before the action runs.

## Composite Action: PR Comment

```yaml
permissions:
  contents: read
  pull-requests: write

jobs:
  security-review-comment:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - uses: owner/pi-security-review@v0.1.0
        with:
          base: origin/${{ github.base_ref }}
          head: HEAD
          final-report: artifacts/final-security-report.md
          comment: "true"
          pr: ${{ github.event.pull_request.number }}
          yes: "true"
```

## Run-Once / Cache Design

Artifact-only mode intentionally does not use run-once cache because it does not call a model and should stay deterministic for every CI run.

For model-backed external runners, add a repository-owned cache/marker around the trusted model step, keyed by:

- repository
- PR number
- head SHA
- prompt/context hash

Do not reuse final reports across different head SHAs.

## Fork Safety

For untrusted forks:

- Prefer artifact-only mode.
- Keep permissions at `contents: read`.
- Do not expose provider API keys or write-scope tokens to attacker-controlled code.
- Do not post comments or send code to external model providers without maintainer approval.
- Avoid `pull_request_target` unless workflow is hardened and secrets cannot reach attacker-controlled steps.

AI review is not hardened against prompt injection from PR diffs, comments, docs, tests, or custom instruction files. Treat all PR content as untrusted.

## Provider / Model Setup

No Claude requirement. The generated prompt can be run with any Pi-configured provider/model: Anthropic, OpenAI, Google, OpenAI-compatible proxies, local models, or custom providers.

Record intended model metadata:

```bash
bun run security-review:ci -- \
  --base origin/main \
  --head HEAD \
  --model openai/gpt-5.1-codex
```

Secrets belong in Pi auth storage or environment variables, not package config or artifacts.

## Troubleshooting

| Condition                                                    | Fix                                                                    |
| ------------------------------------------------------------ | ---------------------------------------------------------------------- |
| `Current directory is not inside a git repository.`          | Run from repo root or checkout repo before script                      |
| Missing base ref                                             | Use `fetch-depth: 0` and fetch target branch                           |
| `GitHub comment mutation requires both --comment and --yes.` | Add `--yes` only when write is intended                                |
| `--comment requires --pr <number>.`                          | Pass PR number from event payload                                      |
| Refusing artifact-only comment                               | Provide `--final-report` or consciously use `--allow-artifact-comment` |
| Final report missing marker                                  | Ensure model output ends with `<!-- pi-security-review-json -->` block |
| `gh` auth failure                                            | Provide `GH_TOKEN`/`GITHUB_TOKEN` and `pull-requests: write`           |
| Fail gate unexpectedly passes                                | Confirm mode is `external-final-report`, not `artifact-only`           |
