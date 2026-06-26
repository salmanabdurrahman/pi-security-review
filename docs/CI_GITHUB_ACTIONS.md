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
      - uses: actions/checkout@v6
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

The examples use floating major tags for readability (`actions/checkout@v6`, `oven-sh/setup-bun@v2`, `actions/upload-artifact@v4`). For high-trust/release workflows, pin third-party actions to reviewed commit SHAs and rotate intentionally.

## Script Flags

| Flag                                | Description                                                                    |
| ----------------------------------- | ------------------------------------------------------------------------------ |
| `--base <ref>`                      | Base ref for Git diff                                                          |
| `--head <ref>`                      | Head ref for Git diff                                                          |
| `--output <path>`                   | JSON artifact path, default `.pi/security-review/ci-context.json`              |
| `--markdown <path>`                 | Markdown artifact path, default `.pi/security-review/ci-report.md`             |
| `--pr <number>`                     | Pull request number for optional comment                                       |
| `--comment`                         | Post PR comment; requires `--yes`, `--pr`, and final report unless override    |
| `--yes` / `-y`                      | Explicit approval for GitHub comment mutation                                  |
| `--model <provider/model>`          | Record intended Pi model metadata in context/prompt                            |
| `--final-report <path>`             | Read model-produced Markdown/JSON marker as final report                       |
| `--scan-instructions-file <path>`   | Read repo-relative custom scan instructions file                               |
| `--filter-instructions-file <path>` | Read repo-relative custom false-positive filter file                           |
| `--scan-instructions-text <text>`   | Add inline custom scan instructions                                            |
| `--filter-instructions-text <text>` | Add inline custom false-positive filter instructions                           |
| `--include <glob[,glob]>`           | Override config include globs for this CI run                                  |
| `--exclude <glob[,glob]>`           | Append exclude globs for this CI run                                           |
| `--paths <path...>`                 | Focus Git diff on paths                                                        |
| `--exclude-directories <dir[,dir]>` | Upstream-compatible alias, expands each dir to `<dir>/**`                      |
| `--allow-artifact-comment`          | Maintainer override to comment artifact-only context; avoid for normal results |
| `--fail-on-high`                    | Exit non-zero when final report contains HIGH findings                         |
| `--fail-on-medium`                  | Exit non-zero when final report contains MEDIUM or HIGH findings               |
| `--ci-help`                         | Show help                                                                      |

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
- safe custom instruction text/source metadata when configured
- bounded PR metadata from `GITHUB_EVENT_PATH` when available
- report envelope or final report payload

Custom instruction files must be repo-relative, stay inside the repository, avoid secret-like paths, and fit the size bound. Inline instruction flags are also bounded. PR metadata is context only; it cannot override security review rules.

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
  - uses: actions/checkout@v6
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
      - uses: actions/checkout@v6
        with:
          fetch-depth: 0
      - uses: owner/pi-security-review@v0.1.0
        with:
          base: origin/${{ github.base_ref }}
          head: HEAD
          output: artifacts/security-context.json
          markdown: artifacts/security-report.md
          scan-instructions-file: .github/security-scan.txt
          exclude-directories: vendor,third_party
          retention-days: 7
```

Action inputs mirror script flags for `base`, `head`, `model`, final report ingestion, custom instruction file/text, `include`, `exclude`, `paths`, and upstream-compatible `exclude-directories`. `upload-results` defaults to `true` and uploads JSON/Markdown artifacts through `actions/upload-artifact`; set `upload-results: false` for repositories where workflow artifacts are too sensitive. `retention-days` defaults to `7`.

Action outputs:

| Output           | Description                                  |
| ---------------- | -------------------------------------------- |
| `findings-count` | Kept findings count in artifact/final report |
| `high-count`     | HIGH findings count                          |
| `medium-count`   | MEDIUM findings count                        |
| `mode`           | `artifact-only` or `external-final-report`   |
| `results-file`   | JSON artifact path                           |
| `markdown-file`  | Markdown artifact path                       |

## Model-backed PR Workflow (OpenAI-compatible)

The bundled `.github/workflows/security-review-pr.yml` is a real PR workflow template:

- Always builds artifact-only context first.
- Runs a model call only for same-repository PRs when secrets are configured.
- Keeps fork PRs artifact-only so model credentials are not exposed to untrusted code.
- Posts/updates a readable PR comment only after a model-produced final report is normalized.
- Applies `fail-on-high` and `fail-on-medium` only after final report comment/write completes.
- Does not post comments for fork PRs or missing model secrets.

Configure repository secrets:

| Secret                           | Required                    | Description                                                |
| -------------------------------- | --------------------------- | ---------------------------------------------------------- |
| `SECURITY_REVIEW_MODEL_API_KEY`  | Yes for model-backed review | API key for OpenAI-compatible `/chat/completions` provider |
| `SECURITY_REVIEW_MODEL_NAME`     | Yes for model-backed review | Model name/provider model ID                               |
| `SECURITY_REVIEW_MODEL_BASE_URL` | Optional                    | Defaults to `https://api.openai.com/v1`                    |

If secrets are missing or PR comes from a fork, the workflow still uploads prompt/context artifacts but is not a final security verdict and does not post a PR comment.

Required workflow permissions for automatic comments:

```yaml
permissions:
  contents: read
  pull-requests: write
```

Comment behavior:

- Uses `<!-- pi-security-review -->` marker.
- Updates existing marker comment when present.
- Never deletes comments.
- Redacts common secret-like values before posting.
- Uses `GITHUB_TOKEN`/`${{ github.token }}` from workflow runtime; no token secret is stored in repo config.

## Composite Action: Final Report Gate

```yaml
permissions:
  contents: read

jobs:
  security-review:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
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
      - uses: actions/checkout@v6
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

The bundled PR workflow uses a generic OpenAI-compatible Chat Completions request:

- `SECURITY_REVIEW_MODEL_BASE_URL` + `/chat/completions`
- `Authorization: Bearer $SECURITY_REVIEW_MODEL_API_KEY`
- `model: $SECURITY_REVIEW_MODEL_NAME`
- `messages: [{ role: "user", content: prompt }]`
- `temperature: 0`

This works for providers that accept the standard Chat Completions subset. Provider-specific thinking/reasoning controls are not enabled by the workflow unless you add a trusted runner step that supplies provider-specific request fields.

| Provider / runtime | Base URL                        | Model examples                                                         | Notes                                                                                                                              |
| ------------------ | ------------------------------- | ---------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------- |
| OpenRouter         | `https://openrouter.ai/api/v1`  | `~openai/gpt-latest`, `anthropic/claude-sonnet-*`, model catalog slugs | OpenAI-compatible. Optional attribution headers (`HTTP-Referer`, `X-OpenRouter-Title`) are not required by this workflow.          |
| DeepSeek           | `https://api.deepseek.com`      | `deepseek-v4-flash`, `deepseek-v4-pro`                                 | OpenAI-compatible. Thinking controls use provider-specific fields; generic workflow still works for basic calls.                   |
| Kimi / Moonshot AI | `https://api.moonshot.ai/v1`    | Kimi model IDs from Kimi platform                                      | OpenAI-compatible. Kimi-specific thinking parameters need custom runner logic.                                                     |
| MiniMax            | `https://api.minimax.io/v1`     | `MiniMax-M3`, M2.x models                                              | OpenAI-compatible. Reasoning/thinking params are provider-specific.                                                                |
| Z.AI / Zhipu GLM   | `https://api.z.ai/api/paas/v4/` | `glm-5.2`, GLM family IDs                                              | OpenAI SDK compatible. Coding Plan uses separate endpoint `https://api.z.ai/api/coding/paas/v4`.                                   |
| Ollama local       | `http://localhost:11434/v1`     | `gpt-oss:20b`, `qwen3:8b`, local pulled models                         | Works on self-hosted runner or local trusted runner. `localhost` on GitHub-hosted runner is not your laptop.                       |
| LM Studio local    | `http://localhost:1234/v1`      | loaded local model identifier                                          | Works on self-hosted runner/local trusted runner.                                                                                  |
| vLLM / SGLang      | `http://<host>:<port>/v1`       | HF/open-weight model IDs served by runtime                             | OpenAI-compatible self-hosted runtimes; model-specific reasoning/chat-template settings belong in server or trusted runner config. |

Example repository secrets for an OpenAI-compatible provider:

```text
SECURITY_REVIEW_MODEL_API_KEY=<provider API key>
SECURITY_REVIEW_MODEL_NAME=<provider model id>
SECURITY_REVIEW_MODEL_BASE_URL=<provider base URL>
```

Examples:

```text
# OpenRouter
SECURITY_REVIEW_MODEL_BASE_URL=https://openrouter.ai/api/v1
SECURITY_REVIEW_MODEL_NAME=~openai/gpt-latest

# DeepSeek
SECURITY_REVIEW_MODEL_BASE_URL=https://api.deepseek.com
SECURITY_REVIEW_MODEL_NAME=deepseek-v4-pro

# Kimi / Moonshot
SECURITY_REVIEW_MODEL_BASE_URL=https://api.moonshot.ai/v1
SECURITY_REVIEW_MODEL_NAME=<kimi model id>

# MiniMax
SECURITY_REVIEW_MODEL_BASE_URL=https://api.minimax.io/v1
SECURITY_REVIEW_MODEL_NAME=MiniMax-M3

# Z.AI / GLM
SECURITY_REVIEW_MODEL_BASE_URL=https://api.z.ai/api/paas/v4/
SECURITY_REVIEW_MODEL_NAME=glm-5.2
```

For local models in Pi interactive usage, configure `~/.pi/agent/models.json` with `api: "openai-completions"`, for example Ollama/LM Studio/vLLM/SGLang. The GitHub PR workflow does not read Pi `models.json`; it only uses the three `SECURITY_REVIEW_MODEL_*` secrets above. Use a self-hosted runner or external trusted model runner when the model server is local.

Record intended model metadata in artifact-only mode:

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
