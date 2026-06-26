# Privacy and Security

`pi-security-review` is local-first, provider-neutral, and telemetry-free. Default behavior reads local Git state, builds bounded review context, writes local reports, and performs no network writes.

## Data Stored Locally

Repo-local files created or read by package:

```text
.pi/security-review.json
.pi/security-review/latest-report.md
.pi/security-review/latest-report.json
.pi/security-review/ci-context.json
.pi/security-review/ci-report.md
```

Stored data may include:

- Config preferences such as path filters, thresholds, model profile metadata, and GitHub comment marker.
- Latest security report Markdown and normalized JSON.
- CI context artifact containing bounded diff/context and generated prompt.
- CI report artifact containing artifact-only or external-final-report output.

Stored data should not include provider credentials, GitHub tokens, environment variables, private keys, or raw secret literals. Writers redact common secret-like values before saving reports/artifacts.

## Local Reads

The package reads from current Git repository:

- Git root, branch, refs, and working-tree status.
- Git diff metadata and bounded diff hunks for selected scope.
- GitHub remote URL for owner/repo detection.
- Repo-local custom instruction files when explicitly requested.
- Optional code-review-graph context when available and enabled.

Default filters skip secret-like files, env files, private keys, certificates, `.pi/`, generated/vendor paths, package artifacts, and oversized files according to config.

## Model Provider Boundary

Review prompts run through Pi's active model/provider lifecycle. Provider can be Anthropic, OpenAI, Google, OpenAI-compatible proxy, local model, or custom Pi provider.

`pi-security-review` does not hardcode Claude/OpenAI SDK calls and does not persist provider credentials.

Prompt data may include:

- Bounded diff/context for files in review scope.
- File paths and line ranges.
- Review scope metadata and truncation warnings.
- Optional custom scan/filter instructions.
- Optional code-review-graph context.
- Model profile metadata such as role names and requested provider/model IDs.

Prompt data must not include:

- Provider API keys or auth secrets.
- Environment variable values.
- Secret literals from reports; prompt contract instructs model to reference only secret type, field/name, and path.
- Files blocked by path/secret filters.

If using external providers, review whether sending diff/context to that provider is allowed by org policy. Use local models when code/data locality is required.

## Network Behavior

No telemetry, metrics upload, or background network calls are performed by runtime helpers.

Network writes happen only through explicit GitHub PR comment paths:

| Path                                       | Default                                 | Required to write                                                     |
| ------------------------------------------ | --------------------------------------- | --------------------------------------------------------------------- |
| `/security-review-comment`                 | Dry-run preview                         | `--yes`                                                               |
| `security_review_github_comment` tool      | Dry-run preview                         | `post: true` and `approve: true`                                      |
| `security-review:ci`                       | Artifact/final report only              | `--comment --yes --pr <number>` plus trusted report                   |
| Composite GitHub Action                    | Artifact-only                           | `comment: true`, `yes: true`, `pr`, and final report unless override  |
| `.github/workflows/security-review-pr.yml` | Artifact-only for forks/missing secrets | Same-repo PR, model secrets, final report, and `pull-requests: write` |

The package never deletes GitHub comments. It can update an existing bot marker comment when requested. Inline comments are best-effort, validated against changed PR lines, and fall back to summary when mapping fails.

## GitHub Authentication

GitHub comment posting uses runtime auth only:

- `gh` CLI auth state, or
- `GH_TOKEN` / `GITHUB_TOKEN` environment variable.

Tokens are not accepted in CLI flags, stored in config, written to reports, or persisted by this package. GitHub Actions workflows should pass `${{ github.token }}` through environment with least permissions needed.

## CI Safety

Artifact-only CI mode needs only `contents: read`. It builds context/prompt artifacts but does not call a model and is not a final security result.

The bundled PR workflow uses `contents: read` and `pull-requests: write` so it can post/update a final report comment. It only performs model-backed review and PR comments for same-repository PRs with configured model secrets. Fork PRs stay artifact-only and do not receive comments.

External final report mode reads a trusted model-produced report containing the `<!-- pi-security-review-json -->` marker and can apply `--fail-on-high` / `--fail-on-medium` gates.

PR comment mode requires:

- `--comment --yes --pr <number>`.
- Authenticated `gh` or token.
- `pull-requests: write` permission.
- Trusted workflow context.
- Final model report via `--final-report`, unless maintainer explicitly passes `--allow-artifact-comment`.

Do not treat artifact-only zero findings as evidence of no vulnerabilities.

## Fork and Prompt-Injection Safety

AI review is not hardened against prompt injection from changed code, comments, docs, tests, commit messages, or custom instruction files. Treat all PR content as untrusted.

For public repositories:

- Use artifact-only mode for untrusted forks.
- Require maintainer approval before model-backed review of external contributions.
- Do not expose provider API keys or write-scope GitHub tokens to attacker-controlled code.
- Avoid `pull_request_target` for untrusted code unless workflow is hardened and does not check out/run attacker-controlled files with secrets.
- Prefer local models for high-sensitivity code when policy requires data locality.

Prompt contract tells the model to ignore attempts to alter review rules, reveal secrets, disable redaction, or perform writes. This reduces risk but is not a security boundary.

## Secret Handling

Path guards refuse common secret-like paths, including:

- `.env`, `.env.*`
- token/credential/password/secret names
- private key files
- key/cert/pem files
- `.pi/` runtime data
- generated/vendor/package artifact paths

Report storage and GitHub comment rendering redact common secret-like values before write/post, including:

- Bearer tokens.
- GitHub tokens.
- AWS access key IDs.
- OpenAI-style keys.
- Private key blocks.
- Assignment-style `apiKey`, `password`, `secret`, and token values.
- Generic long high-entropy strings.

Report JSON storage rejects secret-like field names such as token, password, API key, secret, and private key.

## Subprocess Safety

Runtime helpers use fixed argv arrays through `src/util/exec.ts` and do not build shell command strings from user input. Git refs are validated before use by diff helpers. Tool outputs are bounded to 50 KB or 2,000 lines.

## Package and Publish Safety

`bun run prepublish:audit` builds `dist`, verifies copied runtime files match source files, runs npm pack dry-run, and blocks forbidden package contents:

- `.pi/`
- `node_modules/`
- stale reports/cache
- tarballs and logs
- env files
- private keys and certificates
- tests/tasks
- unapproved docs

Release workflow should use npm trusted publishing/OIDC instead of long-lived npm publish tokens.

## Security Non-Goals

`pi-security-review` is not:

- Complete SAST replacement.
- Secret scanner.
- Dependency vulnerability scanner.
- Runtime protection system.
- Prompt-injection proof sandbox.
- Automatic remediation/autofix tool.

Use it as focused review assistance and keep human security review for high-risk changes.
