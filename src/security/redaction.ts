/** Secret-like value redaction for reports and comments. */

const REDACTION = "[REDACTED_SECRET]";

const SECRET_PATTERNS: RegExp[] = [
  /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/gu,
  /\bgithub_pat_[A-Za-z0-9_]{20,}\b/gu,
  /\bgh[opsru]_[A-Za-z0-9_]{20,}\b/gu,
  /\bAKIA[0-9A-Z]{16}\b/gu,
  /\bASIA[0-9A-Z]{16}\b/gu,
  /\b(?:Bearer|Token)\s+[A-Za-z0-9._~+/=-]{16,}\b/giu,
  /\bsk-[A-Za-z0-9_-]{20,}\b/gu,
  /\b(?:api[_-]?key|access[_-]?token|auth[_-]?token|password|secret)\s*[:=]\s*["']?[^\s"'`,;)]{8,}["']?/giu,
  /\b[A-Za-z0-9+/]{32,}={0,2}\b/gu,
  /\b[0-9a-f]{32,}\b/giu,
];

export function redactSecretLikeValues(text: string): string {
  let redacted = text;
  for (const pattern of SECRET_PATTERNS) redacted = redacted.replace(pattern, REDACTION);
  return redacted;
}

export function redactSecretsInValue<T>(value: T): T {
  if (typeof value === "string") return redactSecretLikeValues(value) as T;
  if (Array.isArray(value)) return value.map((item) => redactSecretsInValue(item)) as T;
  if (!value || typeof value !== "object") return value;

  const redacted: Record<string, unknown> = {};
  for (const [key, child] of Object.entries(value)) redacted[key] = redactSecretsInValue(child);
  return redacted as T;
}
