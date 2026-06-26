/** Security category and hard-exclusion catalogue for prompt generation. */

export interface SecurityCategory {
  id: string;
  title: string;
  group: string;
  checks: string[];
}

export const SECURITY_CATEGORIES: readonly SecurityCategory[] = [
  {
    id: "input_validation",
    title: "Input validation",
    group: "injection",
    checks: [
      "SQL injection via unsanitized user input",
      "Command injection in system calls or subprocesses",
      "LDAP, XPath, or NoSQL injection",
      "XXE in XML parsing",
      "Template injection in template rendering",
      "Path traversal in file operations, uploads, or archive extraction",
    ],
  },
  {
    id: "authn_authz",
    title: "Authentication and authorization",
    group: "access_control",
    checks: [
      "Authentication bypass logic",
      "Privilege escalation across user, tenant, role, or admin boundaries",
      "Insecure direct object references",
      "Authorization logic bypasses",
      "Session handling flaws",
      "JWT or token validation vulnerabilities",
    ],
  },
  {
    id: "crypto_secrets",
    title: "Cryptography and high-value secrets",
    group: "cryptography",
    checks: [
      "Hardcoded high-value secrets newly added to shipped source",
      "Weak cryptographic algorithms or modes",
      "Improper key handling",
      "Insecure randomness for security-sensitive values",
      "Certificate or TLS validation bypasses in production paths",
    ],
  },
  {
    id: "code_execution",
    title: "Injection and code execution",
    group: "rce",
    checks: [
      "Remote code execution via unsafe deserialization",
      "Python pickle, YAML unsafe load, or equivalent deserialization sinks",
      "Dynamic eval or code generation reachable from untrusted input",
      "Shell/subprocess injection with concrete untrusted input flow",
      "XSS via unsafe HTML trust APIs or raw HTML sinks",
    ],
  },
  {
    id: "data_exposure",
    title: "Data exposure",
    group: "privacy",
    checks: [
      "Sensitive data or PII logging",
      "Debug endpoint or stack trace leakage",
      "Over-broad API response exposure",
      "Missing tenant or user boundary checks causing data leak",
      "Production path exposing credentials, auth material, or private data",
    ],
  },
  {
    id: "config_supply_chain",
    title: "Configuration and supply chain",
    group: "platform",
    checks: [
      "Credentialed CORS with unsafe origins",
      "Disabled auth, TLS, or signature verification in production paths",
      "Dangerous CI workflow trigger with concrete untrusted input path",
      "Dependency execution hooks only when exploit path is concrete",
      "Security control deletion that newly exposes a high-impact path",
    ],
  },
] as const;

export const HARD_EXCLUSIONS: readonly string[] = [
  "Denial of Service or resource exhaustion only",
  "Generic missing rate limiting or service overload concerns",
  "Memory, CPU, or file descriptor leak without a security boundary",
  "Generic input validation advice without concrete sink and impact",
  "Generic hardening or best-practice advice",
  "Theoretical race, timing, or side-channel issue without practical exploit path",
  "Outdated third-party libraries managed by dependency scanners",
  "Documentation-only findings in markdown/docs files",
  "Unit-test-only findings unless fixture ships or executes in production",
  "Log spoofing or logging non-PII data",
  "Regex injection or ReDoS",
  "Open redirect unless impact is concrete and high",
  "SSRF where attacker controls only path, not host or protocol",
  "Missing frontend-only auth checks; server-side checks are authoritative",
  "React/Angular XSS without unsafe HTML trust or bypass APIs",
  "GitHub Actions issue without concrete untrusted trigger path",
  "Shell script command injection without concrete untrusted input path",
  "AI prompt injection that does not cross a real trust or security boundary",
] as const;

export const SEVERITY_GUIDELINES: readonly string[] = [
  "HIGH: direct exploit path to RCE, data breach, auth bypass, or privilege escalation.",
  "MEDIUM: specific exploit conditions with significant security impact.",
  "LOW: defense-in-depth or low-impact issues; exclude from default report.",
] as const;

export const CONFIDENCE_GUIDELINES: readonly string[] = [
  "0.90-1.00: certain exploit path identified.",
  "0.80-0.89: clear vulnerability pattern with known exploitation method.",
  "0.70-0.79: suspicious pattern; do not report by default.",
  "Below threshold: exclude and explain briefly in excludedFindings when useful.",
] as const;

export function renderSecurityCategories(categories = SECURITY_CATEGORIES): string {
  return categories
    .map((category) => {
      const checks = category.checks.map((check) => `- ${check}`).join("\n");
      return `**${category.title}** (\`${category.id}\`)\n${checks}`;
    })
    .join("\n\n");
}

export function renderHardExclusions(exclusions = HARD_EXCLUSIONS): string {
  return exclusions.map((exclusion, index) => `${index + 1}. ${exclusion}.`).join("\n");
}
