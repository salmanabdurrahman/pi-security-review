/** Deterministic false-positive filters for security-review findings. */

import type { SecurityReviewConfig } from "../config/schema.ts";
import {
  confidenceMeetsThreshold,
  findingMeetsSignalThreshold,
  normalizeConfidence,
  normalizeSeverity,
  severityMeetsThreshold,
} from "./confidence.ts";
import type { ExcludedFinding, SecurityFinding } from "./findings.ts";
import { normalizeFinding } from "./findings.ts";

export interface FilterFindingsOptions {
  confidenceThreshold?: number;
  severityThreshold?: "high" | "medium";
  enableHardExclusions?: boolean;
  config?: SecurityReviewConfig;
}

export interface FilterFindingsResult {
  findings: SecurityFinding[];
  excludedFindings: ExcludedFinding[];
  summary: {
    totalFindings: number;
    keptFindings: number;
    excludedFindings: number;
    hardExcluded: number;
    confidenceExcluded: number;
    severityExcluded: number;
    highSeverity: number;
    mediumSeverity: number;
    lowSeverity: number;
    exclusionBreakdown: Record<string, number>;
  };
}

export interface HardExclusionResult {
  excluded: boolean;
  reason?: string;
}

type Rule = {
  reason: string;
  test: (context: RuleContext) => boolean;
};

interface RuleContext {
  finding: SecurityFinding;
  file: string;
  title: string;
  description: string;
  exploitScenario: string;
  recommendation: string;
  text: string;
  extension: string;
}

const DOS_PATTERNS = [
  /\b(denial of service|dos attack|resource exhaustion)\b/iu,
  /\b(exhaust|overwhelm|overload).*?\b(resource|memory|cpu)\b/iu,
  /\b(infinite|unbounded).*?\b(loop|recursion)\b/iu,
];

const RATE_LIMITING_PATTERNS = [
  /\b(missing|lack of|no)\s+rate\s+limit/iu,
  /\brate\s+limiting\s+(missing|required|not implemented)\b/iu,
  /\b(implement|add)\s+rate\s+limit/iu,
  /\bunlimited\s+(requests|calls|api)\b/iu,
];

const RESOURCE_LEAK_PATTERNS = [
  /\b(resource|memory|file)\s+leak\s+potential\b/iu,
  /\bunclosed\s+(resource|file|connection)\b/iu,
  /\b(close|cleanup|release)\s+(resource|file|connection)\b/iu,
  /\bpotential\s+memory\s+leak\b/iu,
  /\b(database|thread|socket|connection|file descriptor)\s+leak\b/iu,
];

const REGEX_INJECTION_PATTERNS = [
  /\b(regex|regular expression)\s+injection\b/iu,
  /\b(regex|regular expression)\s+denial of service\b/iu,
  /\bredos\b/iu,
  /\bcatastrophic\s+backtracking\b/iu,
];

const OPEN_REDIRECT_PATTERNS = [
  /\b(open redirect|unvalidated redirect)\b/iu,
  /\bredirect\s+(attack|exploit|vulnerability)\b/iu,
  /\bmalicious\s+redirect\b/iu,
];

const SSRF_PATTERNS = [/\b(ssrf|server\s*-?side\s+request\s+forgery)\b/iu];

const FRONTEND_AUTH_PATTERNS = [
  /\b(client|frontend|front-end|browser)\s*-?side\s+(auth|authorization|authentication)\b/iu,
  /\bmissing\s+(auth|authorization|authentication).*\b(client|frontend|front-end|browser)\b/iu,
];

const XSS_PATTERNS = [/\bxss\b/iu, /\bcross\s*-?site\s+scripting\b/iu];

const UNSAFE_HTML_APIS = [
  "dangerouslysetinnerhtml",
  "bypasssecuritytrusthtml",
  "bypasssecuritytrustscript",
  "innerhtml",
  "outerhtml",
  "insertadjacenthtml",
  "v-html",
  "ng-bind-html",
];

const UNTRUSTED_INPUT_PATTERNS = [
  /\buntrusted\b/iu,
  /\battacker[-\s]?controlled\b/iu,
  /\buser[-\s]?controlled\b/iu,
  /\bpull_request(_target)?\b/iu,
  /\bgithub\.event\.(pull_request|issue|comment)\b/iu,
  /\b(input|argv|stdin|query|param|body|header|cookie|env)\b/iu,
];

const GENERIC_VALIDATION_PATTERNS = [
  /\bmissing\s+input\s+validation\b/iu,
  /\binput\s+validation\s+(required|missing)\b/iu,
  /\b(validate|sanitize)\s+(input|parameters|params)\b/iu,
];

const SPECIFIC_SECURITY_SINK_PATTERNS = [
  /\b(sql|command|ldap|xpath|nosql|template|path traversal|xxe|eval|deserialization|ssrf|xss)\b/iu,
  /\b(auth|authorization|authentication|privilege|tenant|rce|data leak|pii)\b/iu,
];

const RULES: Rule[] = [
  {
    reason: "Documentation-only finding",
    test: ({ file }) => isDocumentationPath(file),
  },
  {
    reason: "Tests-only finding",
    test: ({ file, text }) => isTestPath(file) && !mentionsProductionExecution(text),
  },
  {
    reason: "Generic DOS/resource exhaustion finding (low signal)",
    test: ({ text }) => matchesAny(DOS_PATTERNS, text) && !mentionsCodeExecutionImpact(text),
  },
  {
    reason: "Generic rate limiting recommendation",
    test: ({ text }) => matchesAny(RATE_LIMITING_PATTERNS, text),
  },
  {
    reason: "Resource management finding without security boundary",
    test: ({ text }) => matchesAny(RESOURCE_LEAK_PATTERNS, text) && !mentionsSecurityBoundary(text),
  },
  {
    reason: "Generic input validation advice without concrete sink and impact",
    test: ({ text }) =>
      matchesAny(GENERIC_VALIDATION_PATTERNS, text) &&
      !matchesAny(SPECIFIC_SECURITY_SINK_PATTERNS, text),
  },
  {
    reason: "Regex injection/ReDoS finding (low signal)",
    test: ({ text }) => matchesAny(REGEX_INJECTION_PATTERNS, text),
  },
  {
    reason: "Open redirect finding without concrete high-impact exploit",
    test: ({ text }) =>
      matchesAny(OPEN_REDIRECT_PATTERNS, text) && !mentionsHighImpactRedirect(text),
  },
  {
    reason: "SSRF finding where attacker controls path only, not host or protocol",
    test: ({ text }) => matchesAny(SSRF_PATTERNS, text) && mentionsPathOnlyControl(text),
  },
  {
    reason: "Frontend-only auth check without server-side bypass",
    test: ({ file, text }) =>
      (isFrontendPath(file) || matchesAny(FRONTEND_AUTH_PATTERNS, text)) &&
      mentionsAuth(text) &&
      !mentionsServerSideBypass(text),
  },
  {
    reason: "React/Angular XSS without unsafe HTML trust or bypass API",
    test: ({ file, text }) =>
      (isReactAngularPath(file) || /\b(react|angular)\b/iu.test(text)) &&
      matchesAny(XSS_PATTERNS, text) &&
      !containsUnsafeHtmlApi(text),
  },
  {
    reason: "GitHub Actions issue without concrete untrusted trigger path",
    test: ({ file, text }) => isGitHubActionsPath(file) && !mentionsConcreteUntrustedPath(text),
  },
  {
    reason: "Shell command injection without concrete untrusted input path",
    test: ({ file, text }) =>
      isShellPath(file) &&
      /\b(command|shell)\s+injection\b/iu.test(text) &&
      !mentionsConcreteUntrustedPath(text),
  },
];

export function filterFindings(
  inputFindings: readonly unknown[],
  options: FilterFindingsOptions = {},
): FilterFindingsResult {
  const threshold = options.confidenceThreshold ?? options.config?.confidenceThreshold ?? 0.8;
  const severityThreshold =
    options.severityThreshold ?? options.config?.severityThreshold ?? "medium";
  const enableHardExclusions =
    options.enableHardExclusions ?? options.config?.enableHardExclusions ?? true;

  const findings = inputFindings.map((finding, index) => normalizeFinding(finding, index));
  const kept: SecurityFinding[] = [];
  const excluded: ExcludedFinding[] = [];
  const breakdown: Record<string, number> = {};

  for (const finding of findings) {
    const normalized = {
      ...finding,
      severity: normalizeSeverity(finding.severity),
      confidence: normalizeConfidence(finding.confidence),
    };

    if (enableHardExclusions) {
      const hardExclusion = getHardExclusion(normalized);
      if (hardExclusion.excluded) {
        pushExcluded(excluded, breakdown, {
          finding: normalized,
          file: normalized.file,
          line: normalized.line,
          reason: hardExclusion.reason ?? "Excluded by hard rules.",
          filterStage: "hard_rules",
          confidence: normalized.confidence,
          severity: normalized.severity,
        });
        continue;
      }
    }

    if (!severityMeetsThreshold(normalized.severity, severityThreshold)) {
      pushExcluded(excluded, breakdown, {
        finding: normalized,
        file: normalized.file,
        line: normalized.line,
        reason: `Severity ${normalized.severity} is below threshold ${severityThreshold.toUpperCase()}.`,
        filterStage: "severity",
        confidence: normalized.confidence,
        severity: normalized.severity,
      });
      continue;
    }

    if (!confidenceMeetsThreshold(normalized.confidence, threshold)) {
      pushExcluded(excluded, breakdown, {
        finding: normalized,
        file: normalized.file,
        line: normalized.line,
        reason: `Confidence ${normalized.confidence.toFixed(2)} is below threshold ${threshold.toFixed(2)}.`,
        filterStage: "confidence",
        confidence: normalized.confidence,
        severity: normalized.severity,
      });
      continue;
    }

    if (findingMeetsSignalThreshold(normalized, { threshold, severityThreshold })) {
      kept.push(normalized);
    }
  }

  return {
    findings: kept,
    excludedFindings: excluded,
    summary: {
      totalFindings: findings.length,
      keptFindings: kept.length,
      excludedFindings: excluded.length,
      hardExcluded: excluded.filter((finding) => finding.filterStage === "hard_rules").length,
      confidenceExcluded: excluded.filter((finding) => finding.filterStage === "confidence").length,
      severityExcluded: excluded.filter((finding) => finding.filterStage === "severity").length,
      highSeverity: kept.filter((finding) => finding.severity === "HIGH").length,
      mediumSeverity: kept.filter((finding) => finding.severity === "MEDIUM").length,
      lowSeverity: kept.filter((finding) => finding.severity === "LOW").length,
      exclusionBreakdown: breakdown,
    },
  };
}

export function getHardExclusion(finding: SecurityFinding): HardExclusionResult {
  const context = buildRuleContext(finding);
  for (const rule of RULES) {
    if (rule.test(context)) return { excluded: true, reason: rule.reason };
  }
  return { excluded: false };
}

function buildRuleContext(finding: SecurityFinding): RuleContext {
  const file = finding.file.toLowerCase();
  const title = finding.title.toLowerCase();
  const description = finding.description.toLowerCase();
  const exploitScenario = finding.exploitScenario.toLowerCase();
  const recommendation = finding.recommendation.toLowerCase();
  const text = [title, description, exploitScenario, recommendation].join(" ");
  return {
    finding,
    file,
    title,
    description,
    exploitScenario,
    recommendation,
    text,
    extension: ext(file),
  };
}

function pushExcluded(
  excluded: ExcludedFinding[],
  breakdown: Record<string, number>,
  finding: ExcludedFinding,
): void {
  excluded.push(finding);
  breakdown[finding.reason] = (breakdown[finding.reason] ?? 0) + 1;
}

function matchesAny(patterns: readonly RegExp[], text: string): boolean {
  return patterns.some((pattern) => pattern.test(text));
}

function ext(file: string): string {
  const slash = file.lastIndexOf("/");
  const basename = slash === -1 ? file : file.slice(slash + 1);
  const dot = basename.lastIndexOf(".");
  return dot === -1 ? "" : basename.slice(dot);
}

function isDocumentationPath(file: string): boolean {
  return file.endsWith(".md") || file.endsWith(".mdx") || file.startsWith("docs/");
}

function isTestPath(file: string): boolean {
  return (
    /(^|\/)(test|tests|__tests__|spec|fixtures)(\/|$)/u.test(file) ||
    /\.(test|spec)\.[cm]?[jt]sx?$/u.test(file) ||
    file.endsWith("_test.go") ||
    file.endsWith(".snap")
  );
}

function isFrontendPath(file: string): boolean {
  return (
    /(^|\/)(frontend|client|web|ui|components|pages|app)(\/|$)/u.test(file) ||
    /\.(jsx|tsx|vue|svelte)$/u.test(file)
  );
}

function isReactAngularPath(file: string): boolean {
  return /\.(jsx|tsx)$/u.test(file) || /(^|\/)(react|angular|components)(\/|$)/u.test(file);
}

function isGitHubActionsPath(file: string): boolean {
  return file.startsWith(".github/workflows/") && (file.endsWith(".yml") || file.endsWith(".yaml"));
}

function isShellPath(file: string): boolean {
  return file.endsWith(".sh") || ext(file) === ".bash" || ext(file) === ".zsh";
}

function mentionsProductionExecution(text: string): boolean {
  return /\b(production|prod|shipped|runtime|executed in prod|published package)\b/iu.test(text);
}

function mentionsCodeExecutionImpact(text: string): boolean {
  return /\b(code execution|rce|remote code execution|execute arbitrary code|memory corruption)\b/iu.test(
    text,
  );
}

function mentionsSecurityBoundary(text: string): boolean {
  return /\b(auth|tenant|privilege|sandbox|isolation|security boundary|data leak|rce)\b/iu.test(
    text,
  );
}

function mentionsHighImpactRedirect(text: string): boolean {
  return /\b(oauth|sso|token|credential|account takeover|phishing with credential|auth code)\b/iu.test(
    text,
  );
}

function mentionsPathOnlyControl(text: string): boolean {
  return (
    /\b(path only|only path|path component|url path)\b/iu.test(text) ||
    (/\bpath\b/iu.test(text) && !/\b(host|hostname|protocol|scheme|domain|origin)\b/iu.test(text))
  );
}

function mentionsAuth(text: string): boolean {
  return /\b(auth|authorization|authentication|login|role|permission)\b/iu.test(text);
}

function mentionsServerSideBypass(text: string): boolean {
  return /\b(server[-\s]?side|api|backend|authorization bypass|auth bypass|tenant boundary|idor)\b/iu.test(
    text,
  );
}

function containsUnsafeHtmlApi(text: string): boolean {
  const normalized = text.toLowerCase();
  return UNSAFE_HTML_APIS.some((api) => normalized.includes(api));
}

function mentionsConcreteUntrustedPath(text: string): boolean {
  return UNTRUSTED_INPUT_PATTERNS.some((pattern) => pattern.test(text));
}
