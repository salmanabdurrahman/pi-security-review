/** Config schema and defaults for pi-security-review. */

export type SeverityThreshold = "high" | "medium";
export type ThinkingLevel = "off" | "minimal" | "low" | "medium" | "high" | "xhigh" | null;

export interface ModelProfile {
  provider: string | null;
  model: string | null;
  thinkingLevel: ThinkingLevel;
}

export interface GithubConfig {
  commentByDefault: boolean;
  updateExistingComment: boolean;
  commentMarker: string;
}

export interface CiConfig {
  runEveryCommit: boolean;
  failOnHigh: boolean;
  failOnMedium: boolean;
}

export interface OptionalIntegrationsConfig {
  codeReviewGraph: boolean;
}

export interface SecurityReviewConfig {
  enabled: boolean;
  include: string[];
  exclude: string[];
  excludeDocumentation: boolean;
  excludeTestsByDefault: boolean;
  maxDiffBytes: number;
  maxContextChars: number;
  maxFiles: number;
  maxCommits: number;
  confidenceThreshold: number;
  severityThreshold: SeverityThreshold;
  enableHardExclusions: boolean;
  enableModelFiltering: boolean;
  modelProfiles: Record<string, ModelProfile>;
  agentPipeline: string[];
  customSecurityScanInstructions: string | null;
  falsePositiveFilteringInstructions: string | null;
  github: GithubConfig;
  ci: CiConfig;
  optionalIntegrations: OptionalIntegrationsConfig;
}

export const DEFAULT_CONFIG: SecurityReviewConfig = {
  enabled: true,
  include: ["**/*"],
  exclude: [
    "node_modules/**",
    "dist/**",
    "build/**",
    "coverage/**",
    ".git/**",
    ".pi/**",
    "*.lock",
    "**/*.min.js",
    "**/*.generated.*",
  ],
  excludeDocumentation: true,
  excludeTestsByDefault: true,
  maxDiffBytes: 200_000,
  maxContextChars: 50_000,
  maxFiles: 80,
  maxCommits: 50,
  confidenceThreshold: 0.8,
  severityThreshold: "medium",
  enableHardExclusions: true,
  enableModelFiltering: false,
  modelProfiles: {
    default: { provider: null, model: null, thinkingLevel: null },
    auditor: { provider: null, model: null, thinkingLevel: "high" },
    filter: { provider: null, model: null, thinkingLevel: "medium" },
    reporter: { provider: null, model: null, thinkingLevel: null },
  },
  agentPipeline: ["auditor"],
  customSecurityScanInstructions: null,
  falsePositiveFilteringInstructions: null,
  github: {
    commentByDefault: false,
    updateExistingComment: true,
    commentMarker: "<!-- pi-security-review -->",
  },
  ci: {
    runEveryCommit: false,
    failOnHigh: false,
    failOnMedium: false,
  },
  optionalIntegrations: {
    codeReviewGraph: true,
  },
};

const SEVERITIES = new Set<SeverityThreshold>(["high", "medium"]);
const THINKING_LEVELS = new Set(["off", "minimal", "low", "medium", "high", "xhigh", null]);

export function validateAndMergeConfig(input: unknown, source: string): SecurityReviewConfig {
  const value = asRecord(input, source);
  const github = asOptionalRecord(value.github, `${source}:github`) ?? {};
  const ci = asOptionalRecord(value.ci, `${source}:ci`) ?? {};
  const optionalIntegrations =
    asOptionalRecord(value.optionalIntegrations, `${source}:optionalIntegrations`) ?? {};

  return {
    enabled: asBoolean(value.enabled, `${source}:enabled`, DEFAULT_CONFIG.enabled),
    include: asStringArray(value.include, `${source}:include`, DEFAULT_CONFIG.include),
    exclude: asStringArray(value.exclude, `${source}:exclude`, DEFAULT_CONFIG.exclude),
    excludeDocumentation: asBoolean(
      value.excludeDocumentation,
      `${source}:excludeDocumentation`,
      DEFAULT_CONFIG.excludeDocumentation,
    ),
    excludeTestsByDefault: asBoolean(
      value.excludeTestsByDefault,
      `${source}:excludeTestsByDefault`,
      DEFAULT_CONFIG.excludeTestsByDefault,
    ),
    maxDiffBytes: asPositiveInteger(
      value.maxDiffBytes,
      `${source}:maxDiffBytes`,
      DEFAULT_CONFIG.maxDiffBytes,
    ),
    maxContextChars: asPositiveInteger(
      value.maxContextChars,
      `${source}:maxContextChars`,
      DEFAULT_CONFIG.maxContextChars,
    ),
    maxFiles: asPositiveInteger(value.maxFiles, `${source}:maxFiles`, DEFAULT_CONFIG.maxFiles),
    maxCommits: asPositiveInteger(
      value.maxCommits,
      `${source}:maxCommits`,
      DEFAULT_CONFIG.maxCommits,
    ),
    confidenceThreshold: asConfidence(
      value.confidenceThreshold,
      `${source}:confidenceThreshold`,
      DEFAULT_CONFIG.confidenceThreshold,
    ),
    severityThreshold: asSeverity(
      value.severityThreshold,
      `${source}:severityThreshold`,
      DEFAULT_CONFIG.severityThreshold,
    ),
    enableHardExclusions: asBoolean(
      value.enableHardExclusions,
      `${source}:enableHardExclusions`,
      DEFAULT_CONFIG.enableHardExclusions,
    ),
    enableModelFiltering: asBoolean(
      value.enableModelFiltering,
      `${source}:enableModelFiltering`,
      DEFAULT_CONFIG.enableModelFiltering,
    ),
    modelProfiles: asModelProfiles(
      value.modelProfiles,
      `${source}:modelProfiles`,
      DEFAULT_CONFIG.modelProfiles,
    ),
    agentPipeline: asStringArray(
      value.agentPipeline,
      `${source}:agentPipeline`,
      DEFAULT_CONFIG.agentPipeline,
    ),
    customSecurityScanInstructions: asNullableString(
      value.customSecurityScanInstructions,
      `${source}:customSecurityScanInstructions`,
      DEFAULT_CONFIG.customSecurityScanInstructions,
    ),
    falsePositiveFilteringInstructions: asNullableString(
      value.falsePositiveFilteringInstructions,
      `${source}:falsePositiveFilteringInstructions`,
      DEFAULT_CONFIG.falsePositiveFilteringInstructions,
    ),
    github: {
      commentByDefault: asBoolean(
        github.commentByDefault,
        `${source}:github.commentByDefault`,
        DEFAULT_CONFIG.github.commentByDefault,
      ),
      updateExistingComment: asBoolean(
        github.updateExistingComment,
        `${source}:github.updateExistingComment`,
        DEFAULT_CONFIG.github.updateExistingComment,
      ),
      commentMarker: asNonEmptyString(
        github.commentMarker,
        `${source}:github.commentMarker`,
        DEFAULT_CONFIG.github.commentMarker,
      ),
    },
    ci: {
      runEveryCommit: asBoolean(
        ci.runEveryCommit,
        `${source}:ci.runEveryCommit`,
        DEFAULT_CONFIG.ci.runEveryCommit,
      ),
      failOnHigh: asBoolean(ci.failOnHigh, `${source}:ci.failOnHigh`, DEFAULT_CONFIG.ci.failOnHigh),
      failOnMedium: asBoolean(
        ci.failOnMedium,
        `${source}:ci.failOnMedium`,
        DEFAULT_CONFIG.ci.failOnMedium,
      ),
    },
    optionalIntegrations: {
      codeReviewGraph: asBoolean(
        optionalIntegrations.codeReviewGraph,
        `${source}:optionalIntegrations.codeReviewGraph`,
        DEFAULT_CONFIG.optionalIntegrations.codeReviewGraph,
      ),
    },
  };
}

function asRecord(value: unknown, label: string): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error(`Invalid security-review config at ${label}: expected object.`);
  }
  return value as Record<string, unknown>;
}

function asOptionalRecord(value: unknown, label: string): Record<string, unknown> | undefined {
  if (value === undefined) return undefined;
  return asRecord(value, label);
}

function asBoolean(value: unknown, label: string, fallback: boolean): boolean {
  if (value === undefined) return fallback;
  if (typeof value !== "boolean") {
    throw new Error(`Invalid security-review config at ${label}: expected boolean.`);
  }
  return value;
}

function asStringArray(value: unknown, label: string, fallback: string[]): string[] {
  if (value === undefined) return [...fallback];
  if (
    !Array.isArray(value) ||
    value.some((item) => typeof item !== "string" || item.length === 0)
  ) {
    throw new Error(`Invalid security-review config at ${label}: expected non-empty string array.`);
  }
  return [...value];
}

function asNullableString(value: unknown, label: string, fallback: string | null): string | null {
  if (value === undefined) return fallback;
  if (value === null) return null;
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(
      `Invalid security-review config at ${label}: expected non-empty string or null.`,
    );
  }
  return value;
}

function asNonEmptyString(value: unknown, label: string, fallback: string): string {
  if (value === undefined) return fallback;
  if (typeof value !== "string" || value.length === 0) {
    throw new Error(`Invalid security-review config at ${label}: expected non-empty string.`);
  }
  return value;
}

function asPositiveInteger(value: unknown, label: string, fallback: number): number {
  if (value === undefined) return fallback;
  if (typeof value !== "number" || !Number.isInteger(value) || value <= 0) {
    throw new Error(`Invalid security-review config at ${label}: expected positive integer.`);
  }
  return value;
}

function asConfidence(value: unknown, label: string, fallback: number): number {
  if (value === undefined) return fallback;
  if (typeof value !== "number" || value < 0 || value > 1) {
    throw new Error(`Invalid security-review config at ${label}: expected number between 0 and 1.`);
  }
  return value;
}

function asSeverity(value: unknown, label: string, fallback: SeverityThreshold): SeverityThreshold {
  if (value === undefined) return fallback;
  if (typeof value !== "string" || !SEVERITIES.has(value as SeverityThreshold)) {
    throw new Error(`Invalid security-review config at ${label}: expected one of high, medium.`);
  }
  return value as SeverityThreshold;
}

function asModelProfiles(
  value: unknown,
  label: string,
  fallback: Record<string, ModelProfile>,
): Record<string, ModelProfile> {
  if (value === undefined) return structuredClone(fallback);
  const record = asRecord(value, label);
  const profiles: Record<string, ModelProfile> = {};
  for (const [name, profileValue] of Object.entries(record)) {
    if (name.length === 0) {
      throw new Error(
        `Invalid security-review config at ${label}: profile name must be non-empty.`,
      );
    }
    const profile = asRecord(profileValue, `${label}.${name}`);
    profiles[name] = {
      provider: asNullableString(profile.provider, `${label}.${name}.provider`, null),
      model: asNullableString(profile.model, `${label}.${name}.model`, null),
      thinkingLevel: asThinkingLevel(profile.thinkingLevel, `${label}.${name}.thinkingLevel`, null),
    };
  }
  return profiles;
}

function asThinkingLevel(value: unknown, label: string, fallback: ThinkingLevel): ThinkingLevel {
  if (value === undefined) return fallback;
  if (!THINKING_LEVELS.has(value as ThinkingLevel)) {
    throw new Error(
      `Invalid security-review config at ${label}: expected off, minimal, low, medium, high, xhigh, or null.`,
    );
  }
  return value as ThinkingLevel;
}
