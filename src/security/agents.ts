/** Multi-agent role definitions and model-profile resolution for pi-security-review. */

import { DEFAULT_CONFIG, type SecurityReviewConfig, type ThinkingLevel } from "../config/schema.ts";

export type SecurityReviewAgentRole = "auditor" | "filter" | "reporter";

export interface SecurityReviewAgentDefinition {
  role: SecurityReviewAgentRole;
  title: string;
  promptFragment: string;
  defaultThinkingLevel: ThinkingLevel;
}

export interface ResolvedSecurityReviewAgent {
  role: string;
  title: string;
  promptFragment: string;
  provider: string | null;
  model: string | null;
  modelId?: string;
  thinkingLevel: ThinkingLevel;
  warnings: string[];
}

export const SECURITY_REVIEW_AGENT_DEFINITIONS: Record<
  SecurityReviewAgentRole,
  SecurityReviewAgentDefinition
> = {
  auditor: {
    role: "auditor",
    title: "Security auditor",
    defaultThinkingLevel: "high",
    promptFragment:
      "Identify newly introduced HIGH/MEDIUM vulnerabilities only. Require concrete attacker input, vulnerable path, and security impact.",
  },
  filter: {
    role: "filter",
    title: "False-positive filter",
    defaultThinkingLevel: "medium",
    promptFragment:
      "Validate findings against hard exclusions, severity threshold, confidence threshold, and custom filtering instructions. Drop speculative or low-signal findings.",
  },
  reporter: {
    role: "reporter",
    title: "Report renderer",
    defaultThinkingLevel: null,
    promptFragment:
      "Render concise Markdown and valid JSON marker output. Preserve repo-relative paths, changed-line references, model metadata, and exclusion reasons.",
  },
};

export function resolveSecurityReviewAgents(
  config: SecurityReviewConfig,
): ResolvedSecurityReviewAgent[] {
  const pipeline = config.agentPipeline.length > 0 ? config.agentPipeline : ["auditor"];
  return pipeline.map((role) => resolveSecurityReviewAgent(config, role));
}

export function resolveSecurityReviewAgent(
  config: SecurityReviewConfig,
  role: string,
): ResolvedSecurityReviewAgent {
  const definition = getAgentDefinition(role);
  const profile = config.modelProfiles[role] ?? config.modelProfiles.default;
  const warnings: string[] = [];

  if (!isKnownRole(role)) {
    warnings.push(
      `Unknown security-review agent role '${role}'; using auditor role prompt fragment.`,
    );
  }
  if (!profile) {
    warnings.push(`Model profile '${role}' not found; active Pi model will be used.`);
  }

  const provider = profile?.provider ?? null;
  const model = profile?.model ?? null;
  const thinkingLevel = profile?.thinkingLevel ?? definition.defaultThinkingLevel;

  return {
    role,
    title: definition.title,
    promptFragment: definition.promptFragment,
    provider,
    model,
    modelId: provider && model ? `${provider}/${model}` : undefined,
    thinkingLevel,
    warnings,
  };
}

export function buildAgentPromptSection(agents: readonly ResolvedSecurityReviewAgent[]): string {
  const activeAgents =
    agents.length > 0 ? agents : [resolveSecurityReviewAgent(DEFAULT_CONFIG, "auditor")];

  return [
    "## Agent role pipeline",
    "",
    "Run roles deterministically in listed order. If only `auditor` is configured, keep single-agent behavior stable.",
    "If any role-specific model is unavailable, state warning metadata and continue with active Pi model unless command already failed validation.",
    "Do not store provider secrets or API keys in role metadata.",
    "",
    ...activeAgents.flatMap((agent, index) => [
      `${index + 1}. \`${agent.role}\` — ${agent.title}`,
      `   - Model profile: ${agent.modelId ?? "active Pi model"}`,
      `   - Thinking level: ${agent.thinkingLevel ?? "Pi default/current"}`,
      `   - Role: ${agent.promptFragment}`,
    ]),
  ].join("\n");
}

export function agentMetadata(
  agents: readonly ResolvedSecurityReviewAgent[],
): Array<{ role: string; model?: string; thinkingLevel?: string | null }> {
  return agents.map((agent) => ({
    role: agent.role,
    model: agent.modelId,
    thinkingLevel: agent.thinkingLevel,
  }));
}

function getAgentDefinition(role: string): SecurityReviewAgentDefinition {
  if (isKnownRole(role)) return SECURITY_REVIEW_AGENT_DEFINITIONS[role];
  return SECURITY_REVIEW_AGENT_DEFINITIONS.auditor;
}

function isKnownRole(role: string): role is SecurityReviewAgentRole {
  return role === "auditor" || role === "filter" || role === "reporter";
}
