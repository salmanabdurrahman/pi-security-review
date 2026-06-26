import { expect, test } from "bun:test";
import { DEFAULT_CONFIG, validateAndMergeConfig } from "../src/config/schema.ts";
import {
  agentMetadata,
  buildAgentPromptSection,
  resolveSecurityReviewAgent,
  resolveSecurityReviewAgents,
} from "../src/security/agents.ts";

test("resolves default auditor role without storing secrets", () => {
  const agents = resolveSecurityReviewAgents(DEFAULT_CONFIG);

  expect(agents).toHaveLength(1);
  expect(agents[0]?.role).toBe("auditor");
  expect(agents[0]?.modelId).toBeUndefined();
  expect(agents[0]?.thinkingLevel).toBe("high");
  expect(JSON.stringify(agentMetadata(agents))).not.toMatch(/api[-_]?key|token|secret/i);
});

test("resolves configured auditor filter reporter profiles", () => {
  const config = validateAndMergeConfig(
    {
      agentPipeline: ["auditor", "filter", "reporter"],
      modelProfiles: {
        auditor: { provider: "anthropic", model: "claude-sonnet", thinkingLevel: "high" },
        filter: { provider: "openai", model: "gpt-4.1-mini", thinkingLevel: "medium" },
        reporter: { provider: "local", model: "qwen", thinkingLevel: "off" },
      },
    },
    ".pi/security-review.json",
  );

  const agents = resolveSecurityReviewAgents(config);
  expect(agents.map((agent) => agent.role)).toEqual(["auditor", "filter", "reporter"]);
  expect(agents.map((agent) => agent.modelId)).toEqual([
    "anthropic/claude-sonnet",
    "openai/gpt-4.1-mini",
    "local/qwen",
  ]);
  expect(agentMetadata(agents)[2]?.thinkingLevel).toBe("off");
});

test("unknown role falls back clearly to auditor prompt", () => {
  const agent = resolveSecurityReviewAgent(DEFAULT_CONFIG, "triage");

  expect(agent.role).toBe("triage");
  expect(agent.title).toBe("Security auditor");
  expect(agent.warnings.join("\n")).toContain("Unknown security-review agent role 'triage'");
});

test("agent prompt section describes deterministic fallback", () => {
  const section = buildAgentPromptSection(resolveSecurityReviewAgents(DEFAULT_CONFIG));

  expect(section).toContain("Agent role pipeline");
  expect(section).toContain("single-agent behavior stable");
  expect(section).toContain("Do not store provider secrets");
  expect(section).toContain("`auditor`");
});
