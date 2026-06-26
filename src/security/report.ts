/** Markdown and JSON renderers for security-review results. */

import type { ExcludedFinding, SecurityFinding, SecurityReviewMarkerPayload } from "./findings.ts";

export interface RenderSecurityReportOptions {
  title?: string;
  scope?: string;
  generatedAt?: string;
  model?: string;
  contextTruncated?: boolean;
  diffTruncated?: boolean;
  codeReviewGraphUsed?: boolean;
}

export interface SarifLikeExport {
  version: "2.1.0";
  $schema: "https://json.schemastore.org/sarif-2.1.0.json";
  runs: Array<{
    tool: {
      driver: {
        name: "pi-security-review";
        informationUri?: string;
        rules: Array<{
          id: string;
          name: string;
          shortDescription: { text: string };
          defaultConfiguration: { level: "error" | "warning" | "note" };
        }>;
      };
    };
    results: Array<{
      ruleId: string;
      level: "error" | "warning" | "note";
      message: { text: string };
      locations: Array<{
        physicalLocation: {
          artifactLocation: { uri: string };
          region?: { startLine: number };
        };
      }>;
      properties: { severity: string; confidence: number; status: string; findingId: string };
    }>;
  }>;
}

const SEVERITY_ORDER = ["HIGH", "MEDIUM", "LOW"] as const;

export function renderSecurityReviewMarkdown(
  payload: SecurityReviewMarkerPayload,
  options: RenderSecurityReportOptions = {},
): string {
  const summary = payload.analysisSummary;
  const findings = [...payload.findings].sort(compareFindings);
  const excluded = payload.excludedFindings;
  const high = findings.filter((finding) => finding.severity === "HIGH").length;
  const medium = findings.filter((finding) => finding.severity === "MEDIUM").length;
  const title = options.title ?? "Security Review";
  const diffTruncated = options.diffTruncated ?? summary.diffTruncated ?? false;
  const contextTruncated = options.contextTruncated ?? summary.contextTruncated ?? false;
  const model = options.model ?? payload.metadata?.model;

  const parts: string[] = [];
  parts.push(`# ${title}`);
  parts.push("");
  parts.push("## Summary");
  parts.push("");
  parts.push(`- Files reviewed: ${summary.filesReviewed}`);
  parts.push(`- Findings: ${high} high, ${medium} medium`);
  if (options.scope) parts.push(`- Scope: ${options.scope}`);
  parts.push(`- Truncation: ${formatTruncation(diffTruncated, contextTruncated)}`);
  if (summary.reviewCompleted === false) parts.push("- Review completed: false");
  parts.push("");

  if (findings.length > 0) {
    parts.push("## Findings");
    parts.push("");
    for (const severity of SEVERITY_ORDER) {
      const group = findings.filter((finding) => finding.severity === severity);
      if (group.length === 0 || severity === "LOW") continue;
      for (const finding of group) parts.push(...renderFinding(finding));
    }
  } else {
    parts.push("## Findings");
    parts.push("");
    parts.push("No high-confidence HIGH/MEDIUM findings found.");
    parts.push("");
  }

  parts.push("## Excluded / filtered notes");
  parts.push("");
  if (excluded.length > 0) {
    for (const line of summarizeExcluded(excluded)) parts.push(`- ${line}`);
  } else {
    parts.push("- No findings excluded by deterministic filters.");
  }
  parts.push("");

  parts.push("## Metadata");
  parts.push("");
  if (model) parts.push(`- Model: ${model}`);
  const agents = payload.metadata?.agents;
  if (agents?.length) parts.push(`- Agents: ${agents.map(formatAgentMetadata).join(", ")}`);
  if (options.generatedAt ?? payload.metadata?.generatedAt) {
    parts.push(`- Generated at: ${options.generatedAt ?? payload.metadata?.generatedAt}`);
  }
  parts.push(`- Context truncated: ${contextTruncated ? "yes" : "no"}`);
  parts.push(`- Diff truncated: ${diffTruncated ? "yes" : "no"}`);
  const codeReviewGraphUsed = options.codeReviewGraphUsed ?? payload.metadata?.codeReviewGraphUsed;
  if (codeReviewGraphUsed !== undefined) {
    parts.push(`- Code review graph used: ${codeReviewGraphUsed ? "yes" : "no"}`);
  }

  while (parts.length > 0 && parts[parts.length - 1] === "") parts.pop();
  return parts.join("\n");
}

export function renderSarifLikeJson(payload: SecurityReviewMarkerPayload): SarifLikeExport {
  const rules = [...new Set(payload.findings.map((finding) => finding.category))]
    .sort()
    .map((category) => {
      const finding = payload.findings.find((item) => item.category === category);
      const level = finding ? sarifLevel(finding.severity) : "warning";
      return {
        id: category,
        name: category,
        shortDescription: { text: `pi-security-review ${category}` },
        defaultConfiguration: { level },
      };
    });

  return {
    version: "2.1.0",
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    runs: [
      {
        tool: {
          driver: {
            name: "pi-security-review",
            informationUri: "https://github.com/salmanabdurrahman/pi-security-review",
            rules,
          },
        },
        results: payload.findings.map((finding) => ({
          ruleId: finding.category,
          level: sarifLevel(finding.severity),
          message: { text: finding.title },
          locations: [
            {
              physicalLocation: {
                artifactLocation: { uri: finding.file },
                region: finding.line ? { startLine: finding.line } : undefined,
              },
            },
          ],
          properties: {
            severity: finding.severity,
            confidence: finding.confidence,
            status: finding.status,
            findingId: finding.id,
          },
        })),
      },
    ],
  };
}

function sarifLevel(severity: SecurityFinding["severity"]): "error" | "warning" | "note" {
  if (severity === "HIGH") return "error";
  if (severity === "MEDIUM") return "warning";
  return "note";
}

function renderFinding(finding: SecurityFinding): string[] {
  const location = finding.line ? `${finding.file}:${finding.line}` : finding.file;
  return [
    `### ${finding.severity}: ${finding.title} in \`${location}\``,
    "",
    `- Category: \`${finding.category}\``,
    `- Confidence: ${finding.confidence.toFixed(2)}`,
    `- Description: ${finding.description}`,
    `- Exploit scenario: ${finding.exploitScenario}`,
    `- Recommendation: ${finding.recommendation}`,
    "",
  ];
}

function formatAgentMetadata(agent: {
  role: string;
  model?: string;
  thinkingLevel?: string | null;
}): string {
  const model = agent.model ?? "active Pi model";
  const thinking = agent.thinkingLevel ?? "Pi default/current";
  return `${agent.role}=${model}, thinking=${thinking}`;
}

function summarizeExcluded(excluded: readonly ExcludedFinding[]): string[] {
  const counts = new Map<string, number>();
  for (const finding of excluded) counts.set(finding.reason, (counts.get(finding.reason) ?? 0) + 1);
  return [...counts.entries()]
    .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
    .map(([reason, count]) => `${count} ${count === 1 ? "finding" : "findings"}: ${reason}`);
}

function compareFindings(a: SecurityFinding, b: SecurityFinding): number {
  const severityDiff = severityRank(b.severity) - severityRank(a.severity);
  if (severityDiff !== 0) return severityDiff;
  const confidenceDiff = b.confidence - a.confidence;
  if (confidenceDiff !== 0) return confidenceDiff;
  return `${a.file}:${a.line ?? 0}`.localeCompare(`${b.file}:${b.line ?? 0}`);
}

function severityRank(severity: SecurityFinding["severity"]): number {
  if (severity === "HIGH") return 3;
  if (severity === "MEDIUM") return 2;
  return 1;
}

function formatTruncation(diffTruncated: boolean, contextTruncated: boolean): string {
  if (diffTruncated && contextTruncated) return "diff and context truncated";
  if (diffTruncated) return "diff truncated";
  if (contextTruncated) return "context truncated";
  return "none";
}
