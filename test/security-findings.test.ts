import { describe, expect, test } from "bun:test";
import { DEFAULT_CONFIG } from "../src/config/schema.ts";
import { filterFindings, getHardExclusion } from "../src/security/filters.ts";
import {
  buildSecurityReviewMarkerJson,
  parseSecurityReviewMarkdown,
  type SecurityFinding,
  type SecurityReviewMarkerPayload,
} from "../src/security/findings.ts";
import { renderSarifLikeJson, renderSecurityReviewMarkdown } from "../src/security/report.ts";

function finding(overrides: Partial<SecurityFinding> = {}): SecurityFinding {
  return {
    id: "sr-001",
    file: "src/auth.ts",
    line: 42,
    severity: "HIGH",
    category: "auth_bypass",
    title: "Authorization bypass",
    description: "Server-side authorization check can be bypassed.",
    exploitScenario: "Attacker sends request for another tenant and receives private data.",
    recommendation: "Check tenant authorization before returning data.",
    confidence: 0.92,
    status: "open",
    ...overrides,
  };
}

describe("hard exclusion filters", () => {
  test("exclude low-signal finding classes required by Phase 6", () => {
    const cases: Array<[string, SecurityFinding, string]> = [
      [
        "dos",
        finding({ title: "Denial of Service", description: "Resource exhaustion possible." }),
        "DOS/resource exhaustion",
      ],
      [
        "rate limiting",
        finding({ title: "Missing rate limit", description: "Add rate limiting." }),
        "rate limiting",
      ],
      [
        "resource leak",
        finding({
          title: "Connection leak",
          description: "Database connection leak.",
          exploitScenario: "Long-running process keeps connections open.",
          recommendation: "Close connections after use.",
        }),
        "Resource management",
      ],
      ["docs", finding({ file: "docs/security.md" }), "Documentation-only"],
      ["tests", finding({ file: "test/auth.test.ts" }), "Tests-only"],
      [
        "regex",
        finding({
          title: "Regex injection",
          description: "User input controls regular expression.",
        }),
        "Regex",
      ],
      [
        "open redirect",
        finding({ title: "Open redirect", description: "Unvalidated redirect parameter." }),
        "Open redirect",
      ],
      [
        "ssrf path only",
        finding({ title: "SSRF", description: "Attacker controls URL path only." }),
        "SSRF",
      ],
      [
        "frontend auth",
        finding({
          file: "src/components/Login.tsx",
          title: "Frontend auth missing",
          description: "Client-side auth check missing in browser component.",
        }),
        "Frontend-only auth",
      ],
      [
        "react xss safe default",
        finding({
          file: "src/components/Profile.tsx",
          title: "React XSS",
          description: "Cross-site scripting possible in React rendering.",
          exploitScenario: "Attacker controls display name shown in component.",
          recommendation: "Keep React default escaping enabled.",
        }),
        "React/Angular XSS",
      ],
      [
        "github action no path",
        finding({
          file: ".github/workflows/ci.yml",
          title: "Workflow injection",
          description: "Potential script injection in workflow.",
        }),
        "GitHub Actions",
      ],
      [
        "shell no input",
        finding({
          file: "scripts/deploy.sh",
          title: "Shell command injection",
          description: "Command injection may be possible.",
        }),
        "Shell command injection",
      ],
    ];

    for (const [, item, reason] of cases) {
      const result = getHardExclusion(item);
      expect(result.excluded).toBe(true);
      expect(result.reason).toContain(reason);
    }
  });

  test("keep concrete high-impact variants", () => {
    const kept = [
      finding({
        title: "Open redirect leaks OAuth code",
        description: "Open redirect sends OAuth auth code token to attacker domain.",
      }),
      finding({
        file: "src/components/Profile.tsx",
        title: "React XSS via dangerouslySetInnerHTML",
        description: "User HTML reaches dangerouslySetInnerHTML.",
        exploitScenario: "Attacker stores HTML that renders in victim browser.",
        recommendation: "Sanitize user HTML before rendering.",
      }),
      finding({
        file: ".github/workflows/ci.yml",
        title: "pull_request_target command injection",
        description:
          "pull_request_target workflow executes attacker-controlled PR title in run step.",
      }),
      finding({
        file: "scripts/build.sh",
        title: "Shell command injection",
        description: "Command injection through attacker-controlled argv input.",
      }),
    ];

    for (const item of kept) expect(getHardExclusion(item).excluded).toBe(false);
  });
});

describe("finding filtering", () => {
  test("applies confidence and severity thresholds", () => {
    const result = filterFindings(
      [
        finding({ id: "sr-high", confidence: 0.91, severity: "HIGH" }),
        finding({ id: "sr-low-confidence", confidence: 0.4, severity: "HIGH" }),
        finding({ id: "sr-low-severity", confidence: 0.99, severity: "LOW" }),
      ],
      { config: DEFAULT_CONFIG },
    );

    expect(result.findings.map((item) => item.id)).toEqual(["sr-high"]);
    expect(result.summary.confidenceExcluded).toBe(1);
    expect(result.summary.severityExcluded).toBe(1);
    expect(result.summary.highSeverity).toBe(1);
  });
});

describe("marker parser and renderer", () => {
  test("invalid JSON marker warns without crashing", () => {
    const parsed = parseSecurityReviewMarkdown(
      "# Security Review\n\n<!-- pi-security-review-json -->\n{ nope\n<!-- /pi-security-review-json -->",
    );

    expect(parsed.markdown).toBe("# Security Review");
    expect(parsed.warning).toContain("Invalid security-review JSON marker");
    expect(parsed.marker?.parseError).toBeTruthy();
  });

  test("valid marker normalizes payload", () => {
    const marker = buildSecurityReviewMarkerJson({
      findings: [finding({ severity: "MEDIUM", confidence: 9 as unknown as number })],
      excludedFindings: [],
      analysisSummary: {
        filesReviewed: 1,
        highSeverity: 0,
        mediumSeverity: 1,
        lowSeverity: 0,
        reviewCompleted: true,
      },
    });

    const parsed = parseSecurityReviewMarkdown(`# Security Review\n\n${marker}`);
    expect(parsed.warning).toBeUndefined();
    expect(parsed.marker?.value?.findings[0]?.confidence).toBe(0.9);
    expect(parsed.marker?.value?.findings[0]?.severity).toBe("MEDIUM");
  });

  test("normalizes reference-style snake_case JSON", () => {
    const parsed = parseSecurityReviewMarkdown(`{
      "findings": [
        {
          "file": "src/api.py",
          "line": 42,
          "severity": "HIGH",
          "category": "sql_injection",
          "description": "User input reaches raw SQL.",
          "exploit_scenario": "Attacker passes ' OR 1=1 -- to search and reads private rows.",
          "recommendation": "Use parameterized queries.",
          "confidence": 0.95
        }
      ],
      "analysis_summary": {
        "files_reviewed": 8,
        "high_severity": 1,
        "medium_severity": 0,
        "low_severity": 0,
        "review_completed": true
      }
    }`);

    expect(parsed.warning).toBeUndefined();
    expect(parsed.marker?.source).toBe("raw-json");
    expect(parsed.marker?.value?.analysisSummary.filesReviewed).toBe(8);
    expect(parsed.marker?.value?.analysisSummary.highSeverity).toBe(1);
    expect(parsed.marker?.value?.findings[0]?.exploitScenario).toContain("OR 1=1");
    expect(parsed.marker?.value?.findings[0]?.title).toBe("User input reaches raw SQL.");
  });

  test("parses fenced JSON and whitespace marker variants", () => {
    const fenced = parseSecurityReviewMarkdown(
      'Result:\n```json\n{"findings":[],"analysis_summary":{"files_reviewed":2,"review_completed":true}}\n```\n',
    );
    expect(fenced.marker?.source).toBe("fenced-json");
    expect(fenced.marker?.value?.analysisSummary.filesReviewed).toBe(2);

    const marked = parseSecurityReviewMarkdown(
      '# Review\n<!--   pi-security-review-json   -->\n{"findings":[],"analysis_summary":{"files_reviewed":3,"review_completed":true}}\n<!--   /pi-security-review-json   -->',
    );
    expect(marked.marker?.source).toBe("marker");
    expect(marked.marker?.value?.analysisSummary.filesReviewed).toBe(3);
    expect(marked.markdown).toBe("# Review");
  });

  test("schema validation warnings are actionable", () => {
    const parsed = parseSecurityReviewMarkdown(`{
      "findings": [{ "file": "src/app.ts", "confidence": "high" }],
      "analysis_summary": { "files_reviewed": 4, "review_completed": true }
    }`);

    expect(parsed.warning).toContain("findings[0].severity missing");
    expect(parsed.warning).toContain("findings[0].confidence expected number");
    expect(parsed.marker?.value?.analysisSummary.filesReviewed).toBe(4);
  });

  test("malformed fallback JSON warns without crashing", () => {
    const parsed = parseSecurityReviewMarkdown("```json\n{ nope\n```");

    expect(parsed.marker?.source).toBe("fenced-json");
    expect(parsed.warning).toContain("Invalid security-review fenced-json payload");
  });

  test("renders stable markdown and valid SARIF", () => {
    const payload: SecurityReviewMarkerPayload = {
      findings: [finding()],
      excludedFindings: [
        {
          finding: finding({ id: "sr-002", title: "Missing rate limit" }),
          file: "src/api.ts",
          line: 12,
          reason: "Generic rate limiting recommendation",
          filterStage: "hard_rules",
          confidence: 0.8,
          severity: "MEDIUM",
        },
      ],
      analysisSummary: {
        filesReviewed: 2,
        highSeverity: 1,
        mediumSeverity: 0,
        lowSeverity: 0,
        reviewCompleted: true,
        diffTruncated: false,
        contextTruncated: true,
      },
      metadata: { model: "local/qwen", codeReviewGraphUsed: false },
    };

    expect(renderSecurityReviewMarkdown(payload, { scope: "unstaged" })).toBe(`# Security Review

## Summary

> 🚨 1 high-severity finding need attention.

| Metric | Value |
| --- | ---: |
| Files reviewed | 2 |
| Findings | 1 high, 0 medium |
| Scope | unstaged |
| Truncation | context truncated |

## Findings

### HIGH (1)

<details open>
<summary><strong>HIGH</strong>: Authorization bypass — <code>src/auth.ts:42</code></summary>

| Field | Value |
| --- | --- |
| Category | \`auth_bypass\` |
| Confidence | 0.92 |

**Description**  
Server-side authorization check can be bypassed.

**Exploit scenario**  
Attacker sends request for another tenant and receives private data.

**Recommendation**  
Check tenant authorization before returning data.

</details>

<details>
<summary>Excluded / filtered notes</summary>

- 1 finding: Generic rate limiting recommendation

</details>

<details>
<summary>Metadata</summary>

- Model: local/qwen
- Context truncated: yes
- Diff truncated: no
- Code review graph used: no

</details>`);

    const sarif = renderSarifLikeJson(payload);
    expect(sarif.version).toBe("2.1.0");
    expect(sarif.$schema).toBe("https://json.schemastore.org/sarif-2.1.0.json");
    expect(sarif.runs[0]?.tool.driver.rules[0]).toMatchObject({
      id: "auth_bypass",
      defaultConfiguration: { level: "error" },
    });
    expect(sarif.runs[0]?.results[0]?.level).toBe("error");
    expect(sarif.runs[0]?.results[0]?.properties.findingId).toBe("sr-001");
  });
});
