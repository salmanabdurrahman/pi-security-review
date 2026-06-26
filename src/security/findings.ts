/** Findings model and marker JSON parsing for pi-security-review. */

import { normalizeConfidence, normalizeSeverity } from "./confidence.ts";
import { SECURITY_REVIEW_CLOSE_MARKER, SECURITY_REVIEW_OPEN_MARKER } from "./prompt.ts";

export type Severity = "HIGH" | "MEDIUM" | "LOW";
export type FindingStatus = "open" | "fixed" | "accepted" | "excluded";
export type FilterStage = "hard_rules" | "confidence" | "severity" | "model" | "parser";

export interface SecurityFinding {
  id: string;
  file: string;
  line?: number;
  severity: Severity;
  category: string;
  title: string;
  description: string;
  exploitScenario: string;
  recommendation: string;
  confidence: number;
  status: FindingStatus;
}

export interface ExcludedFinding {
  finding?: SecurityFinding;
  file?: string;
  line?: number;
  reason: string;
  filterStage: FilterStage;
  confidence?: number;
  severity?: Severity;
}

export interface AnalysisSummary {
  filesReviewed: number;
  highSeverity: number;
  mediumSeverity: number;
  lowSeverity: number;
  reviewCompleted: boolean;
  diffTruncated?: boolean;
  contextTruncated?: boolean;
  findingsTotal?: number;
  excludedFindings?: number;
  warnings?: string[];
}

export interface SecurityReviewMarkerPayload {
  findings: SecurityFinding[];
  excludedFindings: ExcludedFinding[];
  analysisSummary: AnalysisSummary;
  metadata?: SecurityReviewMetadata;
}

export interface SecurityReviewMetadata {
  model?: string;
  agents?: Array<{ role: string; model?: string; thinkingLevel?: string | null }>;
  promptChars?: number;
  contextTruncated?: boolean;
  codeReviewGraphUsed?: boolean;
  generatedAt?: string;
  [key: string]: unknown;
}

export interface MarkerJsonResult<T = SecurityReviewMarkerPayload> {
  value?: T;
  raw: string;
  startIndex: number;
  endIndex: number;
  parseError?: string;
  source?: "marker" | "raw-json" | "fenced-json";
}

export interface ParsedSecurityReviewMarkdown {
  markdown: string;
  marker?: MarkerJsonResult<SecurityReviewMarkerPayload>;
  warning?: string;
}

export function extractSecurityReviewMarkerJson<T = SecurityReviewMarkerPayload>(
  text: string,
): MarkerJsonResult<T> | undefined {
  const source = typeof text === "string" ? text : "";
  const markerMatch = /<!--\s*pi-security-review-json\s*-->/i.exec(source);
  if (markerMatch) {
    const openIndex = markerMatch.index;
    const jsonStart = openIndex + markerMatch[0].length;
    const closeMatch = /<!--\s*\/pi-security-review-json\s*-->/i.exec(source.slice(jsonStart));
    if (!closeMatch) {
      return {
        raw: "",
        startIndex: openIndex,
        endIndex: openIndex,
        parseError: `opening marker found at ${openIndex} but closing marker is missing`,
        source: "marker",
      };
    }

    const closeIndex = jsonStart + closeMatch.index;
    const raw = source.slice(jsonStart, closeIndex).trim();
    const endIndex = closeIndex + closeMatch[0].length;
    return parseJsonCandidate(raw, openIndex, endIndex, "marker");
  }

  return extractFallbackJson<T>(source);
}

export function stripSecurityReviewMarkerJson(text: string): string {
  const marker = extractSecurityReviewMarkerJson(text);
  if (!marker) return text;
  return `${text.slice(0, marker.startIndex)}${text.slice(marker.endIndex)}`.trimEnd();
}

export function buildSecurityReviewMarkerJson(payload: SecurityReviewMarkerPayload): string {
  return `${SECURITY_REVIEW_OPEN_MARKER}\n${JSON.stringify(payload, null, 2)}\n${SECURITY_REVIEW_CLOSE_MARKER}`;
}

export function parseSecurityReviewMarkdown(text: string): ParsedSecurityReviewMarkdown {
  const marker = extractSecurityReviewMarkerJson(text);
  if (!marker) return { markdown: text };

  const markdown = stripSecurityReviewMarkerJson(text);
  const sourceLabel = marker.source === "marker" ? "JSON marker" : `${marker.source} payload`;
  if (marker.parseError) {
    return {
      markdown,
      marker,
      warning: `Invalid security-review ${sourceLabel}: ${marker.parseError}`,
    };
  }
  if (!marker.value) {
    return { markdown, marker, warning: `Security-review ${sourceLabel} did not contain a value.` };
  }

  const normalized = normalizePayload(marker.value as unknown);
  const warnings = normalized.analysisSummary.warnings;
  return {
    markdown,
    marker: { ...marker, value: normalized },
    warning: warnings?.length ? warnings.join("; ") : undefined,
  };
}

export function normalizePayload(value: unknown): SecurityReviewMarkerPayload {
  const record = asRecord(value);
  const warnings = validatePayloadShape(record);
  const findings = asArray(record.findings).map((finding, index) =>
    normalizeFinding(finding, index, warnings),
  );
  const excludedFindings = asArray(record.excludedFindings ?? record.excluded_findings).map(
    (item) => normalizeExcludedFinding(item, warnings),
  );
  const analysisSummary = normalizeAnalysisSummary(
    record.analysisSummary ?? record.analysis_summary,
    findings,
    excludedFindings,
    warnings,
  );
  const metadata =
    record.metadata && typeof record.metadata === "object" ? record.metadata : undefined;

  return {
    findings,
    excludedFindings,
    analysisSummary,
    metadata: metadata as SecurityReviewMetadata | undefined,
  };
}

export function normalizeFinding(
  value: unknown,
  index = 0,
  warnings: string[] = [],
): SecurityFinding {
  const record = asRecord(value);
  const description = asString(record.description, "");
  warnMissing(
    record,
    ["file", "severity", "category", "description", "recommendation", "confidence"],
    `findings[${index}]`,
    warnings,
  );
  warnIfWrongType(record.line, "number", `findings[${index}].line`, warnings, true);
  warnIfWrongType(record.confidence, "number", `findings[${index}].confidence`, warnings);
  return {
    id: asString(record.id, `sr-${String(index + 1).padStart(3, "0")}`),
    file: asString(record.file ?? record.path ?? record.filename, "unknown"),
    line: asOptionalPositiveInteger(record.line ?? record.line_number),
    severity: normalizeSeverity(record.severity),
    category: asString(record.category, "uncategorized"),
    title: asString(
      record.title,
      description ? description.slice(0, 80) : "Untitled security finding",
    ),
    description,
    exploitScenario: asString(record.exploitScenario ?? record.exploit_scenario, ""),
    recommendation: asString(record.recommendation ?? record.remediation, ""),
    confidence: normalizeConfidence(record.confidence ?? record.confidence_score),
    status: normalizeStatus(record.status),
  };
}

export function normalizeExcludedFinding(value: unknown, warnings: string[] = []): ExcludedFinding {
  const record = asRecord(value);
  const rawFinding = record.finding;
  const finding =
    rawFinding && typeof rawFinding === "object"
      ? normalizeFinding(rawFinding, 0, warnings)
      : undefined;
  return {
    finding,
    file: asOptionalString(record.file) ?? finding?.file,
    line: asOptionalPositiveInteger(record.line) ?? finding?.line,
    reason: asString(record.reason ?? record.exclusion_reason, "Excluded by filter."),
    filterStage: normalizeFilterStage(record.filterStage ?? record.filter_stage),
    confidence: normalizeConfidence(
      record.confidence ?? record.confidence_score,
      finding?.confidence,
    ),
    severity: record.severity ? normalizeSeverity(record.severity) : finding?.severity,
  };
}

function normalizeAnalysisSummary(
  value: unknown,
  findings: SecurityFinding[],
  excludedFindings: ExcludedFinding[],
  warnings: string[],
): AnalysisSummary {
  const record = value && typeof value === "object" ? (value as Record<string, unknown>) : {};
  if (!value) warnings.push("analysisSummary/analysis_summary missing; summary counts inferred.");
  const suppliedWarnings = asOptionalStringArray(record.warnings) ?? [];
  return {
    filesReviewed: asNumber(record.filesReviewed ?? record.files_reviewed, 0),
    highSeverity: asNumber(
      record.highSeverity ?? record.high_severity,
      findings.filter((finding) => finding.severity === "HIGH").length,
    ),
    mediumSeverity: asNumber(
      record.mediumSeverity ?? record.medium_severity,
      findings.filter((finding) => finding.severity === "MEDIUM").length,
    ),
    lowSeverity: asNumber(
      record.lowSeverity ?? record.low_severity,
      findings.filter((finding) => finding.severity === "LOW").length,
    ),
    reviewCompleted: asBoolean(record.reviewCompleted ?? record.review_completed, false),
    diffTruncated: asOptionalBoolean(record.diffTruncated ?? record.diff_truncated),
    contextTruncated: asOptionalBoolean(record.contextTruncated ?? record.context_truncated),
    findingsTotal:
      asOptionalNumber(record.findingsTotal ?? record.findings_total) ?? findings.length,
    excludedFindings:
      asOptionalNumber(record.excludedFindings ?? record.excluded_findings) ??
      excludedFindings.length,
    warnings: [...suppliedWarnings, ...warnings].length
      ? [...suppliedWarnings, ...warnings]
      : undefined,
  };
}

function extractFallbackJson<T>(source: string): MarkerJsonResult<T> | undefined {
  const trimmed = source.trim();
  if (looksLikeJsonObject(trimmed)) {
    return parseJsonCandidate(
      trimmed,
      source.indexOf(trimmed),
      source.indexOf(trimmed) + trimmed.length,
      "raw-json",
    );
  }

  const fencePattern = /```(?:json|JSON)?\s*([\s\S]*?)```/g;
  for (const match of source.matchAll(fencePattern)) {
    const raw = match[1]?.trim() ?? "";
    if (!raw.startsWith("{")) continue;
    const startIndex = match.index ?? 0;
    const endIndex = startIndex + match[0].length;
    const parsed = parseJsonCandidate<T>(raw, startIndex, endIndex, "fenced-json");
    if (parsed.value || parsed.parseError) return parsed;
  }

  return undefined;
}

function parseJsonCandidate<T>(
  raw: string,
  startIndex: number,
  endIndex: number,
  source: MarkerJsonResult<T>["source"],
): MarkerJsonResult<T> {
  if (raw.length === 0)
    return { raw, startIndex, endIndex, parseError: "JSON block is empty", source };
  try {
    const value = JSON.parse(raw) as T;
    if (!hasFindingsPayloadShape(value)) {
      return {
        value,
        raw,
        startIndex,
        endIndex,
        parseError: "JSON object does not contain a findings array",
        source,
      };
    }
    return { value, raw, startIndex, endIndex, source };
  } catch (error) {
    return { raw, startIndex, endIndex, parseError: (error as Error).message, source };
  }
}

function looksLikeJsonObject(value: string): boolean {
  return value.startsWith("{") && value.endsWith("}");
}

function hasFindingsPayloadShape(value: unknown): boolean {
  const record = asRecord(value);
  return Array.isArray(record.findings);
}

function validatePayloadShape(record: Record<string, unknown>): string[] {
  const warnings: string[] = [];
  if (!Array.isArray(record.findings)) warnings.push("findings missing or not an array.");
  if (!record.analysisSummary && !record.analysis_summary) {
    warnings.push("analysisSummary/analysis_summary missing.");
  }
  if (record.excludedFindings !== undefined && !Array.isArray(record.excludedFindings)) {
    warnings.push("excludedFindings is not an array; ignored.");
  }
  if (record.excluded_findings !== undefined && !Array.isArray(record.excluded_findings)) {
    warnings.push("excluded_findings is not an array; ignored.");
  }
  return warnings;
}

function warnMissing(
  record: Record<string, unknown>,
  keys: string[],
  prefix: string,
  warnings: string[],
): void {
  for (const key of keys) {
    if (record[key] === undefined) warnings.push(`${prefix}.${key} missing; default applied.`);
  }
}

function warnIfWrongType(
  value: unknown,
  expected: "number" | "string" | "boolean",
  field: string,
  warnings: string[],
  optional = false,
): void {
  if (value === undefined && optional) return;
  if (value !== undefined && typeof value !== expected) {
    warnings.push(`${field} expected ${expected}; default applied.`);
  }
}

function asRecord(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};
}

function asArray(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

function asString(value: unknown, fallback: string): string {
  return typeof value === "string" && value.trim().length > 0 ? value.trim() : fallback;
}

function asOptionalString(value: unknown): string | undefined {
  return typeof value === "string" && value.trim().length > 0 ? value.trim() : undefined;
}

function asNumber(value: unknown, fallback: number): number {
  return typeof value === "number" && Number.isFinite(value) ? value : fallback;
}

function asOptionalNumber(value: unknown): number | undefined {
  return typeof value === "number" && Number.isFinite(value) ? value : undefined;
}

function asOptionalPositiveInteger(value: unknown): number | undefined {
  return typeof value === "number" && Number.isInteger(value) && value > 0 ? value : undefined;
}

function asBoolean(value: unknown, fallback: boolean): boolean {
  return typeof value === "boolean" ? value : fallback;
}

function asOptionalBoolean(value: unknown): boolean | undefined {
  return typeof value === "boolean" ? value : undefined;
}

function asOptionalStringArray(value: unknown): string[] | undefined {
  if (!Array.isArray(value)) return undefined;
  return value.filter((item): item is string => typeof item === "string");
}

function normalizeStatus(value: unknown): FindingStatus {
  const text = typeof value === "string" ? value.trim().toLowerCase() : "";
  if (text === "fixed" || text === "accepted" || text === "excluded") return text;
  return "open";
}

function normalizeFilterStage(value: unknown): FilterStage {
  const text = typeof value === "string" ? value.trim() : "";
  if (
    text === "hard_rules" ||
    text === "confidence" ||
    text === "severity" ||
    text === "model" ||
    text === "parser"
  ) {
    return text;
  }
  return "hard_rules";
}
