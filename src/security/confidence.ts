/** Confidence and severity helpers for security-review findings. */

import type { SecurityFinding, Severity } from "./findings.ts";

export interface ConfidenceFilterOptions {
  threshold: number;
  severityThreshold: "high" | "medium";
}

const SEVERITY_RANK: Record<Severity, number> = {
  LOW: 1,
  MEDIUM: 2,
  HIGH: 3,
};

export function normalizeConfidence(value: unknown, fallback = 0): number {
  if (typeof value !== "number" || !Number.isFinite(value)) return fallback;
  const normalized = value > 1 && value <= 10 ? value / 10 : value;
  return Math.min(1, Math.max(0, normalized));
}

export function normalizeSeverity(value: unknown): Severity {
  const text = typeof value === "string" ? value.trim().toUpperCase() : "";
  if (text === "HIGH" || text === "MEDIUM" || text === "LOW") return text;
  return "LOW";
}

export function severityMeetsThreshold(severity: Severity, threshold: "high" | "medium"): boolean {
  const required: Severity = threshold === "high" ? "HIGH" : "MEDIUM";
  return SEVERITY_RANK[severity] >= SEVERITY_RANK[required];
}

export function confidenceMeetsThreshold(confidence: number, threshold: number): boolean {
  return normalizeConfidence(confidence) >= Math.min(1, Math.max(0, threshold));
}

export function findingMeetsSignalThreshold(
  finding: SecurityFinding,
  options: ConfidenceFilterOptions,
): boolean {
  return (
    confidenceMeetsThreshold(finding.confidence, options.threshold) &&
    severityMeetsThreshold(finding.severity, options.severityThreshold)
  );
}
