import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";
import {
  categoryKeys,
  type CategoryKey,
  type CategoryState,
  type FindingConfidence,
  type ScanFinding,
  type FindingStatus,
  type Severity,
} from "@/lib/types";

const severityRank: Record<Severity, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1,
};

const severityPenalty: Record<Severity, number> = {
  critical: 28,
  high: 16,
  medium: 7,
  low: 2,
  info: 0,
};

const warningPenaltyCap: Record<Severity, number> = {
  critical: 28,
  high: 18,
  medium: 10,
  low: 4,
  info: 0,
};

const statusRank: Record<FindingStatus, number> = {
  fail: 4,
  warning: 3,
  info: 2,
  pass: 1,
};

const confidenceRank: Record<FindingConfidence, number> = {
  confirmed: 3,
  likely: 2,
  medium: 1.5,
  low: 1.2,
  info: 1,
};

const confidencePenaltyMultiplier: Record<FindingConfidence, number> = {
  confirmed: 1.25,
  likely: 0.75,
  medium: 0.45,
  low: 0.2,
  info: 0,
};

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function clamp(value: number, min: number, max: number) {
  return Math.min(Math.max(value, min), max);
}

export function average(values: Array<number | null | undefined>) {
  const defined = values.filter((value): value is number => typeof value === "number");
  if (!defined.length) {
    return null;
  }

  return Math.round(defined.reduce((sum, value) => sum + value, 0) / defined.length);
}

export function deriveFindingStatus(finding: Pick<ScanFinding, "severity"> & { status?: FindingStatus }) {
  if (finding.status) {
    return finding.status;
  }

  switch (finding.severity) {
    case "critical":
    case "high":
      return "fail";
    case "medium":
    case "low":
      return "warning";
    case "info":
    default:
      return "info";
  }
}

export function formatFindingHeader(finding: Pick<ScanFinding, "severity" | "confidence"> & { status?: FindingStatus }) {
  const status = deriveFindingStatus(finding).toUpperCase();
  const severity = finding.severity.toUpperCase();
  const confidence = (finding.confidence ?? "info").toUpperCase();
  const showSeverity = Boolean(severity && severity !== status);

  return {
    statusLabel: status,
    severityLabel: showSeverity ? severity : undefined,
    confidenceLabel: confidence,
    compact: showSeverity ? `${status} · ${severity}` : status,
  };
}

export function computeScore(findings: ScanFinding[]) {
  const warningPenaltyTotals: Record<Severity, number> = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    info: 0,
  };

  const failPenalty = findings.reduce((sum, finding) => {
    const status = deriveFindingStatus(finding);
    const confidence = finding.confidence ?? (status === "fail" || status === "warning" ? "likely" : "info");
    if (status === "pass" || status === "info" || confidence === "info") {
      return sum;
    }

    const weightedPenalty = Math.max(
      1,
      Math.round(
        severityPenalty[finding.severity] *
          (finding.scoreWeight ?? 1) *
          (status === "warning" ? 0.5 : 1) *
          confidencePenaltyMultiplier[confidence],
      ),
    );

    if (status === "warning") {
      warningPenaltyTotals[finding.severity] += weightedPenalty;
      return sum;
    }

    return sum + weightedPenalty;
  }, 0);

  const cappedWarningPenalty = (Object.keys(warningPenaltyTotals) as Severity[]).reduce(
    (sum, severity) => sum + Math.min(warningPenaltyTotals[severity], warningPenaltyCap[severity]),
    0,
  );

  return clamp(Math.round(100 - failPenalty - cappedWarningPenalty), 0, 100);
}

export function sortFindings(findings: ScanFinding[]) {
  return [...findings].sort((left, right) => {
    const statusDelta = statusRank[deriveFindingStatus(right)] - statusRank[deriveFindingStatus(left)];
    if (statusDelta !== 0) {
      return statusDelta;
    }

    const severityDelta = severityRank[right.severity] - severityRank[left.severity];
    if (severityDelta !== 0) {
      return severityDelta;
    }

    const confidenceDelta =
      confidenceRank[right.confidence ?? "info"] - confidenceRank[left.confidence ?? "info"];
    if (confidenceDelta !== 0) {
      return confidenceDelta;
    }

    return left.title.localeCompare(right.title);
  });
}

export function applyPremiumGating(findings: ScanFinding[], freeCount = 4) {
  const ordered = sortFindings(findings);
  let revealedIssues = 0;

  return ordered.map((finding) => {
    const status = deriveFindingStatus(finding);
    const isIssue = status === "warning" || status === "fail";
    const shouldGate = finding.premiumOnly || (isIssue && revealedIssues >= freeCount);
    if (isIssue) {
      revealedIssues += 1;
    }

    return {
      ...finding,
      status,
      premiumOnly: shouldGate,
    };
  });
}

export function formatDateTime(value: string) {
  return new Intl.DateTimeFormat("en", {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(new Date(value));
}

export function formatRelative(value: string) {
  const date = new Date(value);
  const seconds = Math.round((date.getTime() - Date.now()) / 1000);
  const formatter = new Intl.RelativeTimeFormat("en", { numeric: "auto" });
  const units: Array<[Intl.RelativeTimeFormatUnit, number]> = [
    ["year", 60 * 60 * 24 * 365],
    ["month", 60 * 60 * 24 * 30],
    ["week", 60 * 60 * 24 * 7],
    ["day", 60 * 60 * 24],
    ["hour", 60 * 60],
    ["minute", 60],
  ];

  for (const [unit, unitSeconds] of units) {
    if (Math.abs(seconds) >= unitSeconds) {
      return formatter.format(Math.round(seconds / unitSeconds), unit);
    }
  }

  return formatter.format(seconds, "second");
}

export function titleCaseCategory(category: CategoryKey) {
  const map: Record<CategoryKey, string> = {
    security: "Security",
    seo: "SEO",
    performance: "Performance",
  };

  return map[category];
}

export function getSeverityStyles(severity: Severity) {
  switch (severity) {
    case "critical":
      return "border-red-200 bg-red-50 text-red-700";
    case "high":
      return "border-rose-200 bg-rose-50 text-rose-700";
    case "medium":
      return "border-amber-200 bg-amber-50 text-amber-700";
    case "low":
      return "border-sky-200 bg-sky-50 text-sky-700";
    case "info":
    default:
      return "border-slate-200 bg-slate-50 text-slate-600";
  }
}

export function getStatusStyles(status: FindingStatus) {
  switch (status) {
    case "pass":
      return "border-emerald-200 bg-emerald-50 text-emerald-700";
    case "warning":
      return "border-amber-200 bg-amber-50 text-amber-700";
    case "fail":
      return "border-rose-200 bg-rose-50 text-rose-700";
    case "info":
    default:
      return "border-slate-200 bg-slate-50 text-slate-600";
  }
}

export function getConfidenceStyles(confidence: FindingConfidence) {
  switch (confidence) {
    case "confirmed":
      return "border-red-200 bg-red-50 text-red-700";
    case "likely":
      return "border-amber-200 bg-amber-50 text-amber-700";
    case "medium":
      return "border-orange-200 bg-orange-50 text-orange-700";
    case "low":
      return "border-sky-200 bg-sky-50 text-sky-700";
    case "info":
    default:
      return "border-slate-200 bg-slate-50 text-slate-600";
  }
}

export function getScoreTone(score: number | null) {
  if (score === null) {
    return "#8d9bb0";
  }
  if (score >= 85) {
    return "#0c9156";
  }
  if (score >= 65) {
    return "#1667d9";
  }
  if (score >= 45) {
    return "#d17c0f";
  }
  return "#d04646";
}

export function emptyCategoryState(timestamp: string) {
  return Object.fromEntries(
    categoryKeys.map((category) => [
      category,
      {
        status: "queued",
        score: null,
        findingCount: 0,
        updatedAt: timestamp,
        error: null,
      } satisfies CategoryState,
    ]),
  ) as Record<CategoryKey, CategoryState>;
}

export function formatScore(score: number | null) {
  return score === null ? "--" : String(score);
}
