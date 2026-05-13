"use client";

import type { CSSProperties } from "react";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { startTransition, useEffect, useMemo, useState } from "react";
import { CheckCircle2, Clock3, Download, FileText, History, Search, Shield, Wrench, X } from "lucide-react";
import { PaypalScansDialog } from "@/components/billing/paypal-scans-dialog";
import { FindingCard } from "@/components/results/finding-card";
import { useAuth } from "@/components/providers/auth-provider";
import { dispatchQuotaRefresh } from "@/lib/quota-events";
import {
  categoryKeys,
  type CategoryKey,
  type ScanEvent,
  type ScanFinding,
  type ScanRecord,
  type ScanQuotaSummary,
  type ScanSummaryResponse,
} from "@/lib/types";
import {
  cn,
  deriveFindingStatus,
  formatFindingHeader,
  formatRelative,
  formatScore,
  getConfidenceStyles,
  getScoreTone,
  getStatusStyles,
  sortFindings,
  titleCaseCategory,
} from "@/lib/utils";

type SidebarScan = Pick<
  ScanRecord,
  "id" | "targetHostname" | "createdAt" | "status" | "overallScore" | "progress"
>;

type ProgressSessionState = {
  scanId: string | null;
  sawLiveState: boolean;
};

type ProgressStepStatus = "queued" | "running" | "completed" | "failed";

type ProgressStep = {
  label: string;
  status: ProgressStepStatus;
  active: boolean;
};

type ViewState = {
  scan: ScanRecord | null;
  findings: Record<CategoryKey, ScanFinding[]>;
  events: ScanEvent[];
  recentScans: SidebarScan[];
  viewerCanAccessFixes: boolean;
  sessionUserId: string | null;
  error: string | null;
};

function emptyFindings() {
  return {
    security: [],
    seo: [],
    performance: [],
  } as Record<CategoryKey, ScanFinding[]>;
}

function sanitizeFilename(value: string) {
  const normalized = value
    .toLowerCase()
    .replace(/^https?:\/\//, "")
    .replace(/^www\./, "")
    .replace(/[^a-z0-9.-]+/g, "-")
    .replace(/^-+|-+$/g, "");

  return normalized || "scan-report";
}

function buildPdfFilename(scan: ScanRecord) {
  const stamp = new Date(scan.updatedAt).toISOString().slice(0, 10);
  return `${sanitizeFilename(scan.targetHostname)}-${stamp}.pdf`;
}

function formatScorePercent(score: number | null) {
  return score === null ? "--" : `${formatScore(score)}%`;
}

function computeDisplayOverallScore(
  securityScore: number | null,
  seoScore: number | null,
  performanceScore: number | null,
  fallbackOverallScore: number | null,
) {
  const weightedScores = [
    { score: securityScore, weight: 0.7 },
    { score: seoScore, weight: 0.15 },
    { score: performanceScore, weight: 0.15 },
  ].filter((entry): entry is { score: number; weight: number } => typeof entry.score === "number");

  if (!weightedScores.length) {
    return fallbackOverallScore;
  }

  const weightTotal = weightedScores.reduce((sum, entry) => sum + entry.weight, 0);
  let score = Math.round(
    weightedScores.reduce((sum, entry) => sum + entry.score * entry.weight, 0) / weightTotal,
  );

  if (typeof securityScore === "number") {
    if (securityScore <= 25) {
      score = Math.min(score, 45);
    } else if (securityScore <= 40) {
      score = Math.min(score, 58);
    } else if (securityScore <= 60) {
      score = Math.min(score, 72);
    }
  }

  return Math.max(0, Math.min(100, score));
}

function summarizeFindingCounts(findings: ScanFinding[]) {
  return findings.reduce(
    (summary, finding) => {
      const status = deriveFindingStatus(finding);
      if (status === "pass" || status === "info") {
        summary.passCount += 1;
      } else {
        summary.failCount += 1;
      }
      return summary;
    },
    {
      passCount: 0,
      failCount: 0,
    },
  );
}

function getLiveProgressHoldPercent(scanId: string | null) {
  if (!scanId) {
    return 98;
  }

  let hash = 0;
  for (const char of scanId) {
    hash = (hash * 31 + char.charCodeAt(0)) % 997;
  }

  return 97 + (hash % 3);
}

function getLiveProgressTarget(rawProgress: number, holdPercent: number) {
  if (rawProgress >= 95) {
    return holdPercent;
  }

  return Math.min(holdPercent, Math.max(12, rawProgress + 18));
}

function getProgressAnimationDelay(progress: number, target: number, isFinished: boolean) {
  if (isFinished) {
    return progress >= 99 ? 540 : 260;
  }

  const milestoneHolds = new Set([18, 32, 47, 63, 78, 90, Math.max(92, target - 1)]);
  if (milestoneHolds.has(progress)) {
    return progress >= 90 ? 1450 : 900;
  }

  if (progress < 35) {
    return 145;
  }

  if (progress < 70) {
    return 225;
  }

  if (progress < 90) {
    return 340;
  }

  return 520;
}

function formatProgressStatus(status: ProgressStepStatus) {
  switch (status) {
    case "completed":
      return "done";
    case "running":
      return "running";
    case "failed":
      return "failed";
    case "queued":
      return "waiting";
  }
}

function isAttackSurfaceSummaryFinding(finding: ScanFinding) {
  return finding.checkKey === "attack-surface-summary";
}

function reportableFindingsForCategory(findings: ScanFinding[]) {
  return findings.filter((finding) => !isAttackSurfaceSummaryFinding(finding));
}

function compactReportValue(value: unknown, maxLength = 120) {
  if (value === null || value === undefined || value === "") {
    return "";
  }

  const raw =
    typeof value === "string" || typeof value === "number" || typeof value === "boolean"
      ? String(value)
      : JSON.stringify(value);
  const compact = raw.replace(/\s+/g, " ").trim();
  return compact.length > maxLength ? `${compact.slice(0, maxLength - 1).trimEnd()}...` : compact;
}

function evidenceLinesForReport(finding: ScanFinding, maxLines = 5) {
  if (finding.locked) {
    return [];
  }

  const evidence = finding.evidence ?? {};
  const authBypassEvidence =
    evidence.authBypassEvidence && typeof evidence.authBypassEvidence === "object" && !Array.isArray(evidence.authBypassEvidence)
      ? (evidence.authBypassEvidence as Record<string, unknown>)
      : null;
  if (authBypassEvidence) {
    return [
      `Login endpoint: ${compactReportValue(authBypassEvidence.loginEndpoint, 120)}`,
      `Payload preview: ${compactReportValue(authBypassEvidence.payloadPreview, 80)}`,
      `Response status: ${compactReportValue(authBypassEvidence.responseStatus, 20)}`,
      `Session artifact: ${compactReportValue(authBypassEvidence.sessionArtifactType, 40)}`,
      `Authentication model: ${compactReportValue(authBypassEvidence.authModel, 40)}`,
      `Verification endpoint: ${compactReportValue(authBypassEvidence.verificationEndpoint, 120)}`,
      `Verification status: ${compactReportValue(authBypassEvidence.verificationStatus, 20)}`,
      `Verification result: ${compactReportValue(authBypassEvidence.verificationResult, 80)}`,
      authBypassEvidence.tokenPreview ? `Token preview: ${compactReportValue(authBypassEvidence.tokenPreview, 40)}` : "",
    ].filter(Boolean).slice(0, maxLines);
  }

  const lines = [
    typeof evidence.summary === "string" ? `Proof: ${evidence.summary}` : "",
    typeof evidence.checkedUrl === "string" ? `URL: ${compactReportValue(evidence.checkedUrl, 180)}` : "",
    typeof evidence.parameter === "string" ? `Parameter: ${evidence.parameter}` : "",
    evidence.beforeStatus !== undefined || evidence.afterStatus !== undefined
      ? `Status: ${compactReportValue(evidence.beforeStatus ?? "n/a", 24)} -> ${compactReportValue(evidence.afterStatus ?? "n/a", 24)}`
      : "",
    typeof evidence.responseDiff === "string" ? `Response diff: ${compactReportValue(evidence.responseDiff, 120)}` : "",
    typeof evidence.confidence === "string" ? `Evidence confidence: ${evidence.confidence}` : "",
  ].filter(Boolean);

  const resultItems = Array.isArray(evidence.results)
    ? evidence.results.slice(0, 3)
    : Array.isArray(evidence.activeProbes)
      ? evidence.activeProbes.slice(0, 3)
      : [];

  resultItems.forEach((item, index) => {
    if (!item || typeof item !== "object") {
      return;
    }

    const row = item as Record<string, unknown>;
    const parts = [
      row.url ? `url=${compactReportValue(row.url, 120)}` : "",
      row.parameter ? `param=${compactReportValue(row.parameter, 40)}` : "",
      row.payload ? `payload=${compactReportValue(row.payload, 56)}` : "",
      row.baselineStatus ? `before=${row.baselineStatus}` : "",
      row.status ? `after=${row.status}` : "",
      row.baselineRecordCount !== undefined ? `baselineRecords=${row.baselineRecordCount}` : "",
      row.probeRecordCount !== undefined ? `probeRecords=${row.probeRecordCount}` : "",
      row.recordExpansion ? "responseDiff=record-expansion" : "",
      row.sqlError ? "sqlError=true" : "",
      row.timeDelay ? "timeDelay=true" : "",
      row.executed ? "executed=true" : "",
    ].filter(Boolean);

    if (parts.length > 0) {
      lines.push(`Probe ${index + 1}: ${parts.join(", ")}`);
    }
  });

  return lines.slice(0, maxLines);
}

function numericEvidence(evidence: Record<string, unknown>, key: string) {
  const value = evidence[key];
  return typeof value === "number" && Number.isFinite(value) ? value : 0;
}

function stringEvidence(evidence: Record<string, unknown>, key: string) {
  const value = evidence[key];
  return typeof value === "string" ? value : "";
}

function objectEvidence(value: unknown) {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

function nestedRecord(value: Record<string, unknown> | null, key: string) {
  return value ? objectEvidence(value[key]) : null;
}

function nestedNumber(value: Record<string, unknown> | null, key: string) {
  const entry = value?.[key];
  return typeof entry === "number" && Number.isFinite(entry) ? entry : 0;
}

function nestedString(value: Record<string, unknown> | null, key: string) {
  const entry = value?.[key];
  return typeof entry === "string" ? entry : "";
}

function arrayRecords(value: unknown) {
  return Array.isArray(value)
    ? value.filter((entry): entry is Record<string, unknown> => Boolean(entry && typeof entry === "object" && !Array.isArray(entry)))
    : [];
}

function recommendationLabelFrom(item: Record<string, unknown> | null, explicitLabel?: string) {
  if (explicitLabel === "Recommended first fix" || explicitLabel === "Recommended first review") {
    return explicitLabel;
  }

  return item?.confidence === "confirmed" && item?.isFixableVulnerability === true
    ? "Recommended first fix"
    : "Recommended first review";
}

function getScanModeLimitations(scanMode: string) {
  if (scanMode === "Deep") {
    return {
      title: "Deep Mode Coverage",
      summary:
        "Deep mode enabled expanded crawling, repeated blind SQLi probes, XSS execution verification, and broader endpoint testing.",
      bullets: [
        "Crawling and endpoint discovery use a larger budget than Fast mode.",
        "Blind SQL injection probes may use repeated baseline/control/test requests.",
        "XSS execution verification is attempted where render locations are discovered.",
        "Authenticated and role-aware proof still depends on provided credentials or sessions.",
      ],
    };
  }

  if (scanMode === "Authenticated") {
    return {
      title: "Authenticated Mode Coverage",
      summary:
        "Authenticated mode used provided credentials/session contexts for protected endpoint, role-based, and authorization testing.",
      bullets: [
        "Protected API checks use the supplied authentication material.",
        "Role-based testing improves when userA, userB, and admin contexts are all provided.",
        "IDOR confirmation still requires cross-user ownership proof.",
        "Tokens and cookies are masked in stored report output.",
      ],
    };
  }

  return {
    title: "Fast Mode Limitations",
    summary:
      "This scan ran in Fast mode. Fast mode prioritizes quick coverage and safe bounded probes. Some deeper checks may be skipped, reduced, or reported as coverage notes instead of confirmed findings.",
    bullets: [
      "Rate-limit probing was deferred or reduced.",
      "Time-based blind SQL injection checks were limited or skipped.",
      "Role-based testing is partial unless userA, userB, and admin contexts are provided.",
      "IDOR confirmation requires two separate user contexts for ownership proof.",
      "Stored XSS execution depends on discovering the page where stored content renders.",
      "Crawling depth and endpoint discovery are bounded.",
      "Some INFO findings represent coverage limitations, not proof that a risk does not exist.",
    ],
  };
}

function primaryAttackPathFrom(evidence: Record<string, unknown>, reportSummary: Record<string, unknown> | null) {
  const summaryPath = objectEvidence(reportSummary?.primaryAttackPath);
  if (summaryPath) {
    return summaryPath;
  }

  const evidencePath = objectEvidence(evidence.primaryAttackPath);
  if (evidencePath) {
    return evidencePath;
  }

  return arrayRecords(evidence.attackPaths)[0] ?? null;
}

function confirmedAttackSteps(path: Record<string, unknown> | null) {
  if (!path) {
    return [];
  }

  const confirmed = arrayRecords(path.confirmedSteps);
  if (confirmed.length > 0) {
    return confirmed.filter((step) => String(step.confidence ?? "").toLowerCase() === "confirmed");
  }

  return arrayRecords(path.steps).filter((step) => String(step.confidence ?? "").toLowerCase() === "confirmed");
}

function likelyAttackExtensions(path: Record<string, unknown> | null) {
  if (!path) {
    return [];
  }

  const likely = arrayRecords(path.likelyExtensions);
  if (likely.length > 0) {
    return likely;
  }

  return arrayRecords(path.steps).filter((step) => String(step.confidence ?? "").toLowerCase() === "likely");
}

function accessMatrixCellLabel(cell: unknown) {
  const record = objectEvidence(cell);
  if (!record) {
    return "not-tested";
  }

  const status = typeof record.status === "number" && record.status > 0 ? `${record.status} ` : "";
  const responseClass = nestedString(record, "responseClass") || "not-tested";
  return `${status}${responseClass}`.trim();
}

function accessMatrixIsPartial(rows: Record<string, unknown>[]) {
  return rows.some((row) => {
    const issue = nestedString(row, "issue") || nestedString(row, "issueType");
    return (
      issue === "partial-coverage" ||
      accessMatrixCellLabel(row.userA) === "not-tested" ||
      accessMatrixCellLabel(row.userB) === "not-tested" ||
      accessMatrixCellLabel(row.admin) === "not-tested"
    );
  });
}

function findingHasConcreteTarget(finding: ScanFinding) {
  const evidence = finding.evidence ?? {};
  return Boolean(
    finding.affectedUrl ||
      finding.affectedParameter ||
      (typeof evidence.checkedUrl === "string" && evidence.checkedUrl.trim()) ||
      (typeof evidence.url === "string" && evidence.url.trim()) ||
      finding.structuredEvidence?.some((entry) => entry.url || entry.parameter),
  );
}

function isConcreteFixableFinding(finding: ScanFinding) {
  const status = deriveFindingStatus(finding);
  const title = `${finding.title} ${finding.checkKey ?? ""}`.toLowerCase();
  const findingClass = String(finding.findingClass ?? "").toLowerCase();
  const isMeta =
    finding.isMetaFinding === true ||
    findingClass.includes("attack-path") ||
    title.includes("attack path analysis") ||
    title.includes("authenticated session context") ||
    title.includes("session model") ||
    title.includes("role-based access matrix") ||
    title.includes("browser-rendered crawl coverage") ||
    title.includes("technology fingerprinting") ||
    title.includes("attack surface summary") ||
    title.includes("authentication surface review");

  return (
    status !== "pass" &&
    status !== "info" &&
    finding.isExploitSupportingEvidence !== true &&
    !isMeta &&
    findingHasConcreteTarget(finding)
  );
}

function isMetaOrSupportingFinding(finding: ScanFinding) {
  const title = `${finding.title} ${finding.checkKey ?? ""}`.toLowerCase();
  const findingClass = String(finding.findingClass ?? "").toLowerCase();

  return (
    finding.isMetaFinding === true ||
    finding.isExploitSupportingEvidence === true ||
    findingClass.includes("attack-path") ||
    title.includes("attack path analysis") ||
    title.includes("authenticated session context") ||
    title.includes("session model") ||
    title.includes("role-based access matrix") ||
    title.includes("browser-rendered crawl coverage") ||
    title.includes("technology fingerprinting") ||
    title.includes("attack surface summary")
  );
}

function isConfirmedExploitableFinding(finding: ScanFinding) {
  return (
    (finding.isFixableVulnerability === true ||
      (finding.isFixableVulnerability !== false && isConcreteFixableFinding(finding))) &&
    finding.confidence === "confirmed" &&
    deriveFindingStatus(finding) === "fail" &&
    isConcreteFixableFinding(finding)
  );
}

function isInvalidFixTitle(title: string) {
  const normalizedTitle = title.toLowerCase();

  if (normalizedTitle.includes("fix browser-rendered crawl coverage")) {
    return false;
  }

  return (
    !normalizedTitle ||
    normalizedTitle.includes("attack path analysis") ||
    normalizedTitle.includes("authenticated session context") ||
    normalizedTitle.includes("session model") ||
    normalizedTitle.includes("role-based access matrix") ||
    normalizedTitle.includes("browser-rendered crawl coverage") ||
    normalizedTitle.includes("technology fingerprinting") ||
    normalizedTitle.includes("attack surface summary")
  );
}

function isConcreteTopFixEntry(entry: Record<string, unknown>, allFindings: ScanFinding[]) {
  const title = nestedString(entry, "title");
  const id = nestedString(entry, "id");

  if (isInvalidFixTitle(title)) {
    return false;
  }

  const matchingFinding = allFindings.find((finding) => finding.id === id || finding.title === title);
  return matchingFinding ? isConcreteFixableFinding(matchingFinding) : true;
}

function calculateClientSecurityScore(findings: ScanFinding[]) {
  let score = 100;
  const allText = findings
    .map((finding) => {
      let evidenceText = "";
      try {
        evidenceText = JSON.stringify(finding.evidence ?? {});
      } catch {
        evidenceText = "";
      }
      return `${finding.checkKey ?? ""} ${finding.title} ${finding.shortDescription} ${finding.proofSummary ?? ""} ${evidenceText}`;
    })
    .join(" ")
    .toLowerCase();
  const confirmedConcreteCritical = findings.filter(
    (finding) =>
      isConfirmedExploitableFinding(finding) &&
      finding.severity === "critical",
  );
  const confirmedConcreteHigh = findings.filter(
    (finding) =>
      isConfirmedExploitableFinding(finding) &&
      finding.severity === "high",
  );
  const likelyHighOrCritical = findings.filter(
    (finding) =>
      (finding.isFixableVulnerability === true ||
        (finding.isFixableVulnerability !== false && isConcreteFixableFinding(finding))) &&
      finding.confidence === "likely" &&
      (finding.severity === "high" || finding.severity === "critical") &&
      isConcreteFixableFinding(finding),
  );
  const likelyMedium = findings.filter(
    (finding) =>
      (finding.isFixableVulnerability === true ||
        (finding.isFixableVulnerability !== false && isConcreteFixableFinding(finding))) &&
      finding.confidence === "likely" &&
      finding.severity === "medium" &&
      isConcreteFixableFinding(finding),
  );
  const lowFixable = findings.filter(
    (finding) =>
      (finding.isFixableVulnerability === true ||
        (finding.isFixableVulnerability !== false && isConcreteFixableFinding(finding))) &&
      finding.severity === "low" &&
      isConcreteFixableFinding(finding),
  );

  score -= confirmedConcreteCritical.length * 30;
  score -= confirmedConcreteHigh.length * 20;
  score -= likelyHighOrCritical.length * 12;
  score -= likelyMedium.length * 5;
  score -= lowFixable.length * 2;

  const hasConfirmedAuthBypass = findings.some(
    (finding) =>
      isConfirmedExploitableFinding(finding) &&
      finding.title.toLowerCase().includes("authentication bypass"),
  );
  const hasConfirmedSqli = findings.some(
    (finding) =>
      isConfirmedExploitableFinding(finding) &&
      (finding.title.toLowerCase().includes("sql injection") ||
        String(finding.findingClass ?? "").toLowerCase().includes("injection")),
  );
  const hasPrimaryAttackPath = findings.some(
    (finding) =>
      finding.confidence === "confirmed" &&
      (String(finding.findingClass ?? "").toLowerCase().includes("attack-path") ||
        finding.title.toLowerCase().includes("attack path analysis")),
  );

  if (confirmedConcreteCritical.length > 0) score = Math.min(score, 40);
  if (hasConfirmedSqli) score = Math.min(score, 35);
  if (hasConfirmedAuthBypass) score = Math.min(score, 30);
  if (hasConfirmedSqli && hasConfirmedAuthBypass) score = Math.min(score, 25);
  if (hasPrimaryAttackPath && (hasConfirmedSqli || hasConfirmedAuthBypass)) score = Math.min(score, 25);

  const hasKnownVulnerableTrainingApp =
    /known intentionally vulnerable application|owasp juice shop|intentionally vulnerable security training application|probably the most modern and sophisticated insecure web application/.test(allText);
  const hasHighDynamicPlatform =
    /hostedprovideronlyauthsurface|search-provider-server|server is set to \\"gws\\"|server is set to "gws"|accounts\.google\.com\/servicelogin|csp\.withgoogle\.com/.test(allText);
  const highDynamicNoConfirmedExploit =
    hasHighDynamicPlatform &&
    confirmedConcreteCritical.length === 0 &&
    confirmedConcreteHigh.length === 0 &&
    likelyHighOrCritical.length === 0 &&
    !hasConfirmedSqli &&
    !hasConfirmedAuthBypass;

  if (hasKnownVulnerableTrainingApp) {
    score = Math.min(score, 35);
  }
  if (highDynamicNoConfirmedExploit) {
    score = Math.max(score, 90);
  }

  const catastrophic = confirmedConcreteCritical.length >= 5;
  if (!catastrophic && hasConfirmedSqli && hasConfirmedAuthBypass) {
    score = Math.max(score, 20);
  }
  score = catastrophic ? Math.max(score, 0) : Math.max(score, 10);
  const roundedScore = Math.max(0, Math.min(100, Math.round(score)));
  const riskLabel =
    hasKnownVulnerableTrainingApp ? "Critical Risk" :
    roundedScore >= 80 ? "Low Risk" :
    roundedScore >= 60 ? "Medium Risk" :
    roundedScore >= 40 ? "High Risk" :
    "Critical Risk";

  return {
    score: roundedScore,
    riskLabel,
    shouldOverrideStoredScore: hasKnownVulnerableTrainingApp || highDynamicNoConfirmedExploit,
    explanation:
      "Security score is risk-based and capped by confirmed critical exploitable findings and attack path evidence.",
  };
}

function extractAttackSurfaceSummary(findings: Record<CategoryKey, ScanFinding[]>) {
  const summaryFinding = findings.security.find((finding) => finding.checkKey === "attack-surface-summary");
  const evidence = (summaryFinding?.evidence ?? {}) as Record<string, unknown>;
  const reportSummary = objectEvidence(evidence.reportSummary);
  const reportCounts = nestedRecord(reportSummary, "counts");
  const reportSecurity = nestedRecord(reportSummary, "security");
  const reportAttackSurface = nestedRecord(reportSummary, "attackSurface");
  const reportCoverageConfidence = objectEvidence(reportSummary?.coverageConfidence) ?? objectEvidence(evidence.coverageConfidence);
  const reportRecommendedFix = objectEvidence(reportSummary?.recommendedFirstFix);
  const reportRecommendedLabel = nestedString(reportSummary, "recommendedFirstLabel");
  const primaryAttackPath = primaryAttackPathFrom(evidence, reportSummary);
  const scanModeLimitations =
    objectEvidence(reportSummary?.scanModeLimitations) ?? getScanModeLimitations(stringEvidence(evidence, "scanMode") || "Fast");
  const allFindings = categoryKeys.flatMap((category) => findings[category]);
  const fallbackCritical = allFindings.filter(
    (finding) => deriveFindingStatus(finding) === "fail" && finding.severity === "critical",
  ).length;
  const fallbackConfirmed = allFindings.filter(
    isConfirmedExploitableFinding,
  ).length;
  const fallbackSupporting = allFindings.filter(
    (finding) => finding.confidence === "confirmed" && isMetaOrSupportingFinding(finding),
  ).length;
  const fallbackLikelyHighImpact = allFindings.filter(
    (finding) =>
      (finding.isFixableVulnerability === true ||
        (finding.isFixableVulnerability !== false && isConcreteFixableFinding(finding))) &&
      finding.confidence === "likely" &&
      (finding.severity === "high" || finding.severity === "critical") &&
      isConcreteFixableFinding(finding),
  ).length;
  const fallbackSecurity = calculateClientSecurityScore(allFindings);
  const storedSecurityScore =
    nestedNumber(reportSecurity, "score") || numericEvidence(evidence, "securityScore") || null;
  const storedSecurityRiskLabel =
    nestedString(reportSecurity, "riskLabel") || stringEvidence(evidence, "securityRiskLabel");
  const storedSecurityExplanation =
    nestedString(reportSecurity, "explanation") || stringEvidence(evidence, "securityScoreExplanation");
  const fallbackRecommendedFix = [...allFindings]
    .filter(isConcreteFixableFinding)
    .sort((left, right) => (right.riskScore ?? 0) - (left.riskScore ?? 0))[0];
  const evidenceRecommendedFix = stringEvidence(evidence, "recommendedFirstFix");
  const safeEvidenceRecommendedFix = isInvalidFixTitle(evidenceRecommendedFix) ? "" : evidenceRecommendedFix;

  if (!summaryFinding) {
    return null;
  }

  return {
    finding: summaryFinding,
    evidence,
    reportSummary,
    primaryAttackPath,
    confirmedAttackSteps: confirmedAttackSteps(primaryAttackPath),
    likelyAttackExtensions: likelyAttackExtensions(primaryAttackPath),
    scanModeLimitations,
    accessMatrix: arrayRecords(evidence.accessMatrix),
    recommendedFirstFix:
      nestedString(reportRecommendedFix, "title") ||
      safeEvidenceRecommendedFix ||
      fallbackRecommendedFix?.title ||
      "No concrete exploitable vulnerability was confirmed",
    recommendedFirstLabel: recommendationLabelFrom(
      reportRecommendedFix,
      reportRecommendedLabel || stringEvidence(evidence, "recommendedFirstLabel"),
    ),
    recommendedFirstFixReason:
      stringEvidence(evidence, "recommendedFirstFixReason") ||
      nestedString(reportRecommendedFix, "reason") ||
      nestedString(reportRecommendedFix, "fixFirstReason") ||
      nestedString(reportRecommendedFix, "proofSummary") ||
      nestedString(reportRecommendedFix, "shortDescription") ||
      "No concrete exploitable vulnerability was confirmed.",
    scanMode: stringEvidence(evidence, "scanMode") || "Fast",
    security: {
      score: fallbackSecurity.shouldOverrideStoredScore
        ? fallbackSecurity.score
        : storedSecurityScore ?? fallbackSecurity.score,
      riskLabel:
        fallbackSecurity.shouldOverrideStoredScore
          ? fallbackSecurity.riskLabel
          : storedSecurityRiskLabel || fallbackSecurity.riskLabel,
      explanation:
        fallbackSecurity.shouldOverrideStoredScore
          ? fallbackSecurity.explanation
          : storedSecurityExplanation || fallbackSecurity.explanation,
    },
    coverageConfidence: reportCoverageConfidence,
    metrics: [
      { label: "Critical issues", value: nestedNumber(reportCounts, "criticalIssues") || numericEvidence(evidence, "criticalIssues") || fallbackCritical },
      { label: "Confirmed exploitable vulnerabilities", value: nestedNumber(reportCounts, "confirmedExploitableVulnerabilities") || numericEvidence(evidence, "confirmedExploitableVulnerabilities") || fallbackConfirmed },
      { label: "Supporting evidence", value: nestedNumber(reportCounts, "confirmedSupportingEvidence") || numericEvidence(evidence, "confirmedSupportingEvidence") || fallbackSupporting },
      { label: "Likely high-impact", value: nestedNumber(reportCounts, "likelyHighImpactIssues") || numericEvidence(evidence, "likelyHighImpactIssues") || fallbackLikelyHighImpact },
      { label: "Public APIs", value: nestedNumber(reportAttackSurface, "publicApis") || numericEvidence(evidence, "publicApis") },
      { label: "Sensitive endpoints", value: nestedNumber(reportAttackSurface, "sensitiveEndpoints") || numericEvidence(evidence, "sensitiveEndpoints") },
      { label: "Missing headers", value: nestedNumber(reportAttackSurface, "missingHeaders") || numericEvidence(evidence, "missingHeaders") },
      { label: "Crawled pages", value: nestedNumber(reportAttackSurface, "crawledPages") || numericEvidence(evidence, "crawledPages") },
      { label: "Discovered endpoints", value: nestedNumber(reportAttackSurface, "discoveredEndpoints") || numericEvidence(evidence, "discoveredEndpoints") },
      { label: "Tested parameters", value: nestedNumber(reportAttackSurface, "testedParameters") || numericEvidence(evidence, "testedParameters") },
      { label: "Coverage confidence", value: nestedString(reportCoverageConfidence, "level") || "Unknown" },
      { label: "Active probes", value: numericEvidence(evidence, "activeProbesExecuted") },
      { label: "Duration", value: stringEvidence(evidence, "scanDuration") || "Running" },
    ],
  };
}

function findingAccentTone(finding: ScanFinding) {
  const status = deriveFindingStatus(finding);
  if (status === "fail") {
    return finding.severity === "critical" ? "#dc2626" : "#e11d48";
  }
  if (status === "warning") {
    return finding.severity === "medium" ? "#d97706" : "#2563eb";
  }
  if (status === "pass") {
    return "#0c9156";
  }
  return "#64748b";
}

function findingSurfaceClasses(finding: ScanFinding) {
  const status = deriveFindingStatus(finding);
  if (status === "fail") {
    return finding.severity === "critical"
      ? "border-red-200 bg-[linear-gradient(180deg,rgba(255,255,255,0.98),rgba(254,242,242,0.92))]"
      : "border-rose-200 bg-[linear-gradient(180deg,rgba(255,255,255,0.98),rgba(255,241,242,0.92))]";
  }
  if (status === "warning") {
    return finding.severity === "medium"
      ? "border-amber-200 bg-[linear-gradient(180deg,rgba(255,255,255,0.98),rgba(255,251,235,0.92))]"
      : "border-sky-200 bg-[linear-gradient(180deg,rgba(255,255,255,0.98),rgba(239,246,255,0.92))]";
  }
  if (status === "pass") {
    return "border-emerald-200 bg-[linear-gradient(180deg,rgba(255,255,255,0.98),rgba(236,253,245,0.9))]";
  }
  return "border-slate-200 bg-[linear-gradient(180deg,rgba(255,255,255,0.98),rgba(248,250,252,0.96))]";
}

function detailPanelClasses(finding: ScanFinding) {
  const status = deriveFindingStatus(finding);
  if (status === "fail") {
    return "border border-white/70 bg-white/75 shadow-[0_10px_28px_rgba(248,113,113,0.08)]";
  }
  if (status === "warning") {
    return "border border-white/70 bg-white/75 shadow-[0_10px_28px_rgba(245,158,11,0.08)]";
  }
  if (status === "pass") {
    return "border border-white/70 bg-white/80 shadow-[0_10px_28px_rgba(16,185,129,0.07)]";
  }
  return "border border-white/70 bg-white/80 shadow-[0_10px_28px_rgba(148,163,184,0.08)]";
}

async function downloadReportPdf(
  scan: ScanRecord,
  findings: Record<CategoryKey, ScanFinding[]>,
) {
  const { jsPDF } = await import("jspdf");
  type PdfColor = readonly [number, number, number];
  const doc = new jsPDF({
    unit: "pt",
    format: "a4",
    compress: true,
  });

  const palette = {
    ink: [15, 23, 42] as const,
    muted: [100, 116, 139] as const,
    primary: [22, 103, 217] as const,
    border: [226, 232, 240] as const,
    surface: [248, 250, 252] as const,
    white: [255, 255, 255] as const,
  };
  const pageWidth = doc.internal.pageSize.getWidth();
  const pageHeight = doc.internal.pageSize.getHeight();
  const marginX = 42;
  const marginY = 48;
  const contentWidth = pageWidth - marginX * 2;
  const lineHeightFor = (fontSize: number) => fontSize * 1.45;
  const colorFromHex = (hex: string): PdfColor => {
    const normalized = hex.replace("#", "");
    return [
      Number.parseInt(normalized.slice(0, 2), 16),
      Number.parseInt(normalized.slice(2, 4), 16),
      Number.parseInt(normalized.slice(4, 6), 16),
    ];
  };
  const splitLines = (text: string, fontSize: number, maxWidth: number) => {
    doc.setFont("helvetica", "normal");
    doc.setFontSize(fontSize);
    return doc.splitTextToSize(text, maxWidth) as string[];
  };
  const getSeverityTheme = (
    severity: ScanFinding["severity"],
  ): { accent: PdfColor; soft: PdfColor; border: PdfColor; text: PdfColor } => {
    switch (severity) {
      case "critical":
        return {
          accent: [220, 38, 38] as const,
          soft: [254, 242, 242] as const,
          border: [254, 202, 202] as const,
          text: [185, 28, 28] as const,
        };
      case "high":
        return {
          accent: [225, 29, 72] as const,
          soft: [255, 241, 242] as const,
          border: [251, 207, 232] as const,
          text: [190, 24, 93] as const,
        };
      case "medium":
        return {
          accent: [217, 119, 6] as const,
          soft: [255, 251, 235] as const,
          border: [253, 230, 138] as const,
          text: [180, 83, 9] as const,
        };
      case "low":
        return {
          accent: [37, 99, 235] as const,
          soft: [239, 246, 255] as const,
          border: [191, 219, 254] as const,
          text: [29, 78, 216] as const,
        };
      case "info":
      default:
        return {
          accent: [100, 116, 139] as const,
          soft: [248, 250, 252] as const,
          border: [226, 232, 240] as const,
          text: [71, 85, 105] as const,
        };
    }
  };
  const getStatusTheme = (
    status: ScanFinding["status"],
  ): { fill: PdfColor; border: PdfColor; text: PdfColor } => {
    switch (status) {
      case "pass":
        return {
          fill: [236, 253, 245] as const,
          border: [167, 243, 208] as const,
          text: [6, 95, 70] as const,
        };
      case "warning":
        return {
          fill: [255, 251, 235] as const,
          border: [253, 230, 138] as const,
          text: [180, 83, 9] as const,
        };
      case "fail":
        return {
          fill: [254, 242, 242] as const,
          border: [254, 202, 202] as const,
          text: [185, 28, 28] as const,
        };
      case "info":
      default:
        return {
          fill: [248, 250, 252] as const,
          border: [226, 232, 240] as const,
          text: [71, 85, 105] as const,
        };
    }
  };
  const getConfidenceTheme = (
    confidence: NonNullable<ScanFinding["confidence"]>,
  ): { fill: PdfColor; border: PdfColor; text: PdfColor } => {
    switch (confidence) {
      case "confirmed":
        return {
          fill: [254, 242, 242] as const,
          border: [254, 202, 202] as const,
          text: [185, 28, 28] as const,
        };
      case "likely":
        return {
          fill: [255, 251, 235] as const,
          border: [253, 230, 138] as const,
          text: [180, 83, 9] as const,
        };
      case "info":
      default:
        return {
          fill: [248, 250, 252] as const,
          border: [226, 232, 240] as const,
          text: [71, 85, 105] as const,
        };
    }
  };
  const getPillWidth = (text: string, fontSize = 8.5, horizontalPadding = 10) => {
    doc.setFont("helvetica", "bold");
    doc.setFontSize(fontSize);
    return doc.getTextWidth(text) + horizontalPadding * 2;
  };
  const drawPill = ({
    x,
    y,
    text,
    fill,
    border,
    color,
    fontSize = 8.5,
    height = 20,
  }: {
    x: number;
    y: number;
    text: string;
    fill: readonly [number, number, number];
    border: readonly [number, number, number];
    color: readonly [number, number, number];
    fontSize?: number;
    height?: number;
  }) => {
    const width = getPillWidth(text, fontSize);
    doc.setFillColor(...fill);
    doc.setDrawColor(...border);
    doc.roundedRect(x, y, width, height, height / 2, height / 2, "FD");
    doc.setFont("helvetica", "bold");
    doc.setFontSize(fontSize);
    doc.setTextColor(...color);
    doc.text(text, x + width / 2, y + height / 2 + fontSize * 0.32, {
      align: "center",
    });
    return width;
  };

  let cursorY = marginY;

  const ensureSpace = (height: number) => {
    if (cursorY + height <= pageHeight - marginY) {
      return;
    }

    doc.addPage();
    cursorY = marginY;
  };

  const drawTextBlock = ({
    text,
    x = marginX,
    maxWidth = contentWidth,
    fontSize,
    color,
    fontStyle = "normal",
    gapAfter = 0,
  }: {
    text: string;
    x?: number;
    maxWidth?: number;
    fontSize: number;
    color: readonly [number, number, number];
    fontStyle?: "normal" | "bold";
    gapAfter?: number;
  }) => {
    const lines = splitLines(text, fontSize, maxWidth);
    const lineHeight = lineHeightFor(fontSize);

    doc.setFont("helvetica", fontStyle);
    doc.setFontSize(fontSize);
    doc.setTextColor(...color);

    lines.forEach((line) => {
      ensureSpace(lineHeight);
      doc.text(line, x, cursorY);
      cursorY += lineHeight;
    });

    cursorY += gapAfter;
  };
  const compactPdfValue = (value: unknown, maxLength = 130) => {
    if (value === null || value === undefined || value === "") {
      return "";
    }

    const raw =
      typeof value === "string" || typeof value === "number" || typeof value === "boolean"
        ? String(value)
        : JSON.stringify(value);
    const compact = raw.replace(/\s+/g, " ").trim();
    return compact.length > maxLength ? `${compact.slice(0, maxLength - 1).trimEnd()}...` : compact;
  };
  const evidenceLinesForPdf = (finding: ScanFinding) => {
    if (finding.locked) {
      return [];
    }

    const evidence = finding.evidence ?? {};
    const authBypassEvidence =
      evidence.authBypassEvidence && typeof evidence.authBypassEvidence === "object" && !Array.isArray(evidence.authBypassEvidence)
        ? (evidence.authBypassEvidence as Record<string, unknown>)
        : null;
    if (authBypassEvidence) {
      return [
        `Login endpoint: ${compactPdfValue(authBypassEvidence.loginEndpoint, 120)}`,
        `Payload preview: ${compactPdfValue(authBypassEvidence.payloadPreview, 80)}`,
        `Response status: ${compactPdfValue(authBypassEvidence.responseStatus, 20)}`,
        `Session artifact: ${compactPdfValue(authBypassEvidence.sessionArtifactType, 40)}`,
        `Authentication model: ${compactPdfValue(authBypassEvidence.authModel, 40)}`,
        `Verification endpoint: ${compactPdfValue(authBypassEvidence.verificationEndpoint, 120)}`,
        `Verification status: ${compactPdfValue(authBypassEvidence.verificationStatus, 20)}`,
        `Verification result: ${compactPdfValue(authBypassEvidence.verificationResult, 80)}`,
        authBypassEvidence.tokenPreview ? `Token preview: ${compactPdfValue(authBypassEvidence.tokenPreview, 40)}` : "",
      ].filter(Boolean).slice(0, 9);
    }

    const confidence = finding.confidence ?? "info";
    const lines = [
      `Confidence: ${confidence.toUpperCase()}`,
      typeof evidence.summary === "string" ? `Proof: ${evidence.summary}` : "",
      evidence.beforeStatus !== undefined || evidence.afterStatus !== undefined
        ? `Status: ${compactPdfValue(evidence.beforeStatus ?? "n/a", 24)} -> ${compactPdfValue(evidence.afterStatus ?? "n/a", 24)}`
        : "",
      typeof evidence.responseDiff === "string" ? `Response diff: ${compactPdfValue(evidence.responseDiff, 110)}` : "",
      Array.isArray(evidence.probePayloads)
        ? `Payloads: ${evidence.probePayloads.map((payload) => compactPdfValue(payload, 42)).filter(Boolean).join(", ")}`
        : typeof evidence.probePayload === "string"
          ? `Payload: ${compactPdfValue(evidence.probePayload, 80)}`
          : "",
    ].filter(Boolean);

    const resultItems = Array.isArray(evidence.results)
      ? evidence.results.slice(0, 3)
      : Array.isArray(evidence.activeProbes)
        ? evidence.activeProbes.slice(0, 3)
        : [];
    resultItems.forEach((item, index) => {
      if (!item || typeof item !== "object") {
        return;
      }

      const row = item as Record<string, unknown>;
      const proofParts = [
        compactPdfValue(row.url ? `url=${row.url}` : row.mutatedUrl ? `mutated=${row.mutatedUrl}` : "", 120),
        compactPdfValue(row.parameter ? `param=${row.parameter}` : "", 40),
        compactPdfValue(row.payload ? `payload=${row.payload}` : "", 56),
        compactPdfValue(row.baselineStatus ? `before=${row.baselineStatus}` : "", 30),
        compactPdfValue(row.status ? `after=${row.status}` : "", 30),
        row.baselineRecordCount !== undefined ? compactPdfValue(`baselineRecords=${row.baselineRecordCount}`, 40) : "",
        row.probeRecordCount !== undefined ? compactPdfValue(`probeRecords=${row.probeRecordCount}`, 40) : "",
        row.sqlError ? "sql-error=true" : "",
        row.recordExpansion ? "record-expansion=true" : "",
        row.timeDelay ? "time-delay=true" : "",
        row.executed ? "executed=true" : "",
        row.context ? compactPdfValue(`context=${row.context}`, 50) : "",
      ].filter(Boolean);
      lines.push(`Result ${index + 1}: ${proofParts.join(", ") || compactPdfValue(row, 120)}`);
    });

    if (typeof evidence.checkedUrl === "string" && lines.length < 4) {
      lines.push(`Checked: ${compactPdfValue(evidence.checkedUrl, 160)}`);
    }

    return lines.slice(0, 5);
  };

  const drawMetricCard = ({
    x,
    label,
    score,
    passCount,
    failCount,
    riskLabel,
  }: {
    x: number;
    label: string;
    score: number | null;
    passCount: number;
    failCount: number;
    riskLabel?: string;
  }) => {
    const cardWidth = (contentWidth - 24) / 4;
    const y = cursorY;
    const tone = colorFromHex(getScoreTone(score));

    doc.setFillColor(...palette.white);
    doc.setDrawColor(...palette.border);
    doc.roundedRect(x, y, cardWidth, 90, 16, 16, "FD");

    doc.setFont("helvetica", "bold");
    doc.setFontSize(9);
    doc.setTextColor(...palette.muted);
    doc.text(label.toUpperCase(), x + 14, y + 22);

    doc.setFont("helvetica", "bold");
    doc.setFontSize(18);
    doc.setTextColor(6, 95, 70);
    doc.text(String(passCount), x + 14, y + 50);
    doc.setFont("helvetica", "normal");
    doc.setFontSize(8);
    doc.setTextColor(...palette.muted);
    doc.text("PASSED", x + 14, y + 64);

    doc.setFont("helvetica", "bold");
    doc.setFontSize(18);
    doc.setTextColor(185, 28, 28);
    doc.text(String(failCount), x + cardWidth / 2 + 6, y + 50);
    doc.setFont("helvetica", "normal");
    doc.setFontSize(8);
    doc.setTextColor(...palette.muted);
    doc.text("FAILED", x + cardWidth / 2 + 6, y + 64);

    doc.setFont("helvetica", "bold");
    doc.setFontSize(9);
    doc.setTextColor(...tone);
    if (riskLabel) {
      doc.text(`RISK ${riskLabel}`, x + 14, y + 76);
      doc.text(`SCORE ${score ?? "--"}/100`, x + 14, y + 86);
    } else {
      doc.text(`SCORE ${formatScorePercent(score)}`, x + 14, y + 80);
    }
  };

  const drawFindingCard = (finding: ScanFinding) => {
    const cardX = marginX;
    const cardWidth = contentWidth;
    const statusTheme = getStatusTheme(finding.status);
    const confidence = finding.confidence ?? "info";
    const headerLabels = formatFindingHeader(finding);
    const confidenceTheme = getConfidenceTheme(confidence);
    const severityTheme = getSeverityTheme(finding.severity);
    const issueDetected = finding.status === "warning" || finding.status === "fail";
    const innerX = cardX + (issueDetected ? 26 : 18);
    const innerWidth = cardWidth - (issueDetected ? 44 : 36);
    const statusLabel = headerLabels.compact;
    const confidenceLabel = `Confidence: ${headerLabels.confidenceLabel}`;
    const chipGap = 8;
    const chipHeight = 20;
    const statusChipWidth = getPillWidth(statusLabel);
    const confidenceChipWidth = getPillWidth(confidenceLabel);
    const chipsWidth = statusChipWidth + confidenceChipWidth + chipGap;
    const titleLines = splitLines(finding.title, 16, Math.max(180, innerWidth - chipsWidth - 18));
    const summaryLines = splitLines(finding.shortDescription, 11, innerWidth);
    const detailPanelGap = 12;
    const detailPanelWidth = finding.locked ? innerWidth : (innerWidth - detailPanelGap) / 2;
    const detailPanelTextWidth = detailPanelWidth - 28;
    const whyLines = finding.locked
      ? splitLines(
          "Sign in with Google to unlock the full remediation details for this check.",
          10,
          detailPanelTextWidth,
        )
      : splitLines(finding.whyItMatters, 10, detailPanelTextWidth);
    const recommendationLines = finding.locked
      ? []
      : splitLines(finding.recommendation, 10, detailPanelTextWidth);
    const evidenceLines = evidenceLinesForPdf(finding).flatMap((line) =>
      splitLines(line, 9, innerWidth - 28),
    );
    const titleHeight = titleLines.length * lineHeightFor(16);
    const summaryHeight = summaryLines.length * lineHeightFor(11);
    const whyHeight = whyLines.length * lineHeightFor(10);
    const recommendationHeight = recommendationLines.length * lineHeightFor(10);
    const evidenceHeight = evidenceLines.length * lineHeightFor(9);
    const headerHeight = Math.max(titleHeight, chipHeight);
    const panelHeadingHeight = lineHeightFor(9);
    const whyPanelHeight = 14 + panelHeadingHeight + 6 + whyHeight + 14;
    const recommendationPanelHeight = finding.locked
      ? 0
      : 14 + panelHeadingHeight + 6 + recommendationHeight + 14;
    const detailPanelsHeight = finding.locked
      ? whyPanelHeight
      : Math.max(whyPanelHeight, recommendationPanelHeight);
    const evidencePanelHeight = evidenceLines.length
      ? 12 + panelHeadingHeight + 6 + evidenceHeight + 12
      : 0;
    const cardHeight =
      18 +
      headerHeight +
      10 +
      12 +
      summaryHeight +
      16 +
      detailPanelsHeight +
      (evidencePanelHeight ? 12 + evidencePanelHeight : 0) +
      18;

    if (cursorY !== marginY) {
      ensureSpace(cardHeight + 12);
    }

    const startY = cursorY;
    let localY = startY + 18;
    const cardBorderColor = issueDetected ? severityTheme.border : palette.border;

    doc.setFillColor(...palette.white);
    doc.setDrawColor(...cardBorderColor);
    doc.roundedRect(cardX, startY, cardWidth, cardHeight, 18, 18, "FD");
    if (issueDetected) {
      doc.setFillColor(...severityTheme.accent);
      doc.roundedRect(cardX + 8, startY + 14, 5, cardHeight - 28, 3, 3, "F");
    }

    doc.setFont("helvetica", "bold");
    doc.setFontSize(16);
    doc.setTextColor(...palette.ink);
    titleLines.forEach((line) => {
      doc.text(line, innerX, localY);
      localY += lineHeightFor(16);
    });

    const chipsY = startY + 18;
    let chipCursorX = cardX + cardWidth - 18;
    const confidenceX = chipCursorX - confidenceChipWidth;
    chipCursorX = confidenceX - chipGap;
    drawPill({
      x: confidenceX,
      y: chipsY,
      text: confidenceLabel,
      fill: confidenceTheme.fill,
      border: confidenceTheme.border,
      color: confidenceTheme.text,
    });
    chipCursorX -= statusChipWidth;
    drawPill({
      x: chipCursorX,
      y: chipsY,
      text: statusLabel,
      fill: statusTheme.fill,
      border: statusTheme.border,
      color: statusTheme.text,
    });

    localY = startY + 18 + headerHeight + 12;
    doc.setFont("helvetica", "normal");
    doc.setFontSize(11);
    doc.setTextColor(...palette.muted);
    summaryLines.forEach((line) => {
      doc.text(line, innerX, localY);
      localY += lineHeightFor(11);
    });

    localY += 16;
    const detailStartY = localY;
    const drawDetailPanel = ({
      x,
      width,
      title,
      lines,
      accent,
      soft,
    }: {
      x: number;
      width: number;
      title: string;
      lines: string[];
      accent: readonly [number, number, number];
      soft: readonly [number, number, number];
    }) => {
      const panelHeight = 14 + panelHeadingHeight + 6 + lines.length * lineHeightFor(10) + 14;
      let panelY = detailStartY + 14;
      doc.setFillColor(...soft);
      doc.setDrawColor(...palette.border);
      doc.roundedRect(x, detailStartY, width, panelHeight, 14, 14, "FD");
      doc.setFont("helvetica", "bold");
      doc.setFontSize(9);
      doc.setTextColor(...accent);
      doc.text(title, x + 14, panelY);
      panelY += panelHeadingHeight + 6;
      doc.setFont("helvetica", "normal");
      doc.setFontSize(10);
      doc.setTextColor(...palette.ink);
      lines.forEach((line) => {
        doc.text(line, x + 14, panelY);
        panelY += lineHeightFor(10);
      });
    };

    drawDetailPanel({
      x: innerX,
      width: detailPanelWidth,
      title: finding.locked ? "DETAILS" : "WHY IT MATTERS",
      lines: whyLines,
      accent: issueDetected ? severityTheme.accent : palette.primary,
      soft: palette.surface,
    });

    if (!finding.locked) {
      drawDetailPanel({
        x: innerX + detailPanelWidth + detailPanelGap,
        width: detailPanelWidth,
        title: "RECOMMENDATION",
        lines: recommendationLines,
        accent: palette.primary,
        soft: [239, 246, 255],
      });
    }

    if (evidenceLines.length > 0) {
      let evidenceY = detailStartY + detailPanelsHeight + 12;
      doc.setFillColor(...palette.surface);
      doc.setDrawColor(...palette.border);
      doc.roundedRect(innerX, evidenceY, innerWidth, evidencePanelHeight, 14, 14, "FD");
      evidenceY += 12;
      doc.setFont("helvetica", "bold");
      doc.setFontSize(9);
      doc.setTextColor(...palette.primary);
      doc.text("EVIDENCE", innerX + 14, evidenceY);
      evidenceY += panelHeadingHeight + 6;
      doc.setFont("helvetica", "normal");
      doc.setFontSize(9);
      doc.setTextColor(...palette.ink);
      evidenceLines.forEach((line) => {
        doc.text(line, innerX + 14, evidenceY);
        evidenceY += lineHeightFor(9);
      });
    }

    cursorY += cardHeight + 12;
  };

  const pdfFindings = Object.fromEntries(
    categoryKeys.map((category) => [
      category,
      sortFindings(
        findings[category].filter((finding) => !isAttackSurfaceSummaryFinding(finding)),
      ),
    ]),
  ) as Record<CategoryKey, ScanFinding[]>;
  const pdfAllFindings = categoryKeys.flatMap((category) => pdfFindings[category]);
  const pdfOverallCounts = summarizeFindingCounts(pdfAllFindings);
  const pdfCategoryCounts = Object.fromEntries(
    categoryKeys.map((category) => [category, summarizeFindingCounts(pdfFindings[category])]),
  ) as Record<CategoryKey, ReturnType<typeof summarizeFindingCounts>>;
  const pdfAttackSurface = extractAttackSurfaceSummary(findings);
  const pdfReportSummary = pdfAttackSurface?.reportSummary ?? null;
  const pdfReportCounts = nestedRecord(pdfReportSummary, "counts");
  const pdfReportSecurity = nestedRecord(pdfReportSummary, "security");
  const pdfCoverageConfidence =
    objectEvidence(pdfReportSummary?.coverageConfidence) ??
    objectEvidence(pdfAttackSurface?.evidence.coverageConfidence);
  const pdfConfirmedFindings = pdfAllFindings.filter(
    isConfirmedExploitableFinding,
  );
  const pdfSupportingEvidenceCount =
    nestedNumber(pdfReportCounts, "confirmedSupportingEvidence") ||
    pdfAllFindings.filter(
      (finding) =>
        finding.confidence === "confirmed" &&
        (finding.isMetaFinding === true || finding.isExploitSupportingEvidence === true),
    ).length;
  const pdfLikelyFindings = pdfAllFindings.filter(
    (finding) =>
      finding.isFixableVulnerability === true &&
      finding.confidence === "likely" &&
      (finding.severity === "high" || finding.severity === "critical") &&
      isConcreteFixableFinding(finding),
  );
  const pdfInfoFindings = pdfAllFindings.filter(
    (finding) => (finding.confidence ?? "info") === "info" || deriveFindingStatus(finding) === "info",
  );
  const pdfReportTopFixes = Array.isArray(pdfReportSummary?.topFixes)
    ? (pdfReportSummary.topFixes as Array<Record<string, unknown>>)
        .filter((entry) => isConcreteTopFixEntry(entry, pdfAllFindings))
        .slice(0, 5)
    : [];
  const pdfEvidenceTopFixes = Array.isArray(pdfAttackSurface?.evidence.topFixes)
    ? (pdfAttackSurface.evidence.topFixes as Array<Record<string, unknown>>)
        .filter((entry) => isConcreteTopFixEntry(entry, pdfAllFindings))
        .slice(0, 5)
    : [];
  const pdfFallbackTopFixes = pdfAllFindings
    .filter(isConcreteFixableFinding)
    .sort((left, right) => (right.riskScore ?? 0) - (left.riskScore ?? 0))
    .slice(0, 5)
    .map((finding, index) => ({
      rank: index + 1,
      id: finding.id,
      title: finding.title,
      riskScore: finding.riskScore ?? 0,
      reason: finding.proofSummary ?? finding.shortDescription,
      recommendation: finding.recommendation,
    }));
  const pdfTopFixes =
    pdfReportTopFixes.length > 0
      ? pdfReportTopFixes
      : pdfEvidenceTopFixes.length > 0
        ? pdfEvidenceTopFixes
        : pdfFallbackTopFixes;
  const pdfRecommendedFix =
    objectEvidence(pdfReportSummary?.recommendedFirstFix) ??
    (pdfTopFixes[0] ?? null);
  const pdfRecommendedLabel = recommendationLabelFrom(
    pdfRecommendedFix,
    nestedString(pdfReportSummary, "recommendedFirstLabel") ||
      pdfAttackSurface?.recommendedFirstLabel,
  );
  const pdfRecommendedFixTitle =
    nestedString(pdfRecommendedFix, "title") ||
    (isInvalidFixTitle(pdfAttackSurface?.recommendedFirstFix ?? "") ? "" : pdfAttackSurface?.recommendedFirstFix) ||
    "No concrete exploitable vulnerability was confirmed";
  const pdfRecommendedFixReason =
    nestedString(pdfRecommendedFix, "reason") ||
    nestedString(pdfRecommendedFix, "fixFirstReason") ||
    nestedString(pdfRecommendedFix, "proofSummary") ||
    nestedString(pdfRecommendedFix, "shortDescription") ||
    pdfAttackSurface?.recommendedFirstFixReason ||
    "No concrete exploitable vulnerability was confirmed.";
  const pdfFallbackSecurity = calculateClientSecurityScore(pdfAllFindings);
  const pdfSecurityScore =
    pdfAttackSurface?.security.score ||
    nestedNumber(pdfReportSecurity, "score") ||
    scan.securityScore ||
    pdfFallbackSecurity.score ||
    null;
  const pdfSecurityRiskLabel =
    pdfAttackSurface?.security.riskLabel ||
    nestedString(pdfReportSecurity, "riskLabel") ||
    pdfFallbackSecurity.riskLabel ||
    (pdfSecurityScore !== null && pdfSecurityScore < 40 ? "Critical Risk" : "");
  const pdfSecurityExplanation =
    pdfAttackSurface?.security.explanation ||
    nestedString(pdfReportSecurity, "explanation") ||
    pdfFallbackSecurity.explanation ||
    "Security score is risk-based and capped by confirmed critical exploitable findings and attack path evidence.";
  const pdfOverallScore = computeDisplayOverallScore(
    pdfSecurityScore,
    scan.seoScore,
    scan.performanceScore,
    scan.overallScore,
  );
  const pdfCoverageLevel = nestedString(pdfCoverageConfidence, "level") || "Unknown";
  const pdfCoverageExplanation =
    nestedString(pdfCoverageConfidence, "explanation") ||
    "Coverage confidence was not recorded for this scan.";
  const pdfPrimaryAttackPath = pdfAttackSurface
    ? primaryAttackPathFrom(pdfAttackSurface.evidence, pdfReportSummary)
    : null;
  const pdfConfirmedAttackSteps = confirmedAttackSteps(pdfPrimaryAttackPath);
  const pdfLikelyAttackExtensions = likelyAttackExtensions(pdfPrimaryAttackPath);
  const pdfScanModeLimitations =
    objectEvidence(pdfReportSummary?.scanModeLimitations) ??
    getScanModeLimitations(pdfAttackSurface?.scanMode ?? scan.scanMode ?? "Fast");
  const pdfSessionModel =
    pdfAttackSurface?.evidence.sessionModel &&
    typeof pdfAttackSurface.evidence.sessionModel === "object"
      ? (pdfAttackSurface.evidence.sessionModel as Record<string, unknown>)
      : null;
  const pdfAccessMatrix = arrayRecords(pdfAttackSurface?.evidence.accessMatrix).slice(0, 12);
  const pdfAccessMatrixPartial = accessMatrixIsPartial(pdfAccessMatrix);

  const headerBadgeRadius = 34;
  const headerRightX = pageWidth - marginX - 68;
  const headerBadgeCenterY = marginY + 40;

  doc.setFont("helvetica", "bold");
  doc.setFontSize(10);
  doc.setTextColor(...palette.primary);
  doc.text("FIXNX FULL REPORT", marginX, cursorY);

  cursorY += 24;
  doc.setFont("helvetica", "bold");
  doc.setFontSize(26);
  doc.setTextColor(...palette.ink);
  doc.text(scan.targetHostname, marginX, cursorY);

  cursorY += 22;
  drawTextBlock({
    text: `Target: ${scan.target}`,
    fontSize: 11,
    color: palette.muted,
    gapAfter: 0,
  });
  drawTextBlock({
    text: `Generated: ${new Date(scan.updatedAt).toLocaleString()}`,
    fontSize: 11,
    color: palette.muted,
    gapAfter: 0,
  });
  drawTextBlock({
    text: `Status: ${scan.status}`,
    fontSize: 11,
    color: palette.muted,
    gapAfter: 0,
  });
  drawTextBlock({
    text: `Scan mode: ${pdfAttackSurface?.scanMode ?? scan.scanMode ?? "Fast"} | Coverage Confidence: ${pdfCoverageLevel} | Confirmed exploitable vulnerabilities: ${nestedNumber(pdfReportCounts, "confirmedExploitableVulnerabilities") || pdfConfirmedFindings.length} | Supporting evidence: ${pdfSupportingEvidenceCount} | Likely high-impact: ${nestedNumber(pdfReportCounts, "likelyHighImpactIssues") || pdfLikelyFindings.length} | Informational findings: ${nestedNumber(pdfReportCounts, "informationalFindings") || pdfInfoFindings.length}`,
    fontSize: 11,
    color: palette.muted,
    gapAfter: 20,
  });

  const overallTone = colorFromHex(getScoreTone(pdfOverallScore));
  doc.setDrawColor(...overallTone);
  doc.setLineWidth(6);
  doc.circle(headerRightX, headerBadgeCenterY, headerBadgeRadius, "S");
  doc.setFont("helvetica", "bold");
  doc.setFontSize(22);
  doc.setTextColor(...overallTone);
  doc.text(formatScorePercent(pdfOverallScore), headerRightX, headerBadgeCenterY + 2, {
    align: "center",
  });
  doc.setFont("helvetica", "bold");
  doc.setFontSize(7);
  doc.setTextColor(...palette.muted);
  doc.text("OVERALL", headerRightX, headerBadgeCenterY + 17, { align: "center" });

  ensureSpace(104);
  const metricWidth = (contentWidth - 24) / 4;
  drawMetricCard({
    x: marginX,
    label: "Overall",
    score: pdfOverallScore,
    passCount: pdfOverallCounts.passCount,
    failCount: pdfOverallCounts.failCount,
  });
  drawMetricCard({
    x: marginX + metricWidth + 8,
    label: "Security",
    score: pdfSecurityScore,
    passCount: pdfCategoryCounts.security.passCount,
    failCount: pdfCategoryCounts.security.failCount,
    riskLabel: pdfSecurityRiskLabel,
  });
  drawMetricCard({
    x: marginX + (metricWidth + 8) * 2,
    label: "SEO",
    score: scan.seoScore,
    passCount: pdfCategoryCounts.seo.passCount,
    failCount: pdfCategoryCounts.seo.failCount,
  });
  drawMetricCard({
    x: marginX + (metricWidth + 8) * 3,
    label: "Performance",
    score: scan.performanceScore,
    passCount: pdfCategoryCounts.performance.passCount,
    failCount: pdfCategoryCounts.performance.failCount,
  });
  cursorY += 114;

  if (pdfAttackSurface) {
    ensureSpace(124);
    const boxY = cursorY;
    doc.setFillColor(...palette.surface);
    doc.setDrawColor(...palette.border);
    doc.roundedRect(marginX, boxY, contentWidth, 112, 16, 16, "FD");
    doc.setFont("helvetica", "bold");
    doc.setFontSize(13);
    doc.setTextColor(...palette.ink);
    doc.text("Attack Surface Summary", marginX + 16, boxY + 24);
    doc.setFont("helvetica", "normal");
    doc.setFontSize(9);
    doc.setTextColor(...palette.muted);
    doc.text(`Scan mode: ${pdfAttackSurface.scanMode}`, pageWidth - marginX - 16, boxY + 24, {
      align: "right",
    });

    const metricGap = 8;
    const summaryMetrics = pdfAttackSurface.metrics.slice(0, 8);
    const summaryCardWidth = (contentWidth - 32 - metricGap * 3) / 4;
    summaryMetrics.forEach((metric, index) => {
      const column = index % 4;
      const row = Math.floor(index / 4);
      const x = marginX + 16 + column * (summaryCardWidth + metricGap);
      const y = boxY + 38 + row * 28;
      doc.setFillColor(...palette.white);
      doc.setDrawColor(...palette.border);
      doc.roundedRect(x, y, summaryCardWidth, 24, 8, 8, "FD");
      doc.setFont("helvetica", "bold");
      doc.setFontSize(8);
      doc.setTextColor(...palette.ink);
      doc.text(String(metric.value), x + 8, y + 15);
      doc.setFont("helvetica", "normal");
      doc.setFontSize(6.5);
      doc.setTextColor(...palette.muted);
      doc.text(metric.label.toUpperCase(), x + summaryCardWidth - 8, y + 15, {
        align: "right",
      });
    });

    doc.setFont("helvetica", "bold");
    doc.setFontSize(9);
    doc.setTextColor(...palette.primary);
    doc.text(
      `${pdfRecommendedLabel}: ${compactPdfValue(pdfRecommendedFixTitle, 150)}`,
      marginX + 16,
      boxY + 102,
    );
    cursorY += 126;
  }

  ensureSpace(120);
  doc.setFont("helvetica", "bold");
  doc.setFontSize(18);
  doc.setTextColor(...palette.ink);
  doc.text("Executive Summary", marginX, cursorY);
  cursorY += 24;
  drawTextBlock({
    text:
      pdfConfirmedFindings.length > 0
        ? `This scan confirmed ${nestedNumber(pdfReportCounts, "confirmedExploitableVulnerabilities") || pdfConfirmedFindings.length} exploitable vulnerability/vulnerabilities and identified ${nestedNumber(pdfReportCounts, "likelyHighImpactIssues") || pdfLikelyFindings.length} likely high-impact issue(s). The highest priority fix is ${pdfRecommendedFixTitle} because it is the strongest concrete fixable issue by confidence, exposure, and attack-path impact. The report separates confirmed exploitability from supporting evidence and coverage notes.`
        : pdfCoverageLevel !== "High"
          ? `This scan did not confirm a concrete exploitable vulnerability, but it detected elevated attack-surface risk and limited coverage confidence. Review ${nestedNumber(pdfReportCounts, "likelyHighImpactIssues") || pdfLikelyFindings.length} likely high-impact issue(s), authentication/form surfaces, reflected-input indicators, and coverage notes before treating the target as low risk.`
          : `This scan did not confirm a concrete exploitable vulnerability. Review ${nestedNumber(pdfReportCounts, "likelyHighImpactIssues") || pdfLikelyFindings.length} likely high-impact issue(s) and ${nestedNumber(pdfReportCounts, "informationalFindings") || pdfInfoFindings.length} informational coverage note(s) for areas that may require deeper authenticated testing.`,
    fontSize: 11,
    color: palette.ink,
    gapAfter: 12,
  });
  drawTextBlock({
    text: `Security Risk: ${pdfSecurityRiskLabel || "Unknown"} | Security Score: ${pdfSecurityScore ?? "--"}/100. ${pdfSecurityExplanation}`,
    fontSize: 10,
    color: palette.muted,
    gapAfter: 12,
  });
  drawTextBlock({
    text: `Coverage Confidence: ${pdfCoverageLevel}. ${pdfCoverageExplanation}`,
    fontSize: 10,
    color: palette.muted,
    gapAfter: 12,
  });
  if (pdfScanModeLimitations) {
    ensureSpace(90);
    doc.setFont("helvetica", "bold");
    doc.setFontSize(15);
    doc.setTextColor(...palette.ink);
    doc.text(compactPdfValue(pdfScanModeLimitations.title, 120), marginX, cursorY);
    cursorY += 20;
    drawTextBlock({
      text: compactPdfValue(pdfScanModeLimitations.summary, 260),
      fontSize: 10,
      color: palette.muted,
      gapAfter: 4,
    });
    if (Array.isArray(pdfScanModeLimitations.bullets)) {
      pdfScanModeLimitations.bullets.slice(0, 7).forEach((bullet) => {
        drawTextBlock({
          text: `- ${compactPdfValue(bullet, 160)}`,
          fontSize: 9,
          color: palette.ink,
          gapAfter: 1,
        });
      });
    }
    cursorY += 8;
  }

  ensureSpace(120);
  doc.setFont("helvetica", "bold");
  doc.setFontSize(16);
  doc.setTextColor(...palette.ink);
  doc.text(pdfRecommendedLabel, marginX, cursorY);
  cursorY += 20;
  drawTextBlock({
    text: pdfRecommendedFixTitle,
    fontSize: 12,
    color: palette.primary,
    fontStyle: "bold",
    gapAfter: 4,
  });
  drawTextBlock({
    text: compactPdfValue(pdfRecommendedFixReason, 240),
    fontSize: 10,
    color: palette.muted,
    gapAfter: 16,
  });

  if (pdfTopFixes.length > 0) {
    ensureSpace(160);
    doc.setFont("helvetica", "bold");
    doc.setFontSize(16);
    doc.setTextColor(...palette.ink);
    doc.text("Top Reviews/Fixes", marginX, cursorY);
    cursorY += 20;
    pdfTopFixes.forEach((fix, index) => {
      ensureSpace(42);
      doc.setFillColor(...palette.surface);
      doc.setDrawColor(...palette.border);
      doc.roundedRect(marginX, cursorY, contentWidth, 34, 10, 10, "FD");
      doc.setFont("helvetica", "bold");
      doc.setFontSize(10);
      doc.setTextColor(...palette.primary);
      doc.text(`#${index + 1}`, marginX + 10, cursorY + 21);
      doc.setTextColor(...palette.ink);
      doc.text(compactPdfValue(fix.title, 84), marginX + 42, cursorY + 14);
	      doc.setFont("helvetica", "normal");
	      doc.setFontSize(8);
	      doc.setTextColor(...palette.muted);
	      doc.text(
	        `Risk ${compactPdfValue(fix.riskScore ?? 0, 12)} | ${compactPdfValue(fix.reason ?? fix.fixFirstReason ?? fix.proofSummary ?? fix.shortDescription, 120)}`,
	        marginX + 42,
	        cursorY + 27,
	      );
	      cursorY += 42;
	    });
  }

  if (pdfPrimaryAttackPath) {
    doc.addPage();
    cursorY = marginY;
    doc.setFont("helvetica", "bold");
    doc.setFontSize(18);
    doc.setTextColor(...palette.ink);
    doc.text("Attack Path Analysis", marginX, cursorY);
    cursorY += 24;
    drawTextBlock({
      text: `Primary Attack Path: ${compactPdfValue(pdfPrimaryAttackPath.title, 140)}`,
      fontSize: 12,
      color: palette.primary,
      fontStyle: "bold",
      gapAfter: 4,
    });
    drawTextBlock({
      text: compactPdfValue(pdfPrimaryAttackPath.summary ?? pdfPrimaryAttackPath.finalImpact ?? "", 260),
      fontSize: 10,
      color: palette.muted,
      gapAfter: 10,
    });
    drawTextBlock({
      text: "Confirmed Steps",
      fontSize: 11,
      color: palette.ink,
      fontStyle: "bold",
      gapAfter: 4,
    });
    pdfConfirmedAttackSteps.slice(0, 5).forEach((step, index) => {
      ensureSpace(66);
      doc.setFillColor(...palette.surface);
      doc.setDrawColor(...palette.border);
      doc.roundedRect(marginX, cursorY, contentWidth, 56, 12, 12, "FD");
      doc.setFont("helvetica", "bold");
      doc.setFontSize(9);
      doc.setTextColor(...palette.ink);
      const suffix = step.supportingEvidence === true ? " (supporting evidence)" : "";
      doc.text(`Step ${index + 1}: ${compactPdfValue(step.title, 100)}${suffix}`, marginX + 12, cursorY + 14);
      doc.setFont("helvetica", "normal");
      doc.setFontSize(8);
      doc.setTextColor(...palette.muted);
      doc.text(compactPdfValue(`Action: ${step.attackerAction ?? ""}`, 150), marginX + 12, cursorY + 28);
      doc.text(compactPdfValue(`Evidence: ${step.evidence ?? step.technicalEvidence ?? ""}`, 150), marginX + 12, cursorY + 40);
      doc.text(compactPdfValue(`Gained capability: ${step.gainedCapability ?? ""}`, 150), marginX + 12, cursorY + 51);
      cursorY += 66;
    });
    if (pdfLikelyAttackExtensions.length > 0) {
      drawTextBlock({
        text: "Likely Extensions",
        fontSize: 11,
        color: palette.ink,
        fontStyle: "bold",
        gapAfter: 4,
      });
      pdfLikelyAttackExtensions.slice(0, 4).forEach((step) => {
        drawTextBlock({
          text: `- ${compactPdfValue(step.title, 100)}: ${compactPdfValue(step.evidence ?? step.technicalEvidence ?? "", 160)}`,
          fontSize: 9,
          color: palette.muted,
          gapAfter: 2,
        });
      });
    }
    drawTextBlock({
      text: `Final impact: ${compactPdfValue(pdfPrimaryAttackPath.finalImpact, 240)}`,
      fontSize: 10,
      color: palette.ink,
      gapAfter: 4,
    });
    drawTextBlock({
      text: `Fix first: ${compactPdfValue(pdfPrimaryAttackPath.fixFirstTitle ?? pdfRecommendedFixTitle, 140)}. ${compactPdfValue(pdfPrimaryAttackPath.fixFirstReason ?? pdfRecommendedFixReason, 220)}`,
      fontSize: 10,
      color: palette.ink,
      gapAfter: 16,
    });
    const suppressedCount = Number(pdfPrimaryAttackPath.suppressedRelatedPathCount ?? 0);
    if (suppressedCount > 0) {
      drawTextBlock({
        text: `${suppressedCount} related path(s) were suppressed to reduce duplicate attack-chain reporting.`,
        fontSize: 9,
        color: palette.muted,
        gapAfter: 10,
      });
    }
  }

  if (pdfSessionModel || pdfAccessMatrix.length > 0) {
    doc.addPage();
    cursorY = marginY;
    if (pdfSessionModel) {
      doc.setFont("helvetica", "bold");
      doc.setFontSize(18);
      doc.setTextColor(...palette.ink);
      doc.text("Session Model", marginX, cursorY);
      cursorY += 24;
      [
        `Session type: ${compactPdfValue(pdfSessionModel.sessionType ?? "unknown")}`,
        `Authenticated context obtained: ${compactPdfValue(pdfSessionModel.authenticatedContextObtained ?? false)}`,
        `Storage locations: ${Array.isArray(pdfSessionModel.storageLocations) ? pdfSessionModel.storageLocations.join(", ") : "unknown"}`,
        `Token exposed to JavaScript: ${compactPdfValue(pdfSessionModel.tokenExposedToJavaScript ?? "unknown")}`,
        `Risks: ${Array.isArray(pdfSessionModel.risks) && pdfSessionModel.risks.length ? pdfSessionModel.risks.join(", ") : "none observed"}`,
      ].forEach((line) => {
        drawTextBlock({
          text: line,
          fontSize: 10,
          color: palette.ink,
          gapAfter: 2,
        });
      });
      cursorY += 12;
    }

    if (pdfAccessMatrix.length > 0) {
      ensureSpace(80);
      doc.setFont("helvetica", "bold");
      doc.setFontSize(18);
      doc.setTextColor(...palette.ink);
      doc.text(pdfAccessMatrixPartial ? "Partial Access Matrix" : "Role-Based Access Matrix", marginX, cursorY);
      cursorY += 24;
      if (pdfAccessMatrixPartial) {
        drawTextBlock({
          text:
            "Only anonymous and scanner-auth-context were available for at least one sampled endpoint. Provide userA, userB, and admin contexts for full role-based authorization proof.",
          fontSize: 10,
          color: palette.muted,
          gapAfter: 8,
        });
      }
      pdfAccessMatrix.forEach((row) => {
        ensureSpace(72);
        doc.setFillColor(...palette.surface);
        doc.setDrawColor(...palette.border);
        doc.roundedRect(marginX, cursorY, contentWidth, 64, 8, 8, "FD");
        doc.setFont("helvetica", "bold");
        doc.setFontSize(8);
        doc.setTextColor(...palette.ink);
        doc.text(compactPdfValue(row.endpoint, 88), marginX + 8, cursorY + 12);
        doc.setFont("helvetica", "normal");
        doc.setTextColor(...palette.muted);
        doc.text(
          compactPdfValue(
            `Sensitivity ${row.sensitivity ?? "unknown"} | Issue ${row.issue ?? row.issueType ?? "none"}`,
            150,
          ),
          marginX + 8,
          cursorY + 24,
        );
        doc.text(
          compactPdfValue(
            `Anon ${accessMatrixCellLabel(row.anonymous)} | Scanner auth ${accessMatrixCellLabel(row.scannerAuthContext)} | UserA ${accessMatrixCellLabel(row.userA)} | UserB ${accessMatrixCellLabel(row.userB)} | Admin ${accessMatrixCellLabel(row.admin)}`,
            170,
          ),
          marginX + 8,
          cursorY + 38,
        );
        doc.text(compactPdfValue(String(row.explanation ?? ""), 170), marginX + 8, cursorY + 52);
        cursorY += 72;
      });
    }
  }

  categoryKeys.forEach((category) => {
    ensureSpace(40);
    doc.setFont("helvetica", "bold");
    doc.setFontSize(18);
    doc.setTextColor(...palette.ink);
    doc.text(category === "security" ? "Security Report" : `${titleCaseCategory(category)} Appendix`, marginX, cursorY);

    doc.setFont("helvetica", "normal");
    doc.setFontSize(11);
    doc.setTextColor(...palette.muted);
    doc.text(`${pdfFindings[category].length} checks`, pageWidth - marginX, cursorY, {
      align: "right",
    });

    cursorY += 10;
    doc.setDrawColor(...palette.border);
    doc.setLineWidth(1);
    doc.line(marginX, cursorY, pageWidth - marginX, cursorY);
    cursorY += 20;

    if (pdfFindings[category].length === 0) {
      drawTextBlock({
        text: "No checks were returned for this category.",
        fontSize: 11,
        color: palette.muted,
        gapAfter: 12,
      });
      return;
    }

    pdfFindings[category].forEach((finding) => {
      drawFindingCard(finding);
    });
    cursorY += 6;
  });

  const pageCount = doc.getNumberOfPages();
  for (let pageNumber = 1; pageNumber <= pageCount; pageNumber += 1) {
    doc.setPage(pageNumber);
    doc.setFont("helvetica", "normal");
    doc.setFontSize(9);
    doc.setTextColor(...palette.muted);
    doc.text(
      `Page ${pageNumber} of ${pageCount}`,
      pageWidth - marginX,
      pageHeight - 18,
      { align: "right" },
    );
  }

  doc.save(buildPdfFilename(scan));
}

async function fetchJson<T>(url: string) {
  const response = await fetch(url, { cache: "no-store" });
  const payload = (await response.json().catch(() => null)) as T | { error?: string } | null;

  if (!response.ok) {
    const message =
      payload && typeof payload === "object" && "error" in payload && typeof payload.error === "string"
        ? payload.error
        : "Request failed";
    throw new Error(message);
  }

  return payload as T;
}

async function fetchWorkspaceData(scanId: string) {
  const [summary, findingsPayload, eventsPayload, recentPayload] = await Promise.all([
    fetchJson<ScanSummaryResponse>(`/api/scans/${scanId}`),
    fetchJson<{ findings: ScanFinding[]; viewerCanAccessFixes: boolean }>(
      `/api/scans/${scanId}/findings`,
    ),
    fetchJson<{ events: ScanEvent[] }>(`/api/scans/${scanId}/events`),
    fetchJson<{ scans: SidebarScan[] }>(`/api/scans/recent`),
  ]);

  const grouped = emptyFindings();
  findingsPayload.findings.forEach((finding) => {
    grouped[finding.category].push(finding);
  });
  const sortedGrouped = Object.fromEntries(
    categoryKeys.map((category) => [category, sortFindings(grouped[category])]),
  ) as Record<CategoryKey, ScanFinding[]>;

  return {
    scan: summary.scan,
    findings: sortedGrouped,
    events: eventsPayload.events,
    recentScans: recentPayload.scans,
    viewerCanAccessFixes: findingsPayload.viewerCanAccessFixes,
    sessionUserId: summary.session.userId,
  };
}

function workspaceHasAllResults(
  scan: ScanRecord | null,
  findings: Record<CategoryKey, ScanFinding[]>,
) {
  return scan
    ? categoryKeys.every((category) => {
        const snapshot = scan.categoryStatus[category];
        const statusIsFinal = snapshot.status === "completed" || snapshot.status === "failed";
        const findingsAreLoaded =
          snapshot.status !== "completed" ||
          findings[category].length >= snapshot.findingCount;

        return statusIsFinal && findingsAreLoaded;
      })
    : false;
}

export function ResultsClient({ scanId }: { scanId: string }) {
  const router = useRouter();
  const pathname = usePathname();
  const searchParams = useSearchParams();
  const { user, status, isConfigured, signInWithGoogle, ensureServerSession } = useAuth();
  const [state, setState] = useState<ViewState>({
    scan: null,
    findings: emptyFindings(),
    events: [],
    recentScans: [],
    viewerCanAccessFixes: false,
    sessionUserId: null,
    error: null,
  });
  const [actionError, setActionError] = useState<string | null>(null);
  const [actionPending, setActionPending] = useState(false);
  const [downloadPending, setDownloadPending] = useState(false);
  const [reportOpen, setReportOpen] = useState(false);
  const [quota, setQuota] = useState<ScanQuotaSummary | null>(null);
  const [paypalOpen, setPaypalOpen] = useState(false);
  const [severityFilter, setSeverityFilter] = useState<"all" | ScanFinding["severity"]>("all");
  const [confidenceFilter, setConfidenceFilter] = useState<"all" | NonNullable<ScanFinding["confidence"]>>("all");
  const [confirmedOnly, setConfirmedOnly] = useState(false);
  const [attackPathOnly, setAttackPathOnly] = useState(false);
  const [publicOnly, setPublicOnly] = useState(false);
  const [recentScanQuery, setRecentScanQuery] = useState("");
  const [displayProgress, setDisplayProgress] = useState(0);
  const [progressSession, setProgressSession] = useState<ProgressSessionState>({
    scanId: null,
    sawLiveState: false,
  });

  const requestedTab = (searchParams.get("tab") as CategoryKey | null) ?? "security";
  const activeTab = categoryKeys.includes(requestedTab) ? requestedTab : "security";

  useEffect(() => {
    let cancelled = false;
    let timer: number | null = null;

    const loadWorkspace = async () => {
      try {
        if (status === "signed-in" && user) {
          await ensureServerSession();
        }

        const next = await fetchWorkspaceData(scanId);
        if (!cancelled) {
          startTransition(() => {
            setState({
              ...next,
              error: null,
            });
          });
          if (!workspaceHasAllResults(next.scan, next.findings)) {
            timer = window.setTimeout(() => {
              void loadWorkspace();
            }, 2500);
          }
        }
      } catch (error) {
        const message = error instanceof Error ? error.message : "Unable to load the report.";
        if (!cancelled) {
          startTransition(() => {
            setState((current) => ({ ...current, error: message }));
          });
          timer = window.setTimeout(() => {
            void loadWorkspace();
          }, 5000);
        }
      }
    };

    void loadWorkspace();

    return () => {
      cancelled = true;
      if (timer !== null) {
        window.clearTimeout(timer);
      }
    };
  }, [ensureServerSession, scanId, status, user]);

  const scan = state.scan;
  const progressTarget = scan ? Math.max(0, Math.min(100, scan.progress)) : 0;
  const allResultsReady = workspaceHasAllResults(scan, state.findings);
  const liveProgressHoldPercent = scan ? getLiveProgressHoldPercent(scan.id) : 98;
  const displayProgressCap = allResultsReady ? 100 : liveProgressHoldPercent;
  const progressTargetForDisplay = allResultsReady
    ? 100
    : getLiveProgressTarget(progressTarget, liveProgressHoldPercent);
  const isLiveProgressState = scan ? !allResultsReady : false;
  const isFinishedProgressState = allResultsReady;
  const isNewProgressSession = scan ? progressSession.scanId !== scan.id : false;
  const openedFinishedScan = scan
    ? isFinishedProgressState && (isNewProgressSession || !progressSession.sawLiveState)
    : false;
  const visibleProgress = scan
    ? openedFinishedScan
      ? 100
      : isNewProgressSession
        ? Math.min(progressTargetForDisplay, 15)
        : Math.min(displayProgress, displayProgressCap)
    : displayProgress;
  const showCompletionAnimation = allResultsReady && visibleProgress >= 100;

  useEffect(() => {
    if (!scan) {
      return;
    }

    if (progressSession.scanId !== scan.id) {
      const initialProgress = isFinishedProgressState ? 100 : Math.min(progressTargetForDisplay, 15);
      const timer = window.setTimeout(() => {
        setProgressSession({
          scanId: scan.id,
          sawLiveState: isLiveProgressState,
        });
        setDisplayProgress(initialProgress);
      }, 0);

      return () => {
        window.clearTimeout(timer);
      };
    }

    if (isLiveProgressState && !progressSession.sawLiveState) {
      const timer = window.setTimeout(() => {
        setProgressSession((current) =>
          current.scanId === scan.id ? { ...current, sawLiveState: true } : current,
        );
      }, 0);

      return () => {
        window.clearTimeout(timer);
      };
    }
  }, [
    isFinishedProgressState,
    isLiveProgressState,
    progressSession.scanId,
    progressSession.sawLiveState,
    progressTargetForDisplay,
    scan,
  ]);

  useEffect(() => {
    if (!scan) {
      return;
    }

    const prefersReducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    const openedCompletedReport =
      isFinishedProgressState && !progressSession.sawLiveState;

    if (openedCompletedReport || prefersReducedMotion) {
      const immediateProgress = isFinishedProgressState ? 100 : progressTargetForDisplay;
      const timer = window.setTimeout(() => {
        setDisplayProgress(immediateProgress);
      }, 0);

      return () => {
        window.clearTimeout(timer);
      };
    }

    if (displayProgress >= progressTargetForDisplay) {
      return;
    }

    const delay = getProgressAnimationDelay(
      displayProgress,
      progressTargetForDisplay,
      isFinishedProgressState,
    );
    const timer = window.setTimeout(() => {
      setDisplayProgress((current) => {
        if (progressSession.scanId !== scan.id) {
          return current;
        }

        if (isFinishedProgressState) {
          return Math.min(100, current + 1);
        }

        return Math.min(progressTargetForDisplay, current + 1);
      });
    }, delay);

    return () => {
      window.clearTimeout(timer);
    };
  }, [
    displayProgress,
    isFinishedProgressState,
    progressSession.scanId,
    progressSession.sawLiveState,
    progressTargetForDisplay,
    scan,
  ]);

  const attackSurfaceSummary = useMemo(
    () => extractAttackSurfaceSummary(state.findings),
    [state.findings],
  );
  const categoryCards = useMemo(
    () =>
      categoryKeys.map((category) => {
        const snapshot = scan?.categoryStatus[category];
        const findings = reportableFindingsForCategory(state.findings[category]);
        const count = findings.length;
        const { passCount, failCount } = summarizeFindingCounts(findings);
        const score =
          category === "security"
            ? attackSurfaceSummary?.security.score ?? scan?.securityScore ?? null
            : category === "seo"
              ? scan?.seoScore ?? null
              : scan?.performanceScore ?? null;

        return {
          category,
          status: snapshot?.status ?? "queued",
          count,
          passCount,
          failCount,
          score,
        };
      }),
    [attackSurfaceSummary, scan, state.findings],
  );

  const rawActiveFindings = state.findings[activeTab].filter(
    (finding) => !isAttackSurfaceSummaryFinding(finding),
  );
  const latestEvent = state.events[0] ?? null;
  const progressSteps = useMemo<ProgressStep[]>(() => {
    if (!scan) {
      return [];
    }

    const hasStarted =
      scan.progress > 10 ||
      state.events.length > 0 ||
      categoryCards.some((item) => item.status !== "queued");
    const reportStatus: ProgressStepStatus = allResultsReady
      ? "completed"
      : scan.status === "failed"
        ? "failed"
        : scan.status === "queued"
          ? "queued"
          : "running";

    return [
      {
        label: "Discovery",
        status: hasStarted ? "completed" : "running",
        active: !hasStarted,
      },
      ...categoryCards.map((item) => ({
        label: item.category === "seo" ? "SEO" : titleCaseCategory(item.category),
        status: item.status,
        active: item.status === "running",
      })),
      {
        label: "Report",
        status: reportStatus,
        active:
          reportStatus === "running" &&
          !categoryCards.some((item) => item.status === "running"),
      },
    ];
  }, [allResultsReady, categoryCards, scan, state.events.length]);
  const activeProgressStepIndex = progressSteps.findIndex((step) => step.active);
  const progressStepCounter = progressSteps.length
    ? `${activeProgressStepIndex >= 0 ? activeProgressStepIndex + 1 : progressSteps.length}/${progressSteps.length}`
    : null;
  const currentProgressMessage = allResultsReady
    ? "Report ready. All checks completed."
    : latestEvent?.message ??
      (activeProgressStepIndex >= 0
        ? `${progressSteps[activeProgressStepIndex]?.label} ${formatProgressStatus(progressSteps[activeProgressStepIndex]?.status ?? "queued")}.`
        : scan?.latestPhase ?? "Preparing scan.");
  const progressNarrative = allResultsReady
    ? "All scan results are loaded and the report is ready."
    : scan?.status === "partial-results"
      ? "Initial results are ready. Deeper browser and active checks are still updating this report live."
    : visibleProgress >= liveProgressHoldPercent
      ? "Finalizing evidence and report output before marking the scan complete."
      : "Live checks are running across discovery, security, SEO, and performance.";
  const allFindings = useMemo(
    () =>
      categoryKeys
        .flatMap((category) => state.findings[category])
        .filter((finding) => !isAttackSurfaceSummaryFinding(finding)),
    [state.findings],
  );
  const effectiveSecurityScore = attackSurfaceSummary?.security.score ?? scan?.securityScore ?? null;
  const effectiveOverallScore = scan
    ? computeDisplayOverallScore(
        effectiveSecurityScore,
        scan.seoScore,
        scan.performanceScore,
        scan.overallScore,
      )
    : null;
  const criticalIssueCount = useMemo(
    () =>
      allFindings.filter(
        (finding) => deriveFindingStatus(finding) === "fail" && finding.severity === "critical",
      ).length,
    [allFindings],
  );
  const warningIssueCount = useMemo(
    () => allFindings.filter((finding) => deriveFindingStatus(finding) === "warning").length,
    [allFindings],
  );
  const failingIssueCount = useMemo(
    () => allFindings.filter((finding) => deriveFindingStatus(finding) === "fail").length,
    [allFindings],
  );
  const overallCounts = useMemo(() => summarizeFindingCounts(allFindings), [allFindings]);
  const reportMetricCards = [
    {
      label: "Overall",
      score: effectiveOverallScore,
      count: allFindings.length,
      passCount: overallCounts.passCount,
      failCount: overallCounts.failCount,
    },
    ...categoryCards.map((item) => ({
      label: titleCaseCategory(item.category),
      score: item.score,
      count: item.count,
      passCount: item.passCount,
      failCount: item.failCount,
    })),
  ];
  const activeFindings = sortFindings(
    rawActiveFindings.filter((finding) => {
      if (severityFilter !== "all" && finding.severity !== severityFilter) {
        return false;
      }
      if (confidenceFilter !== "all" && (finding.confidence ?? "info") !== confidenceFilter) {
        return false;
      }
      if (confirmedOnly && (finding.confidence ?? "info") !== "confirmed") {
        return false;
      }
      if (attackPathOnly && !finding.attackPathParticipant) {
        return false;
      }
      if (publicOnly && !finding.publicEndpoint) {
        return false;
      }
      return true;
    }),
  );
  const reportFindingsByCategory = Object.fromEntries(
    categoryKeys.map((category) => [
      category,
      sortFindings(
        state.findings[category].filter((finding) => !isAttackSurfaceSummaryFinding(finding)),
      ),
    ]),
  ) as Record<CategoryKey, ScanFinding[]>;
  const filteredRecentScans = useMemo(() => {
    const query = recentScanQuery.trim().toLowerCase();
    if (!query) {
      return state.recentScans;
    }

    return state.recentScans.filter((recent) =>
      [
        recent.targetHostname,
        recent.status,
        recent.id,
        formatRelative(recent.createdAt),
      ]
        .join(" ")
        .toLowerCase()
        .includes(query),
    );
  }, [recentScanQuery, state.recentScans]);

  const handleChangeTab = (tab: CategoryKey) => {
    const nextParams = new URLSearchParams(searchParams.toString());
    nextParams.set("tab", tab);
    router.replace(`${pathname}?${nextParams.toString()}`, { scroll: false });
  };

  const refreshWorkspace = async () => {
    const next = await fetchWorkspaceData(scanId);
    setState({
      ...next,
      error: null,
    });
  };

  const handleContinueWithGoogle = async () => {
    setActionError(null);

    if (!isConfigured) {
      setActionError("Firebase client setup is missing, so Google sign-in is disabled.");
      return;
    }

    setActionPending(true);
    try {
      const sessionUser =
        user && status === "signed-in" ? await ensureServerSession() : await signInWithGoogle();
      const normalizedSessionEmail = sessionUser.email?.trim().toLowerCase() ?? null;
      const shouldClaimScan =
        Boolean(scan?.isAnonymous) ||
        Boolean(scan?.createdByUserId === sessionUser.uid) ||
        Boolean(
          normalizedSessionEmail &&
            scan?.createdByUserEmail?.trim().toLowerCase() === normalizedSessionEmail,
        );

      if (shouldClaimScan) {
        const claimResponse = await fetch(`/api/scans/${scanId}/claim`, { method: "POST" });
        const claimPayload = (await claimResponse.json().catch(() => null)) as
          | { error?: string; code?: string; details?: unknown }
          | null;
        if (!claimResponse.ok) {
          if (
            claimPayload?.code === "SCAN_QUOTA_EXCEEDED" &&
            claimPayload.details &&
            typeof claimPayload.details === "object"
          ) {
            setQuota(claimPayload.details as ScanQuotaSummary);
            setPaypalOpen(true);
          }
          throw new Error(claimPayload?.error ?? "Unable to link this scan.");
        }

        dispatchQuotaRefresh();
      }

      await refreshWorkspace();
    } catch (error) {
      setActionError(error instanceof Error ? error.message : "Unable to continue with Google.");
    } finally {
      setActionPending(false);
    }
  };

  const handleDownloadPdf = async () => {
    if (!scan) {
      return;
    }

    setActionError(null);
    setDownloadPending(true);

    try {
      await downloadReportPdf(scan, state.findings);
    } catch (error) {
      setActionError(
        error instanceof Error ? error.message : "Unable to generate the PDF report.",
      );
    } finally {
      setDownloadPending(false);
    }
  };

  if (!scan && !state.error) {
    return (
      <div className="workspace-gradient min-h-screen">
        <div className="mx-auto flex min-h-screen max-w-[1440px] items-start gap-6 px-6 py-24">
          <div className="h-[700px] w-72 animate-pulse rounded-[2rem] bg-white/60" />
          <div className="flex-1 space-y-6">
            <div className="h-52 animate-pulse rounded-[2rem] bg-white/60" />
            <div className="h-20 animate-pulse rounded-[2rem] bg-white/60" />
            <div className="h-48 animate-pulse rounded-[2rem] bg-white/60" />
          </div>
        </div>
      </div>
    );
  }

  if (state.error || !scan) {
    return (
      <div className="workspace-gradient min-h-screen px-6 py-24">
        <div className="glass-panel mx-auto max-w-[820px] rounded-[2rem] p-10">
          <p className="text-xs font-bold uppercase tracking-[0.22em] text-[var(--danger)]">
            Report unavailable
          </p>
          <h1 className="mt-4 text-4xl font-semibold tracking-[-0.03em] text-slate-900">
            {state.error ?? "The report could not be loaded."}
          </h1>
          <p className="mt-4 max-w-[620px] text-sm leading-7 text-slate-500">
            This scan may have expired, storage may not be configured yet, or the current link is invalid. Start a new scan to generate a fresh live report.
          </p>
          <button
            type="button"
            onClick={() => router.push("/")}
            className="mt-8 rounded-full bg-[var(--primary)] px-6 py-3 text-sm font-semibold text-white transition-all hover:bg-[#004ca1]"
          >
            Start a new scan
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="workspace-gradient min-h-screen overflow-x-hidden text-[var(--ink)]">
      <div className="mx-auto flex w-full min-w-0 max-w-[1440px] pt-16">
        <aside className="soft-scrollbar sticky top-16 hidden h-[calc(100vh-64px)] w-72 shrink-0 flex-col overflow-y-auto border-r border-white/20 bg-white/40 px-6 py-8 shadow-[10px_0_40px_rgba(0,0,0,0.02)] backdrop-blur-[30px] lg:flex">
          <div className="mb-8">
            <h3 className="text-lg font-black text-blue-600">fixnx</h3>
            <p className="mt-1 text-xs font-medium text-slate-500">
              Live website scan workspace
            </p>
          </div>

          <div className="flex flex-1 flex-col gap-6">
            <div>
              <span className="mb-4 block px-4 text-[10px] font-bold uppercase tracking-[0.24em] text-slate-400">
                Navigation
              </span>
              <div className="space-y-2">
                <div className="flex items-center gap-3 rounded-full bg-blue-600 px-4 py-3 text-white shadow-[0_4px_12px_rgba(0,122,255,0.3)]">
                  <Shield className="h-4 w-4" />
                  <span className="text-sm font-semibold">Home</span>
                </div>
                <button
                  type="button"
                  onClick={() => router.push("/history")}
                  className="flex w-full items-center gap-3 rounded-full px-4 py-3 text-slate-600 transition-all hover:bg-white/40"
                >
                  <History className="h-4 w-4" />
                  <span className="text-sm font-medium">Scans</span>
                </button>
              </div>
            </div>

            <div className="min-h-0 flex-1">
              <label className="relative mb-3 block px-1">
                <Search className="pointer-events-none absolute left-4 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-400" />
                <input
                  type="search"
                  value={recentScanQuery}
                  onChange={(event) => setRecentScanQuery(event.target.value)}
                  placeholder="Search scans"
                  className="h-10 w-full rounded-full border border-white/70 bg-white/70 pl-10 pr-4 text-sm font-medium text-slate-700 shadow-sm outline-none transition-all placeholder:text-slate-400 focus:border-blue-200 focus:bg-white focus:ring-4 focus:ring-blue-100/70"
                  aria-label="Search recent scans"
                />
              </label>
              <span className="mb-4 block px-4 text-[10px] font-bold uppercase tracking-[0.24em] text-slate-400">
                Your Scans
              </span>
              <div className="soft-scrollbar max-h-[320px] space-y-1 overflow-y-auto pr-2">
                {state.recentScans.length ? (
                  filteredRecentScans.length ? (
                    filteredRecentScans.map((recent) => (
                      <button
                        key={recent.id}
                        type="button"
                        onClick={() => router.push(`/scans/${recent.id}`)}
                        className={cn(
                          "w-full rounded-[1rem] p-3 text-left transition-all hover:bg-white/60",
                          recent.id === scanId && "bg-white/70 shadow-sm",
                        )}
                      >
                        <p className="text-sm font-medium text-slate-900">{recent.targetHostname}</p>
                        <p className="mt-1 text-[11px] text-slate-500">
                          {recent.id === scanId
                            ? `Current scan • ${recent.progress}%`
                            : `Last scan ${formatRelative(recent.createdAt)}`}
                        </p>
                      </button>
                    ))
                  ) : (
                    <div className="rounded-[1rem] bg-white/50 p-4 text-sm text-slate-500">
                      No scans match this search.
                    </div>
                  )
                ) : (
                  <div className="rounded-[1rem] bg-white/50 p-4 text-sm text-slate-500">
                    Recent scans will appear here.
                  </div>
                )}
              </div>
            </div>
          </div>

          <button
            type="button"
            onClick={() => router.push("/#scan-launch")}
            className="mt-8 w-full rounded-full bg-[var(--primary)] px-5 py-4 text-sm font-bold text-white shadow-lg shadow-[var(--primary)]/20 transition-all active:scale-[0.98]"
          >
            New Scan
          </button>
        </aside>

        <main className="min-w-0 flex-1 px-5 py-8 md:px-10 md:py-12">
          <div className="glass-panel min-w-0 overflow-hidden rounded-[2rem] p-6 shadow-[0_8px_32px_rgba(0,0,0,0.03)] md:p-8">
            <div className="grid min-w-0 gap-8 lg:grid-cols-[minmax(0,1fr)_240px]">
              <div className="min-w-0">
                <div className="mb-4 flex min-w-0 flex-wrap items-center gap-3">
                  <span className="shrink-0 rounded-full bg-blue-50 px-3 py-1 text-[11px] font-bold uppercase tracking-[0.18em] text-blue-600">
                    Live Analysis
                  </span>
                  <span className="scan-phase-pill inline-flex w-full min-w-0 max-w-full items-center gap-2 overflow-hidden rounded-full bg-white/75 px-3 py-1 text-sm text-slate-500 shadow-sm sm:w-auto">
                    <span
                      className={cn(
                        "loader-dot inline-flex shrink-0",
                        scan.status === "completed"
                          ? "text-[var(--success)]"
                          : scan.status === "failed"
                            ? "text-[var(--danger)]"
                            : "text-[var(--primary)]",
                      )}
                    />
                    <span className="min-w-0 flex-1 truncate">{currentProgressMessage}</span>
                    {progressStepCounter ? (
                      <span className="hidden shrink-0 rounded-full bg-slate-100 px-2 py-0.5 text-[10px] font-bold uppercase tracking-[0.12em] text-slate-500 sm:inline-flex">
                        Step {progressStepCounter}
                      </span>
                    ) : null}
                  </span>
                </div>
                <h1 className="break-words text-4xl font-semibold tracking-[-0.03em] text-slate-900 md:text-5xl">
                  {scan.targetHostname}
                </h1>
                <div className="mt-6 flex min-w-0 items-end justify-between gap-4">
                  <div className="min-w-0">
                    <p className="text-sm font-medium text-slate-500">Overall progress</p>
                    <p className="mt-1 break-words text-xs uppercase tracking-[0.2em] text-slate-400">
                      {scan.status}
                    </p>
                  </div>
                  <div className="text-right">
                    <div className="flex items-center justify-end gap-2">
                      {showCompletionAnimation ? (
                        <span className="scan-complete-check inline-flex h-7 w-7 items-center justify-center rounded-full bg-emerald-50 text-emerald-600 ring-1 ring-emerald-200">
                          <CheckCircle2 className="h-4 w-4" />
                        </span>
                      ) : null}
                      <span className="text-3xl font-semibold text-[var(--primary)]">
                        {visibleProgress}%
                      </span>
                    </div>
                    <p className="text-xs font-semibold uppercase tracking-[0.18em] text-slate-400">
                      Audited
                    </p>
                  </div>
                </div>
                <div className="mt-4 h-3 overflow-hidden rounded-full bg-slate-100 shadow-inner">
                  <div
                    className={cn(
                      "progress-stripes h-full rounded-full bg-[var(--primary)] shadow-[0_0_20px_rgba(0,88,188,0.35)] transition-all duration-700",
                      scan.status === "completed" && "after:hidden",
                      showCompletionAnimation && "completion-bar-finish",
                    )}
                    style={{ width: `${visibleProgress}%` }}
                  />
                </div>
                <p className="mt-4 break-words text-sm text-slate-500">{progressNarrative}</p>
                <div className="mt-4 flex min-w-0 max-w-full flex-wrap gap-2">
                  {progressSteps.map((step) => (
                    <span
                      key={step.label}
                      className={cn(
                        "inline-flex min-w-0 max-w-full items-center gap-2 overflow-hidden rounded-full border px-3 py-1.5 text-[11px] font-semibold shadow-sm transition-colors",
                        step.status === "completed" &&
                          "border-emerald-100 bg-emerald-50 text-emerald-700",
                        step.status === "running" &&
                          "border-blue-100 bg-blue-50 text-blue-700",
                        step.status === "failed" && "border-rose-100 bg-rose-50 text-rose-700",
                        step.status === "queued" &&
                          "border-white/70 bg-white/65 text-slate-500",
                      )}
                    >
                      <span
                        className={cn(
                          "h-2 w-2 shrink-0 rounded-full",
                          step.status === "completed" && "bg-emerald-500",
                          step.status === "running" && "bg-blue-500",
                          step.status === "failed" && "bg-rose-500",
                          step.status === "queued" && "bg-slate-300",
                        )}
                      />
                      <span className="min-w-0 truncate">{step.label}</span>
                      <span className="shrink-0 text-[10px] uppercase tracking-[0.12em] opacity-70">
                        {formatProgressStatus(step.status)}
                      </span>
                    </span>
                  ))}
                </div>
                {scan.status === "partial-results" ? (
                  <div className="mt-4 break-words rounded-[1.25rem] border border-emerald-100 bg-emerald-50/80 px-4 py-3 text-sm leading-6 text-emerald-800">
                    <span className="font-semibold">Initial results are ready.</span>{" "}
                    You can review the findings now while deeper checks continue in the background.
                  </div>
                ) : null}
                <div className="mt-6 grid gap-3 md:grid-cols-3">
                  {categoryCards.map((item) => (
                    <div key={item.category} className="min-w-0 rounded-[1.3rem] bg-white/55 p-4">
                      <div className="flex items-center justify-between gap-3">
                        <div className="min-w-0">
                          <p className="text-xs font-bold uppercase text-slate-500">
                            {titleCaseCategory(item.category)}
	                          </p>
	                          <p className="mt-1 text-xs font-semibold text-slate-500">
	                            {item.category === "security" && attackSurfaceSummary?.security.riskLabel
	                              ? `Risk ${attackSurfaceSummary.security.riskLabel} | Score ${item.score ?? "--"}/100`
	                              : `Score ${formatScorePercent(item.score)}`}
	                          </p>
                        </div>
                        <span
                          className={cn(
                            "shrink-0 rounded-full px-3 py-1 text-[10px] font-bold uppercase",
                            item.status === "completed" && "bg-emerald-50 text-emerald-700",
                            item.status === "running" && "bg-blue-50 text-blue-700",
                            item.status === "failed" && "bg-red-50 text-red-700",
                            item.status === "queued" && "bg-slate-100 text-slate-500",
                          )}
                        >
                          {item.status}
                        </span>
                      </div>
                      <div className="mt-4 grid grid-cols-2 gap-2">
                        <div className="rounded-[1rem] bg-emerald-50 px-3 py-2">
                          <p className="text-lg font-bold text-emerald-700">{item.passCount}</p>
                          <p className="text-[11px] font-semibold text-emerald-700">passed</p>
                        </div>
                        <div className="rounded-[1rem] bg-rose-50 px-3 py-2">
                          <p className="text-lg font-bold text-rose-700">{item.failCount}</p>
                          <p className="text-[11px] font-semibold text-rose-700">failed</p>
                        </div>
                      </div>
                      <p className="mt-3 text-xs text-slate-500">{item.count} total checks</p>
                    </div>
                  ))}
                </div>
              </div>

              <div className="glass-panel min-w-0 flex flex-col items-center justify-center rounded-[2rem] bg-white/70 p-5 sm:p-6">
                <div
                  className="score-ring-modern h-36 w-36 sm:h-40 sm:w-40"
                  style={
                    {
                      "--score": effectiveOverallScore ?? scan.progress,
                      "--ring-color": getScoreTone(effectiveOverallScore),
                    } as CSSProperties
                  }
                >
                  <div className="relative z-10 flex flex-col items-center">
                    <span className="text-4xl font-semibold text-slate-900 sm:text-5xl">
                      {formatScorePercent(effectiveOverallScore)}
                    </span>
                    <span className="mt-1 text-xs font-semibold uppercase text-slate-400">
                      Overall
                    </span>
                  </div>
                </div>
                <p className="mt-5 text-sm text-slate-500">
                  Updated {formatRelative(scan.updatedAt)}
                </p>
                <div className="mt-4 grid w-full grid-cols-2 gap-2 text-center">
                  <div className="rounded-[1rem] bg-emerald-50 px-3 py-2">
                    <p className="text-base font-bold text-emerald-700">{overallCounts.passCount}</p>
                    <p className="text-[11px] font-semibold text-emerald-700">passed</p>
                  </div>
                  <div className="rounded-[1rem] bg-rose-50 px-3 py-2">
                    <p className="text-base font-bold text-rose-700">{overallCounts.failCount}</p>
                    <p className="text-[11px] font-semibold text-rose-700">failed</p>
                  </div>
                </div>
              </div>
            </div>
          </div>

          {attackSurfaceSummary ? (
            <section className="mt-6 rounded-[2rem] border border-white/70 bg-white/65 p-5 shadow-[0_12px_48px_rgba(15,23,42,0.05)]">
              <div className="flex flex-col gap-3 md:flex-row md:items-start md:justify-between">
                <div>
                  <p className="text-xs font-bold uppercase tracking-[0.18em] text-[var(--primary)]">
                    Attack Surface Summary
                  </p>
                  <p className="mt-2 text-sm leading-7 text-slate-500">
                    Scan mode {attackSurfaceSummary.scanMode}. {attackSurfaceSummary.recommendedFirstLabel}:{" "}
                    <span className="font-semibold text-slate-800">
                      {attackSurfaceSummary.recommendedFirstFix}
                    </span>
                  </p>
                  {attackSurfaceSummary.coverageConfidence ? (
                    <p className="mt-1 text-sm leading-7 text-slate-500">
                      Coverage Confidence:{" "}
                      <span className="font-semibold text-slate-800">
                        {nestedString(attackSurfaceSummary.coverageConfidence, "level") || "Unknown"}
                      </span>
                      . {nestedString(attackSurfaceSummary.coverageConfidence, "explanation")}
                    </p>
                  ) : null}
                </div>
                <span className="inline-flex w-fit rounded-full border border-blue-100 bg-blue-50 px-3 py-1 text-[10px] font-bold uppercase text-blue-700">
                  Security report default
                </span>
              </div>
              <div className="mt-4 grid gap-2 sm:grid-cols-2 lg:grid-cols-5">
                {attackSurfaceSummary.metrics.slice(0, 10).map((metric) => (
                  <div
                    key={`surface-${metric.label}`}
                    className="rounded-[1.1rem] border border-white/70 bg-white/75 px-3 py-2"
                  >
                    <p className="text-lg font-bold text-slate-900">{metric.value}</p>
                    <p className="text-[10px] font-bold uppercase tracking-[0.12em] text-slate-500">
                      {metric.label}
                    </p>
                  </div>
                ))}
              </div>
            </section>
          ) : null}

          <section className="mt-6 grid gap-3 sm:grid-cols-2 xl:grid-cols-6">
            {[
              {
                label: "Confirmed Exploitable Vulnerabilities",
                value:
                  attackSurfaceSummary?.metrics.find((metric) => metric.label === "Confirmed exploitable vulnerabilities")?.value ??
                  allFindings.filter(isConfirmedExploitableFinding).length,
              },
              {
                label: "Supporting Evidence",
                value:
                  attackSurfaceSummary?.metrics.find((metric) => metric.label === "Supporting evidence")?.value ?? 0,
              },
              { label: "Critical Issues", value: criticalIssueCount },
              {
                label: "Attack Paths",
                value: attackSurfaceSummary?.primaryAttackPath ? 1 : 0,
              },
              {
                label: "Public APIs",
                value:
                  attackSurfaceSummary?.metrics.find((metric) => metric.label === "Public APIs")?.value ?? 0,
              },
              {
                label: "Sensitive Endpoints",
                value:
                  attackSurfaceSummary?.metrics.find((metric) => metric.label === "Sensitive endpoints")?.value ?? 0,
              },
            ].map((card) => (
              <div
                key={`risk-card-${card.label}`}
                className="rounded-[1.35rem] border border-white/70 bg-white/70 px-4 py-3 shadow-[0_10px_30px_rgba(15,23,42,0.05)]"
              >
                <p className="text-2xl font-bold text-slate-900">{card.value}</p>
                <p className="mt-1 text-[10px] font-bold uppercase tracking-[0.12em] text-slate-500">
                  {card.label}
                </p>
              </div>
            ))}
          </section>

          <div className="mt-8 flex flex-col items-start justify-between gap-5 xl:flex-row xl:items-center">
            <div className="flex flex-wrap gap-2 rounded-full bg-white/50 p-1.5 shadow-sm backdrop-blur-xl">
                  {categoryCards.map((item) => (
                <button
                  key={item.category}
                  type="button"
                  onClick={() => handleChangeTab(item.category)}
                  className={cn(
                    "rounded-full px-6 py-2.5 text-sm font-semibold transition-all",
                    activeTab === item.category
                      ? "bg-white text-[var(--primary)] shadow-sm"
                      : "text-slate-500 hover:text-slate-800",
                  )}
                >
                  {item.category === "security" ? "Security" : `${titleCaseCategory(item.category)} appendix`}
                </button>
              ))}
            </div>
            <div className="grid w-full grid-cols-2 gap-3 sm:flex sm:w-auto sm:flex-wrap sm:items-center">
              <button
                type="button"
                onClick={() => setReportOpen(true)}
                className="inline-flex min-w-0 items-center justify-center gap-2 rounded-full border border-white/50 bg-white px-3 py-3 text-xs font-semibold text-slate-700 shadow-sm transition-all hover:shadow-md sm:px-6 sm:text-sm"
              >
                <FileText className="h-4 w-4 text-[var(--primary)]" />
                Full Report
              </button>
              <button
                type="button"
                onClick={() => void handleContinueWithGoogle()}
                disabled={actionPending || state.viewerCanAccessFixes || !isConfigured}
                className="inline-flex min-w-0 items-center justify-center gap-2 rounded-full border border-white/50 bg-white px-3 py-3 text-xs font-semibold text-slate-700 shadow-sm transition-all hover:shadow-md disabled:cursor-not-allowed disabled:opacity-60 sm:px-6 sm:text-sm"
              >
                <Wrench className="h-4 w-4 text-[var(--primary)]" />
                {!isConfigured
                  ? "Google login unavailable"
                  : state.viewerCanAccessFixes
                    ? "Google connected"
                    : "Sign in"}
              </button>
            </div>
          </div>

          {actionError ? (
            <p className="mt-4 text-sm font-medium text-[var(--danger)]">{actionError}</p>
          ) : null}

          <div className="mt-5 flex flex-wrap items-center gap-2 rounded-[1.5rem] border border-white/70 bg-white/55 p-3">
            <select
              value={severityFilter}
              onChange={(event) => setSeverityFilter(event.target.value as typeof severityFilter)}
              className="h-10 rounded-full border border-slate-200 bg-white px-3 text-xs font-semibold text-slate-600 outline-none"
            >
              <option value="all">All severities</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
              <option value="info">Info</option>
            </select>
            <select
              value={confidenceFilter}
              onChange={(event) => setConfidenceFilter(event.target.value as typeof confidenceFilter)}
              className="h-10 rounded-full border border-slate-200 bg-white px-3 text-xs font-semibold text-slate-600 outline-none"
            >
              <option value="all">All confidence</option>
              <option value="confirmed">Confirmed</option>
              <option value="likely">Likely</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
              <option value="info">Info</option>
            </select>
            {[
              ["Confirmed only", confirmedOnly, setConfirmedOnly],
              ["Attack path only", attackPathOnly, setAttackPathOnly],
              ["Public endpoint only", publicOnly, setPublicOnly],
            ].map(([label, enabled, setter]) => (
              <button
                key={label as string}
                type="button"
                onClick={() => (setter as (value: boolean) => void)(!(enabled as boolean))}
                className={cn(
                  "h-10 rounded-full border px-3 text-xs font-semibold transition-colors",
                  enabled
                    ? "border-blue-200 bg-blue-50 text-blue-700"
                    : "border-slate-200 bg-white text-slate-600",
                )}
              >
                {label as string}
              </button>
            ))}
          </div>

          <div
            id="threats-panel"
            className="soft-scrollbar mt-8 space-y-6 overflow-y-auto pb-10"
          >
            {activeFindings.length ? (
              activeFindings.map((finding) => (
                <FindingCard
                  key={finding.id}
                  finding={finding}
                  onUnlock={handleContinueWithGoogle}
                  unlockDisabled={actionPending || state.viewerCanAccessFixes || !isConfigured}
                />
              ))
            ) : (
              <div className="glass-panel rounded-[2rem] bg-white/60 p-8 text-center">
                <div className="mx-auto inline-flex h-12 w-12 items-center justify-center rounded-full bg-blue-50 text-blue-600">
                  <Clock3 className="h-5 w-5" />
                </div>
                <p className="mt-4 text-lg font-semibold text-slate-900">
                  {titleCaseCategory(activeTab)} checks are still running
                </p>
                <p className="mt-2 text-sm leading-7 text-slate-500">
                  The worker is still collecting checks. Stay on this page and the results will stream in automatically.
                </p>
              </div>
            )}
          </div>
        </main>
      </div>

      <PaypalScansDialog
        open={paypalOpen}
        quota={quota}
        onClose={() => setPaypalOpen(false)}
        onApproved={async (nextQuota) => {
          setQuota(nextQuota);
          setPaypalOpen(false);
          dispatchQuotaRefresh();
          await handleContinueWithGoogle();
        }}
      />

      {reportOpen && scan ? (
        <div className="fixed inset-0 z-[70] flex items-center justify-center bg-slate-950/45 px-4 py-8 backdrop-blur-[6px]">
          <div className="relative flex h-[min(860px,92vh)] w-full max-w-[1140px] flex-col overflow-hidden rounded-[2.2rem] border border-white/60 bg-[linear-gradient(180deg,rgba(255,255,255,0.98),rgba(248,250,252,0.96))] shadow-[0_30px_120px_rgba(15,23,42,0.24)]">
            <div className="flex flex-col gap-4 border-b border-slate-200/80 bg-white/75 px-5 py-5 backdrop-blur-xl sm:flex-row sm:items-start sm:justify-between sm:px-6">
              <div>
                <p className="text-xs font-bold uppercase text-[var(--primary)]">
                  Full Report
                </p>
                <h2 className="mt-2 break-words text-2xl font-semibold text-slate-900 sm:text-3xl">
                  {scan.targetHostname}
                </h2>
                <div className="mt-3 flex flex-wrap items-center gap-2">
                  {criticalIssueCount > 0 ? (
                    <span className="rounded-full border border-red-200 bg-red-50 px-3 py-1 text-[10px] font-bold uppercase text-red-700">
                      {criticalIssueCount} Critical Issues Found
                    </span>
                  ) : null}
                  {failingIssueCount > 0 && criticalIssueCount === 0 ? (
                    <span className="rounded-full border border-rose-200 bg-rose-50 px-3 py-1 text-[10px] font-bold uppercase text-rose-700">
                      {failingIssueCount} Failing Checks
                    </span>
                  ) : null}
                  {warningIssueCount > 0 ? (
                    <span className="rounded-full border border-amber-200 bg-amber-50 px-3 py-1 text-[10px] font-bold uppercase text-amber-700">
                      {warningIssueCount} Warnings
                    </span>
                  ) : null}
                </div>
                <p className="mt-2 text-sm text-slate-500">
                  Updated {formatRelative(scan.updatedAt)} • {scan.status}
                </p>
              </div>
              <div className="flex w-full items-center justify-between gap-3 sm:w-auto sm:justify-end">
                <button
                  type="button"
                  onClick={handleDownloadPdf}
                  disabled={downloadPending}
                  className="inline-flex min-w-0 flex-1 items-center justify-center gap-2 rounded-full border border-slate-200 bg-white px-4 py-2.5 text-sm font-semibold text-slate-800 shadow-sm transition-colors hover:bg-slate-50 disabled:cursor-not-allowed disabled:opacity-60 sm:flex-none sm:px-5"
                >
                  <Download className="h-4 w-4 text-[var(--primary)]" />
                  {downloadPending ? "Preparing PDF..." : "Download PDF"}
                </button>
                <button
                  type="button"
                  onClick={() => setReportOpen(false)}
                  className="inline-flex h-11 w-11 items-center justify-center rounded-full border border-slate-200 bg-white text-slate-600 transition-colors hover:bg-slate-50"
                >
                  <X className="h-5 w-5" />
                </button>
              </div>
            </div>

            <div className="overflow-y-auto px-6 py-6">
              <div className="rounded-[2rem] border border-white/70 bg-[linear-gradient(180deg,rgba(255,255,255,0.95),rgba(244,247,255,0.88))] p-5 shadow-[0_12px_48px_rgba(15,23,42,0.06)]">
                <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
                  {reportMetricCards.map((metric) => (
                    <div
                      key={`report-metric-${metric.label}`}
                      className="rounded-[1.5rem] border border-white/80 bg-white/80 p-4 shadow-[0_10px_28px_rgba(148,163,184,0.08)]"
                    >
                      <p className="text-[11px] font-bold uppercase text-slate-500">
                        {metric.label}
                      </p>
                      <div className="mt-3 grid grid-cols-2 gap-2">
                        <div className="rounded-[1rem] bg-emerald-50 px-3 py-2">
                          <p className="text-2xl font-bold text-emerald-700">{metric.passCount}</p>
                          <p className="text-[11px] font-semibold text-emerald-700">passed</p>
                        </div>
                        <div className="rounded-[1rem] bg-rose-50 px-3 py-2">
                          <p className="text-2xl font-bold text-rose-700">{metric.failCount}</p>
                          <p className="text-[11px] font-semibold text-rose-700">failed</p>
                        </div>
                      </div>
	                      <p className="mt-3 text-sm font-semibold" style={{ color: getScoreTone(metric.score) }}>
	                        {metric.label === "Security" && attackSurfaceSummary?.security.riskLabel
	                          ? `Security Risk: ${attackSurfaceSummary.security.riskLabel} | Score ${metric.score ?? "--"}/100`
	                          : `Score ${formatScorePercent(metric.score)}`}
	                      </p>
                      <div className="mt-4 h-1.5 overflow-hidden rounded-full bg-slate-200">
                        <div
                          className="h-full rounded-full"
                          style={{
                            width: `${Math.max(0, Math.min(100, metric.score ?? 0))}%`,
                            backgroundColor: getScoreTone(metric.score),
                          }}
                        />
                      </div>
                      <p className="mt-3 text-xs font-medium text-slate-500">{metric.count} total checks</p>
                    </div>
                  ))}
                </div>
              </div>

              {attackSurfaceSummary ? (
                <div className="mt-5 rounded-[1.8rem] border border-white/80 bg-white/80 p-5 shadow-[0_12px_42px_rgba(15,23,42,0.05)]">
                  <div className="flex flex-col gap-2 sm:flex-row sm:items-start sm:justify-between">
                    <div>
                      <p className="text-[11px] font-bold uppercase tracking-[0.18em] text-[var(--primary)]">
                        Attack Surface Summary
                      </p>
                      <p className="mt-2 text-sm leading-7 text-slate-600">
                        {attackSurfaceSummary.recommendedFirstLabel}:{" "}
                        <span className="font-semibold text-slate-900">
                          {attackSurfaceSummary.recommendedFirstFix}
                        </span>
                      </p>
                      {attackSurfaceSummary.coverageConfidence ? (
                        <p className="mt-1 text-sm leading-7 text-slate-600">
                          Coverage Confidence:{" "}
                          <span className="font-semibold text-slate-900">
                            {nestedString(attackSurfaceSummary.coverageConfidence, "level") || "Unknown"}
                          </span>
                          . {nestedString(attackSurfaceSummary.coverageConfidence, "explanation")}
                        </p>
                      ) : null}
                    </div>
                    <span className="inline-flex w-fit rounded-full border border-slate-200 bg-slate-50 px-3 py-1 text-[10px] font-bold uppercase text-slate-600">
                      {attackSurfaceSummary.scanMode} mode
                    </span>
                  </div>
                  <div className="mt-4 grid gap-2 sm:grid-cols-2 lg:grid-cols-5">
                    {attackSurfaceSummary.metrics.slice(0, 10).map((metric) => (
                      <div
                        key={`report-surface-${metric.label}`}
                        className="rounded-[1rem] border border-slate-100 bg-slate-50 px-3 py-2"
                      >
                        <p className="text-lg font-bold text-slate-900">{metric.value}</p>
                        <p className="text-[10px] font-bold uppercase tracking-[0.12em] text-slate-500">
                          {metric.label}
                        </p>
                      </div>
                    ))}
                  </div>
                </div>
              ) : null}

              {attackSurfaceSummary?.scanModeLimitations ? (
                <section className="mt-5 rounded-[1.8rem] border border-white/80 bg-white/80 p-5 shadow-[0_12px_42px_rgba(15,23,42,0.05)]">
                  <p className="text-[11px] font-bold uppercase tracking-[0.18em] text-[var(--primary)]">
                    {nestedString(attackSurfaceSummary.scanModeLimitations, "title")}
                  </p>
                  <p className="mt-2 text-sm leading-7 text-slate-600">
                    {nestedString(attackSurfaceSummary.scanModeLimitations, "summary")}
                  </p>
                  {Array.isArray(attackSurfaceSummary.scanModeLimitations.bullets) ? (
                    <ul className="mt-3 grid gap-2 text-sm leading-6 text-slate-600 md:grid-cols-2">
                      {attackSurfaceSummary.scanModeLimitations.bullets.map((bullet) => (
                        <li key={`mode-limit-${bullet}`} className="rounded-[1rem] bg-slate-50 px-3 py-2">
                          {String(bullet)}
                        </li>
                      ))}
                    </ul>
                  ) : null}
                </section>
              ) : null}

              {attackSurfaceSummary?.primaryAttackPath ? (
                <section className="mt-5 rounded-[1.8rem] border border-white/80 bg-white/80 p-5 shadow-[0_12px_42px_rgba(15,23,42,0.05)]">
                  <p className="text-[11px] font-bold uppercase tracking-[0.18em] text-[var(--primary)]">
                    Attack Path Analysis
                  </p>
                  <h3 className="mt-2 text-xl font-semibold text-slate-900">
                    Primary Attack Path: {nestedString(attackSurfaceSummary.primaryAttackPath, "title")}
                  </h3>
                  <p className="mt-2 text-sm leading-7 text-slate-600">
                    {nestedString(attackSurfaceSummary.primaryAttackPath, "summary")}
                  </p>
                  <div className="mt-4 grid gap-3 lg:grid-cols-[1.2fr_0.8fr]">
                    <div className="rounded-[1.3rem] border border-slate-100 bg-slate-50 p-4">
                      <p className="text-[11px] font-bold uppercase tracking-[0.16em] text-slate-500">
                        Confirmed Steps
                      </p>
                      <div className="mt-3 space-y-3">
                        {attackSurfaceSummary.confirmedAttackSteps.map((step, index) => (
                          <div key={`confirmed-step-${nestedString(step, "findingId") || index}`} className="rounded-[1rem] bg-white px-3 py-3">
                            <p className="text-sm font-semibold text-slate-900">
                              Step {index + 1} — {nestedString(step, "title")}
                              {step.supportingEvidence === true ? (
                                <span className="ml-2 rounded-full bg-blue-50 px-2 py-0.5 text-[10px] font-bold uppercase text-blue-700">
                                  supporting evidence
                                </span>
                              ) : null}
                            </p>
                            <p className="mt-1 text-xs leading-6 text-slate-600">
                              Action: {nestedString(step, "attackerAction")}
                            </p>
                            <p className="text-xs leading-6 text-slate-600">
                              Evidence: {nestedString(step, "evidence") || nestedString(step, "technicalEvidence")}
                            </p>
                            <p className="text-xs leading-6 text-slate-600">
                              Gained capability: {nestedString(step, "gainedCapability")}
                            </p>
                          </div>
                        ))}
                      </div>
                    </div>
                    <div className="rounded-[1.3rem] border border-amber-100 bg-amber-50/70 p-4">
                      <p className="text-[11px] font-bold uppercase tracking-[0.16em] text-amber-700">
                        Likely Extensions
                      </p>
                      <div className="mt-3 space-y-3">
                        {attackSurfaceSummary.likelyAttackExtensions.length > 0 ? (
                          attackSurfaceSummary.likelyAttackExtensions.map((step, index) => (
                            <div key={`likely-step-${nestedString(step, "findingId") || index}`} className="rounded-[1rem] bg-white/80 px-3 py-3">
                              <p className="text-sm font-semibold text-slate-900">{nestedString(step, "title")}</p>
                              <p className="mt-1 text-xs leading-6 text-slate-600">
                                Why likely: {nestedString(step, "evidence") || nestedString(step, "technicalEvidence")}
                              </p>
                            </div>
                          ))
                        ) : (
                          <p className="text-sm leading-7 text-slate-600">
                            No unconfirmed chain extensions were included in the primary path.
                          </p>
                        )}
                      </div>
                    </div>
                  </div>
                  <div className="mt-4 rounded-[1.2rem] border border-blue-100 bg-blue-50 px-4 py-3 text-sm leading-7 text-slate-700">
                    <p>
                      <span className="font-semibold text-slate-900">Final impact:</span>{" "}
                      {nestedString(attackSurfaceSummary.primaryAttackPath, "finalImpact")}
                    </p>
                    <p>
                      <span className="font-semibold text-slate-900">Fix first:</span>{" "}
                      {nestedString(attackSurfaceSummary.primaryAttackPath, "fixFirstTitle") ||
                        attackSurfaceSummary.recommendedFirstFix}
                    </p>
                  </div>
                </section>
              ) : null}

              {attackSurfaceSummary?.accessMatrix?.length ? (
                <section className="mt-5 rounded-[1.8rem] border border-white/80 bg-white/80 p-5 shadow-[0_12px_42px_rgba(15,23,42,0.05)]">
                  <p className="text-[11px] font-bold uppercase tracking-[0.18em] text-[var(--primary)]">
                    {accessMatrixIsPartial(attackSurfaceSummary.accessMatrix)
                      ? "Partial Access Matrix"
                      : "Role-Based Access Matrix"}
                  </p>
                  {accessMatrixIsPartial(attackSurfaceSummary.accessMatrix) ? (
                    <p className="mt-2 text-sm leading-7 text-slate-600">
                      Only anonymous and scanner-auth-context were available for at least one sampled endpoint. Provide userA, userB, and admin contexts for full role-based authorization proof.
                    </p>
                  ) : null}
                  <div className="mt-4 space-y-3">
                    {attackSurfaceSummary.accessMatrix.slice(0, 8).map((row, index) => (
                      <div key={`access-row-${nestedString(row, "endpoint") || index}`} className="rounded-[1.2rem] border border-slate-100 bg-slate-50 p-4">
                        <div className="flex flex-col gap-2 lg:flex-row lg:items-start lg:justify-between">
                          <div>
                            <p className="break-all text-sm font-semibold text-slate-900">
                              {nestedString(row, "endpoint")}
                            </p>
                            <p className="mt-1 text-xs uppercase tracking-[0.12em] text-slate-500">
                              Sensitivity {nestedString(row, "sensitivity") || "unknown"} · Issue {nestedString(row, "issue") || nestedString(row, "issueType") || "none"}
                            </p>
                          </div>
                        </div>
                        <div className="mt-3 grid gap-2 text-xs sm:grid-cols-2 lg:grid-cols-5">
                          {[
                            ["Anonymous", row.anonymous],
                            ["Scanner Auth", row.scannerAuthContext],
                            ["UserA", row.userA],
                            ["UserB", row.userB],
                            ["Admin", row.admin],
                          ].map(([label, cell]) => (
                            <div key={`${nestedString(row, "endpoint")}-${label}`} className="rounded-[0.9rem] bg-white px-3 py-2">
                              <p className="font-bold uppercase text-slate-500">{String(label)}</p>
                              <p className="mt-1 font-semibold text-slate-800">{accessMatrixCellLabel(cell)}</p>
                            </div>
                          ))}
                        </div>
                        <p className="mt-3 text-xs leading-6 text-slate-600">
                          {nestedString(row, "explanation")}
                        </p>
                      </div>
                    ))}
                  </div>
                </section>
              ) : null}

              <div className="mt-8 space-y-8">
                {categoryKeys.map((category) => (
                  <section key={`report-${category}`}>
                    <div className="flex items-center justify-between gap-3 border-b border-slate-200/80 pb-3">
                      <div>
                        <h3 className="text-2xl font-semibold tracking-[-0.02em] text-slate-900">
                          {category === "security" ? "Security Report" : `${titleCaseCategory(category)} Appendix`}
                        </h3>
                        <p className="mt-1 text-sm text-slate-500">
                          {reportFindingsByCategory[category].length} checks in this category
                        </p>
                      </div>
                    </div>

                    <div className="mt-4 space-y-4">
                      {reportFindingsByCategory[category].map((finding) => (
                        <article
                          key={`report-card-${finding.id}`}
                          className={cn(
                            "relative overflow-hidden rounded-[1.7rem] border p-5 shadow-[0_16px_44px_rgba(15,23,42,0.05)]",
                            findingSurfaceClasses(finding),
                          )}
                        >
                          {(deriveFindingStatus(finding) === "warning" ||
                            deriveFindingStatus(finding) === "fail") && (
                            <div
                              className="absolute inset-y-5 left-0 w-1 rounded-r-full"
                              style={{ backgroundColor: findingAccentTone(finding) }}
                            />
                          )}
                          <div className="flex flex-wrap items-start justify-between gap-3">
                            <div>
                              <h4 className="text-lg font-semibold text-slate-900">{finding.title}</h4>
                              <p className="mt-2 max-w-[760px] text-sm leading-7 text-slate-500">
                                {finding.shortDescription}
                              </p>
                            </div>
                            <div className="flex flex-wrap gap-2">
                              <span
                                className={cn(
                                  "rounded-full px-3 py-1 text-[10px] font-bold uppercase tracking-[0.14em]",
                                  getStatusStyles(deriveFindingStatus(finding)),
                                )}
                              >
                                {formatFindingHeader(finding).compact}
                              </span>
                              <span
                                className={cn(
                                  "rounded-full px-3 py-1 text-[10px] font-bold uppercase tracking-[0.14em]",
                                  getConfidenceStyles(finding.confidence ?? "info"),
                                )}
                              >
                                Confidence: {formatFindingHeader(finding).confidenceLabel}
                              </span>
                              {typeof finding.riskScore === "number" ? (
                                <span className="rounded-full border border-slate-200 bg-white px-3 py-1 text-[10px] font-bold uppercase tracking-[0.14em] text-slate-700">
                                  Risk {finding.riskScore}/100
                                </span>
                              ) : null}
                              {finding.priorityLabel ? (
                                <span className="rounded-full border border-blue-100 bg-blue-50 px-3 py-1 text-[10px] font-bold uppercase tracking-[0.14em] text-blue-700">
                                  {finding.priorityLabel}
                                </span>
                              ) : null}
                            </div>
                          </div>

                          {finding.locked ? (
                            <div className="mt-4 rounded-[1.3rem] border border-dashed border-slate-300 bg-white/80 p-4 text-sm text-slate-500">
                              Sign in with Google to unlock the full remediation details for this check.
                            </div>
                          ) : (
                            <div className="mt-4 grid gap-3 lg:grid-cols-2">
                              <div className={cn("rounded-[1.3rem] p-4", detailPanelClasses(finding))}>
                                <p
                                  className="text-[11px] font-bold uppercase tracking-[0.18em]"
                                  style={{ color: findingAccentTone(finding) }}
                                >
                                  Why It Matters
                                </p>
                                <p className="mt-2 text-sm leading-7 text-slate-600">
                                  {finding.whyItMatters}
                                </p>
                              </div>
                              <div className="rounded-[1.3rem] border border-white/70 bg-[linear-gradient(180deg,rgba(255,255,255,0.82),rgba(239,246,255,0.9))] p-4 shadow-[0_10px_28px_rgba(59,130,246,0.07)]">
                                <p className="text-[11px] font-bold uppercase tracking-[0.18em] text-[var(--primary)]">
                                  Recommendation
                                </p>
                                <p className="mt-2 text-sm leading-7 text-slate-600">
                                  {finding.recommendation}
                                </p>
                              </div>
                            </div>
                          )}

                          {!finding.locked && evidenceLinesForReport(finding, 4).length > 0 ? (
                            <div className="mt-4 rounded-[1.3rem] border border-white/70 bg-white/75 p-4 shadow-[0_10px_28px_rgba(148,163,184,0.08)]">
                              <p className="text-[11px] font-bold uppercase tracking-[0.18em] text-[var(--primary)]">
                                Evidence
                              </p>
                              <div className="mt-2 space-y-1">
                                {evidenceLinesForReport(finding, 4).map((line, index) => (
                                  <p
                                    key={`report-evidence-${finding.id}-${index}`}
                                    className="break-words text-xs leading-6 text-slate-600"
                                  >
                                    {line}
                                  </p>
                                ))}
                              </div>
                            </div>
                          ) : null}
                        </article>
                      ))}
                    </div>
                  </section>
                ))}
              </div>
            </div>
          </div>
        </div>
      ) : null}
    </div>
  );
}
