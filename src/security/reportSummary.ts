import type { ScanFinding } from "@/lib/types";
import { deriveFindingStatus } from "@/lib/utils";
import type { AttackPath } from "@/security/analysis/attackPathBuilder";
import {
  calculateSecurityScore,
  chooseRecommendedFirstFix,
  getTopFixes,
  isConfirmedExploitableVulnerability,
  isConfirmedSupportingEvidence,
  isLikelyHighImpactIssue,
} from "@/security/analysis/riskPrioritizer";

export type SecurityRiskLabel = "Low Risk" | "Medium Risk" | "High Risk" | "Critical Risk";

export type ReportSummary = {
  target: string;
  scanMode: "Fast" | "Deep" | "Authenticated" | string;
  generatedAt: string;
  overallScore: number;
  security: {
    score: number;
    riskLabel: SecurityRiskLabel;
    explanation: string;
    passedChecks: number;
    failedChecks: number;
  };
  counts: {
    confirmedExploitableVulnerabilities: number;
    confirmedSupportingEvidence: number;
    likelyHighImpactIssues: number;
    informationalFindings: number;
    criticalIssues: number;
    highIssues: number;
    mediumIssues: number;
    lowIssues: number;
    passedChecks: number;
    failedChecks: number;
  };
  attackSurface: {
    publicApis: number;
    sensitiveEndpoints: number;
    missingHeaders: number;
    crawledPages: number;
    discoveredEndpoints: number;
    testedParameters: number;
    activeProbesExecuted?: number;
    scanDurationMs?: number;
    scanDuration?: string;
  };
  recommendedFirstFix: ScanFinding | null;
  topFixes: ScanFinding[];
  primaryAttackPath?: AttackPath | null;
  scanModeLimitations: {
    title: string;
    summary: string;
    bullets: string[];
  };
};

export function scanModeLimitationsFor(scanMode: string): ReportSummary["scanModeLimitations"] {
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

export function buildReportSummary(params: {
  target: string;
  scanMode: string;
  generatedAt: string;
  findings: ScanFinding[];
  attackPaths: AttackPath[];
  attackSurface: ReportSummary["attackSurface"];
  overallScore?: number;
}): ReportSummary {
  const recommendedFirstFix = chooseRecommendedFirstFix(params.findings, params.attackPaths);
  const topFixes = getTopFixes(params.findings, params.attackPaths, 5);
  const securityScore = calculateSecurityScore(params.findings, params.attackPaths);
  const passedChecks = params.findings.filter((finding) => deriveFindingStatus(finding) === "pass").length;
  const failedChecks = params.findings.filter((finding) => deriveFindingStatus(finding) === "fail").length;

  return {
    target: params.target,
    scanMode: params.scanMode,
    generatedAt: params.generatedAt,
    overallScore: params.overallScore ?? securityScore.score,
    security: {
      score: securityScore.score,
      riskLabel: securityScore.label as SecurityRiskLabel,
      explanation: securityScore.explanation,
      passedChecks,
      failedChecks,
    },
    counts: {
      confirmedExploitableVulnerabilities: params.findings.filter(isConfirmedExploitableVulnerability).length,
      confirmedSupportingEvidence: params.findings.filter(isConfirmedSupportingEvidence).length,
      likelyHighImpactIssues: params.findings.filter(isLikelyHighImpactIssue).length,
      informationalFindings: params.findings.filter(
        (finding) =>
          finding.severity === "info" ||
          deriveFindingStatus(finding) === "info" ||
          (finding.confidence ?? "info") === "info",
      ).length,
      criticalIssues: params.findings.filter(
        (finding) => finding.severity === "critical" && deriveFindingStatus(finding) !== "pass",
      ).length,
      highIssues: params.findings.filter(
        (finding) => finding.severity === "high" && deriveFindingStatus(finding) !== "pass",
      ).length,
      mediumIssues: params.findings.filter(
        (finding) => finding.severity === "medium" && deriveFindingStatus(finding) !== "pass",
      ).length,
      lowIssues: params.findings.filter(
        (finding) => finding.severity === "low" && deriveFindingStatus(finding) !== "pass",
      ).length,
      passedChecks,
      failedChecks,
    },
    attackSurface: params.attackSurface,
    recommendedFirstFix,
    topFixes,
    primaryAttackPath: params.attackPaths[0] ?? null,
    scanModeLimitations: scanModeLimitationsFor(params.scanMode),
  };
}
