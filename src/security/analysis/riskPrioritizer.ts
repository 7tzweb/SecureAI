import {
  type FindingConfidence,
  type FindingStatus,
  type ScanFinding,
  type Severity,
} from "@/lib/types";
import { clamp, deriveFindingStatus } from "@/lib/utils";
import type { AttackPath } from "@/security/analysis/attackPathBuilder";

export type RiskScoreInput = {
  severityScore: number;
  confidenceScore: number;
  exploitabilityScore: number;
  impactScore: number;
  exposureScore: number;
  attackPathWeight: number;
  publicEndpoint: boolean;
  authRequired: boolean;
  dataExposure: boolean;
  headerOnly?: boolean;
  severity: Severity;
  confidence: FindingConfidence;
};

const severityScores: Record<Severity, number> = {
  info: 0,
  low: 2,
  medium: 5,
  high: 8,
  critical: 10,
};

const confidenceScores: Record<FindingConfidence, number> = {
  info: 0.2,
  low: 0.3,
  medium: 0.5,
  likely: 0.7,
  confirmed: 1,
};

export function severityScore(severity: Severity) {
  return severityScores[severity];
}

export function confidenceScore(confidence: FindingConfidence) {
  return confidenceScores[confidence];
}

export function priorityLabel(riskScore: number): NonNullable<ScanFinding["priorityLabel"]> {
  if (riskScore >= 90) {
    return "Fix immediately";
  }
  if (riskScore >= 70) {
    return "High priority";
  }
  if (riskScore >= 40) {
    return "Medium priority";
  }
  return "Low priority";
}

export function calculateRiskScore(input: RiskScoreInput) {
  const base =
    input.severityScore * 0.25 +
    input.confidenceScore * 10 * 0.15 +
    input.exploitabilityScore * 0.2 +
    input.impactScore * 0.2 +
    input.exposureScore * 0.1 +
    input.attackPathWeight;

  let risk = base * 10;

  if (input.publicEndpoint && !input.authRequired && input.confidence === "confirmed") {
    risk += 5;
  }
  if (input.dataExposure && input.confidence === "confirmed") {
    risk += 5;
  }
  if (input.attackPathWeight > 0) {
    risk += 5;
  }
  if (input.confidence === "info") {
    risk = Math.min(risk, 35);
  }
  if (input.confidence === "likely" && input.attackPathWeight <= 0) {
    risk = Math.min(risk, 75);
  }
  if (input.headerOnly) {
    risk = Math.min(risk, 45);
  }
  if (input.confidence === "confirmed" && input.severity === "critical") {
    risk = Math.max(risk, 85);
  }

  return clamp(Math.round(risk), 0, 100);
}

function statusDefaultExploitability(status: FindingStatus, severity: Severity) {
  if (status === "pass" || status === "info") {
    return 0;
  }
  if (severity === "critical") {
    return 9;
  }
  if (severity === "high") {
    return 7;
  }
  if (severity === "medium") {
    return 5;
  }
  return 2;
}

export function calculateFindingRisk(finding: ScanFinding) {
  const status = deriveFindingStatus(finding);
  const confidence = finding.confidence ?? (status === "fail" || status === "warning" ? "likely" : "info");
  const evidence = finding.evidence ?? {};
  const exploitability =
    typeof finding.exploitabilityScore === "number"
      ? finding.exploitabilityScore
      : typeof evidence.exploitabilityScore === "number"
        ? evidence.exploitabilityScore
        : statusDefaultExploitability(status, finding.severity);
  const impact =
    typeof finding.impactScore === "number"
      ? finding.impactScore
      : typeof evidence.impactScore === "number"
        ? evidence.impactScore
        : finding.severity === "critical"
          ? 9
          : finding.severity === "high"
            ? 7
            : finding.severity === "medium"
              ? 5
              : finding.severity === "low"
                ? 2
                : 0;
  const exposure =
    typeof finding.exposureScore === "number"
      ? finding.exposureScore
      : typeof evidence.exposureScore === "number"
        ? evidence.exposureScore
        : finding.publicEndpoint || evidence.publicEndpoint === true
          ? 9
          : finding.authRequired || evidence.authRequired === true
            ? 5
            : 3;
  const headerOnly = finding.findingClass === "headers" || /header|hsts|csp|frame|referrer|permissions/i.test(finding.checkKey ?? finding.title);
  const attackPathWeight = finding.attackPathParticipant || evidence.attackPathParticipant === true ? 4 : 0;
  const score = calculateRiskScore({
    severityScore: severityScore(finding.severity),
    confidenceScore: confidenceScore(confidence),
    exploitabilityScore: clamp(exploitability, 0, 10),
    impactScore: clamp(impact, 0, 10),
    exposureScore: clamp(exposure, 0, 10),
    attackPathWeight,
    publicEndpoint: Boolean(finding.publicEndpoint ?? evidence.publicEndpoint),
    authRequired: Boolean(finding.authRequired ?? evidence.authRequired),
    dataExposure: Boolean(finding.dataExposure ?? evidence.dataExposure),
    headerOnly,
    severity: finding.severity,
    confidence,
  });

  return {
    exploitabilityScore: clamp(exploitability, 0, 10),
    impactScore: clamp(impact, 0, 10),
    exposureScore: clamp(exposure, 0, 10),
    confidenceScore: confidenceScore(confidence),
    riskScore: score,
    priorityLabel: priorityLabel(score),
  };
}

function normalized(value: string | undefined | null) {
  return String(value ?? "").toLowerCase();
}

function evidenceHasConcreteTarget(finding: ScanFinding) {
  const evidence = finding.evidence ?? {};
  const structuredEvidence = finding.structuredEvidence ?? [];
  const checkedUrl = evidence.checkedUrl;
  const evidenceLocations = evidence.locations;

  return Boolean(
    finding.affectedUrl ||
      finding.affectedParameter ||
      (typeof checkedUrl === "string" && checkedUrl.trim().length > 0) ||
      structuredEvidence.some((entry) => Boolean(entry.url || entry.parameter)) ||
      (Array.isArray(evidenceLocations) &&
        evidenceLocations.some((location) => location && typeof location === "object" && "url" in location)),
  );
}

export function isConcreteFixableFinding(finding: ScanFinding): boolean {
  const status = deriveFindingStatus(finding);
  const findingClass = normalized(finding.findingClass);
  const title = normalized(finding.title);
  const checkKey = normalized(finding.checkKey);
  const text = `${title} ${checkKey}`;
  const isClearlyMeta =
    finding.isMetaFinding === true ||
    findingClass.includes("attack-path") ||
    findingClass.includes("analysis") ||
    findingClass.includes("coverage") ||
    findingClass.includes("crawl") ||
    text.includes("attack path analysis") ||
    text.includes("authenticated session context") ||
    text.includes("session model") ||
    text.includes("role-based access matrix") ||
    text.includes("browser-rendered crawl coverage") ||
    text.includes("technology fingerprinting") ||
    text.includes("attack surface summary") ||
    text.includes("authentication surface review") ||
    text.includes("crawl coverage");

  return (
    status !== "pass" &&
    status !== "info" &&
    !isClearlyMeta &&
    finding.isExploitSupportingEvidence !== true &&
    evidenceHasConcreteTarget(finding)
  );
}

export function scoreFixCandidate(finding: ScanFinding, attackPaths: AttackPath[] = []) {
  let score = finding.riskScore ?? 0;

  if (finding.confidence === "confirmed") score += 20;
  if (finding.confidence === "likely") score += 5;

  if (finding.severity === "critical") score += 15;
  if (finding.severity === "high") score += 10;
  if (finding.severity === "medium") score += 4;

  if (finding.publicEndpoint) score += 10;
  if (finding.authRequired === false) score += 8;
  if (finding.dataExposure) score += 8;

  const isInAttackPath = attackPaths.some((path) =>
    path.steps?.some((step) => step.findingId === finding.id),
  );
  if (isInAttackPath) score += 12;

  const gains = finding.capabilitiesGained ?? [];
  if (gains.includes("authenticated_context") || gains.includes("protected_api_access")) {
    score += 10;
  }

  const findingClass = normalized(finding.findingClass);
  const title = normalized(finding.title);
  if (
    gains.includes("database_query_manipulation") ||
    findingClass.includes("injection") ||
    title.includes("sql injection")
  ) {
    score += 8;
  }

  if (
    title.includes("content-security-policy") ||
    title.includes("hsts") ||
    title.includes("permissions-policy") ||
    title.includes("referrer-policy") ||
    findingClass.includes("headers")
  ) {
    score -= 10;
  }

  return score;
}

export function chooseRecommendedFirstFix(findings: ScanFinding[], attackPaths: AttackPath[] = []) {
  return [...findings]
    .filter(isConcreteFixableFinding)
    .sort((left, right) => scoreFixCandidate(right, attackPaths) - scoreFixCandidate(left, attackPaths))[0] ?? null;
}

export function getTopFixes(findings: ScanFinding[], attackPaths: AttackPath[] = [], limit = 5) {
  return [...findings]
    .filter(isConcreteFixableFinding)
    .sort((left, right) => scoreFixCandidate(right, attackPaths) - scoreFixCandidate(left, attackPaths))
    .slice(0, limit);
}

export function isConfirmedExploitableVulnerability(finding: ScanFinding): boolean {
  return (
    isFixableOrInferred(finding) &&
    finding.confidence === "confirmed" &&
    deriveFindingStatus(finding) === "fail" &&
    finding.isMetaFinding !== true &&
    finding.isExploitSupportingEvidence !== true &&
    isConcreteFixableFinding(finding)
  );
}

export function isConfirmedSupportingEvidence(finding: ScanFinding): boolean {
  const title = normalized(finding.title);
  const findingClass = normalized(finding.findingClass);
  const supporting =
    finding.isExploitSupportingEvidence === true ||
    finding.isMetaFinding === true ||
    findingClass.includes("attack-path") ||
    title.includes("attack path analysis") ||
    title.includes("authenticated session context");

  return supporting && finding.confidence === "confirmed";
}

export function isLikelyHighImpactIssue(finding: ScanFinding): boolean {
  return (
    isFixableOrInferred(finding) &&
    finding.confidence === "likely" &&
    (finding.severity === "high" || finding.severity === "critical") &&
    isConcreteFixableFinding(finding)
  );
}

function isFixableOrInferred(finding: ScanFinding) {
  return (
    finding.isFixableVulnerability === true ||
    (finding.isFixableVulnerability !== false && isConcreteFixableFinding(finding))
  );
}

export function calculateSecurityScore(findings: ScanFinding[], attackPaths: AttackPath[] = []) {
  let score = 100;

  const confirmedConcreteCritical = findings.filter(
    (finding) =>
      isFixableOrInferred(finding) &&
      finding.confidence === "confirmed" &&
      finding.severity === "critical" &&
      isConcreteFixableFinding(finding),
  );
  const confirmedConcreteHigh = findings.filter(
    (finding) =>
      isFixableOrInferred(finding) &&
      finding.confidence === "confirmed" &&
      finding.severity === "high" &&
      isConcreteFixableFinding(finding),
  );
  const likelyHighOrCritical = findings.filter(
    (finding) =>
      isFixableOrInferred(finding) &&
      finding.confidence === "likely" &&
      (finding.severity === "high" || finding.severity === "critical") &&
      isConcreteFixableFinding(finding),
  );
  const likelyMedium = findings.filter(
    (finding) =>
      isFixableOrInferred(finding) &&
      finding.confidence === "likely" &&
      finding.severity === "medium" &&
      isConcreteFixableFinding(finding),
  );
  const lowFixable = findings.filter(
    (finding) =>
      isFixableOrInferred(finding) &&
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
      normalized(finding.title).includes("authentication bypass") &&
      finding.confidence === "confirmed" &&
      isFixableOrInferred(finding),
  );
  const hasConfirmedSqli = findings.some(
    (finding) =>
      (normalized(finding.title).includes("sql injection") ||
        normalized(finding.findingClass).includes("injection")) &&
      finding.confidence === "confirmed" &&
      isFixableOrInferred(finding),
  );
  const hasPrimaryAttackPath = attackPaths.length > 0;

  if (confirmedConcreteCritical.length > 0) score = Math.min(score, 40);
  if (hasConfirmedSqli) score = Math.min(score, 35);
  if (hasConfirmedAuthBypass) score = Math.min(score, 30);
  if (hasConfirmedSqli && hasConfirmedAuthBypass) score = Math.min(score, 25);
  if (hasPrimaryAttackPath && (hasConfirmedSqli || hasConfirmedAuthBypass)) {
    score = Math.min(score, 25);
  }

  const catastrophic =
    confirmedConcreteCritical.length >= 5 ||
    findings.some(
      (finding) =>
        normalized(finding.title).includes("admin compromise") &&
        finding.confidence === "confirmed",
    );

  if (!catastrophic && hasConfirmedSqli && hasConfirmedAuthBypass) {
    score = Math.max(score, 20);
  }

  score = catastrophic ? Math.max(score, 0) : Math.max(score, 10);
  score = clamp(Math.round(score), 0, 100);

  const label =
    score >= 80 ? "Low Risk" :
    score >= 60 ? "Medium Risk" :
    score >= 40 ? "High Risk" :
    "Critical Risk";

  return {
    score,
    label,
    explanation:
      "Security score is risk-based and capped by confirmed critical exploitable findings and attack path evidence.",
  };
}

export function topFixes(findings: ScanFinding[], limit = 5) {
  return getTopFixes(findings, [], limit);
}
