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

export type SecurityScoreBreakdown = {
  baseScore: number;
  confirmedExploitPenalty: number;
  likelyIssuePenalty: number;
  attackSurfacePenalty: number;
  coveragePenalty: number;
  platformRiskPenalty: number;
  headerPenalty: number;
  capsApplied: string[];
  finalScore: number;
  riskLabel: "Low Risk" | "Medium Risk" | "High Risk" | "Critical Risk";
  explanation: string;
};

export type CoverageConfidence = {
  level: "High" | "Medium" | "Low";
  explanation: string;
  signals: string[];
};

export type GroupedFix = {
  id: string;
  title: string;
  riskScore: number;
  priorityLabel: NonNullable<ScanFinding["priorityLabel"]>;
  findings: string[];
  affectedUrls: string[];
  reason: string;
  recommendation: string;
  confidence: FindingConfidence;
  isFixableVulnerability: boolean;
};

export type FixRecommendation = ScanFinding | GroupedFix;
export type RecommendationLabel = "Recommended first fix" | "Recommended first review";

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

function effectiveSeverity(finding: ScanFinding) {
  return finding.computedRiskSeverity ?? finding.severity;
}

function effectiveEvidenceStrength(finding: ScanFinding) {
  const evidenceStrength = finding.evidenceStrength ?? finding.evidence?.evidenceStrength;
  return evidenceStrength === "weak" ||
    evidenceStrength === "moderate" ||
    evidenceStrength === "strong" ||
    evidenceStrength === "exploit-proof"
    ? evidenceStrength
    : undefined;
}

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
  const severity = effectiveSeverity(finding);
  const exploitability =
    typeof finding.exploitabilityScore === "number"
      ? finding.exploitabilityScore
      : typeof evidence.exploitabilityScore === "number"
        ? evidence.exploitabilityScore
        : statusDefaultExploitability(status, severity);
  const impact =
    typeof finding.impactScore === "number"
      ? finding.impactScore
      : typeof evidence.impactScore === "number"
        ? evidence.impactScore
        : severity === "critical"
          ? 9
          : severity === "high"
            ? 7
            : severity === "medium"
              ? 5
              : severity === "low"
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
  const evidenceStrength = effectiveEvidenceStrength(finding);
  let score = calculateRiskScore({
    severityScore: severityScore(severity),
    confidenceScore: confidenceScore(confidence),
    exploitabilityScore: clamp(exploitability, 0, 10),
    impactScore: clamp(impact, 0, 10),
    exposureScore: clamp(exposure, 0, 10),
    attackPathWeight,
    publicEndpoint: Boolean(finding.publicEndpoint ?? evidence.publicEndpoint),
    authRequired: Boolean(finding.authRequired ?? evidence.authRequired),
    dataExposure: Boolean(finding.dataExposure ?? evidence.dataExposure),
    headerOnly,
    severity,
    confidence,
  });

  if (evidenceStrength === "weak") {
    score = Math.min(score * 0.5, 45);
  } else if (evidenceStrength === "moderate") {
    score = Math.min(score * 0.75, confidence === "confirmed" ? 70 : 62);
  }

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

function evidenceText(finding: ScanFinding) {
  try {
    return JSON.stringify(finding.evidence ?? {}).toLowerCase();
  } catch {
    return "";
  }
}

function fullFindingText(finding: ScanFinding) {
  return `${finding.checkKey ?? ""} ${finding.title} ${finding.shortDescription} ${finding.proofSummary ?? ""} ${evidenceText(finding)}`.toLowerCase();
}

function hasTag(finding: ScanFinding, tag: string) {
  return finding.scoringTags?.includes(tag) ?? false;
}

function evidenceArrayCount(finding: ScanFinding, key: string) {
  const value = finding.evidence?.[key];
  return Array.isArray(value) ? value.length : 0;
}

function findingUrlList(finding: ScanFinding) {
  const urls = new Set<string>();
  const checkedUrl = finding.evidence?.checkedUrl;
  if (finding.affectedUrl) {
    urls.add(finding.affectedUrl);
  }
  if (typeof checkedUrl === "string") {
    checkedUrl
      .split(",")
      .map((url) => url.trim())
      .filter(Boolean)
      .slice(0, 6)
      .forEach((url) => urls.add(url));
  }
  finding.structuredEvidence?.forEach((entry) => {
    if (entry.url) {
      urls.add(entry.url);
    }
  });
  return [...urls].slice(0, 8);
}

function statusIsIssue(finding: ScanFinding) {
  const status = deriveFindingStatus(finding);
  return status === "fail" || status === "warning";
}

function isLikelyIssue(finding: ScanFinding) {
  return (finding.confidence ?? "info") === "likely" && statusIsIssue(finding);
}

function isConfirmedFixableRecommendation(item: FixRecommendation) {
  return item.confidence === "confirmed" && item.isFixableVulnerability === true;
}

export function getRecommendationLabel(item: FixRecommendation | null | undefined): RecommendationLabel {
  return item && isConfirmedFixableRecommendation(item)
    ? "Recommended first fix"
    : "Recommended first review";
}

function isHeaderFinding(finding: ScanFinding) {
  return finding.findingClass === "headers" || /header|hsts|content-security-policy|x-frame|clickjacking|content-type|referrer|permissions/i.test(
    `${finding.checkKey ?? ""} ${finding.title}`,
  );
}

function evidenceNumber(finding: ScanFinding, key: string) {
  const value = finding.evidence?.[key];
  return typeof value === "number" && Number.isFinite(value) ? value : 0;
}

function evidenceBoolean(finding: ScanFinding, key: string) {
  return finding.evidence?.[key] === true;
}

function evidenceStringArray(finding: ScanFinding, key: string) {
  const value = finding.evidence?.[key];
  return Array.isArray(value) ? value.filter((entry): entry is string => typeof entry === "string") : [];
}

function evidenceRecordArray(finding: ScanFinding, key: string) {
  const value = finding.evidence?.[key];
  return Array.isArray(value)
    ? value.filter((entry): entry is Record<string, unknown> => Boolean(entry && typeof entry === "object" && !Array.isArray(entry)))
    : [];
}

function hasOnlyUpgradeInsecureRequests(value: string) {
  return value
    .toLowerCase()
    .split(";")
    .map((part) => part.trim())
    .filter(Boolean)
    .every((directive) => directive === "upgrade-insecure-requests");
}

function buildSecurityContext(findings: ScanFinding[], attackSurface?: { crawledPages?: number; testedParameters?: number }) {
  const get = (pattern: RegExp) => findings.find((finding) => pattern.test(`${finding.checkKey ?? ""} ${finding.title}`.toLowerCase()));
  const allText = findings.map(fullFindingText).join(" ");
  const reflectedFinding = get(/reflected-input-exposure|reflected input exposure/);
  const reflectedInputCount =
    reflectedFinding
      ? Math.max(
          evidenceArrayCount(reflectedFinding, "reflectedParameters"),
          Number(String(reflectedFinding.shortDescription).match(/(\d+)/)?.[1] ?? 0),
        )
      : 0;
  const authSurfaceFinding = get(/authentication-surface-review|authentication surface review/);
  const passwordFinding = get(/password-field-security|password field security/);
  const uploadFinding = get(/file-upload-risk-indicators|file upload risk indicators/);
  const xssFinding = get(/xss-risk-indicators|xss evidence review/);
  const browserFinding = get(/browser-rendered-crawl-coverage|browser-rendered crawl coverage/);
  const sensitiveEndpointFinding = get(/sensitive-endpoint-discovery|sensitive endpoint discovery/);
  const apiExposureFinding = get(/api exposure|api surface|public api/);
  const cspFinding = get(/content-security-policy/);
  const hstsFinding = get(/hsts-header|hsts header/);
  const xfoFinding = get(/x-frame-options/);
  const clickjackingFinding = get(/clickjacking-protection|clickjacking protection/);
  const xctoFinding = get(/x-content-type-options/);
  const referrerFinding = get(/referrer-policy/);
  const securityTxtFinding = get(/security-txt|security\.txt/);
  const techFinding = get(/technology-fingerprinting|technology fingerprinting/);
  const poweredByFinding = get(/x-powered-by-disclosure|x-powered-by disclosure/);
  const fastHtmlSurfaceFinding = get(/fast-html-surface|first-page html surface/);
  const knownVulnerableTrainingApp = findings.some((finding) =>
    /known intentionally vulnerable application|owasp juice shop|intentionally vulnerable security training application/i.test(
      fullFindingText(finding),
    ),
  );

  const browserText = browserFinding ? fullFindingText(browserFinding) : "";
  const browserRenderingFailed =
    Boolean(browserFinding) &&
    (deriveFindingStatus(browserFinding!) === "warning" || /fetch-only|did not produce|rendered":false|rendering was attempted/.test(browserText));
  const browserAppShellCoverageGap =
    browserRenderingFailed &&
    (
      evidenceBoolean(browserFinding!, "appShellLikely") ||
      (
        Boolean(fastHtmlSurfaceFinding) &&
        evidenceNumber(fastHtmlSurfaceFinding!, "scripts") >= 3 &&
        evidenceNumber(fastHtmlSurfaceFinding!, "forms") === 0
      )
    );
  const browserLowCoverage =
    Boolean(browserFinding) &&
    !browserRenderingFailed &&
    ((attackSurface?.crawledPages ?? 0) > 0 && (attackSurface?.crawledPages ?? 0) <= 3);
  const authSurfaceDetected =
    Boolean(authSurfaceFinding) &&
    (statusIsIssue(authSurfaceFinding!) ||
      authSurfaceFinding!.evidence.authSurfaceDetected === true ||
      Number(authSurfaceFinding!.evidence.authRouteCount ?? 0) > 0 ||
      Number(authSurfaceFinding!.evidence.passwordFormCount ?? 0) > 0);
  const passwordFieldWeakness =
    Boolean(passwordFinding) &&
    (statusIsIssue(passwordFinding!) || Number(passwordFinding!.evidence.passwordFormCount ?? 0) > 0);
  const passwordFormDetected =
    passwordFieldWeakness || Boolean(passwordFinding && Number(passwordFinding.evidence.passwordFormCount ?? 0) > 0);
  const uploadFormDetected =
    Boolean(uploadFinding) &&
    (statusIsIssue(uploadFinding!) ||
      /upload form signals|upload-oriented surfaces were detected|multipart|wpforms/.test(fullFindingText(uploadFinding!)));
  const uploadGroupingSignal =
    Boolean(uploadFinding) &&
    statusIsIssue(uploadFinding!) &&
    (evidenceNumber(uploadFinding!, "uploadFormCount") > 0 ||
      evidenceNumber(uploadFinding!, "uploadRouteCount") > 0 ||
      evidenceRecordArray(uploadFinding!, "uploadForms").length > 0 ||
      evidenceRecordArray(uploadFinding!, "uploadRoutes").length > 0 ||
      /upload form signals|upload-oriented surfaces were detected|multipart|wpforms/.test(fullFindingText(uploadFinding!)));
  const xssIndicators =
    Boolean(xssFinding && statusIsIssue(xssFinding)) ||
    reflectedInputCount > 0 ||
    Boolean(reflectedFinding && statusIsIssue(reflectedFinding));
  const sensitiveFormSignal =
    findings.some((finding) => {
      const text = fullFindingText(finding);
      return (
        statusIsIssue(finding) &&
        (/(csrf-protection-sensitive-forms|sensitive form|form handling)/.test(text) ||
          evidenceNumber(finding, "sensitiveFormCount") > 0 ||
          evidenceRecordArray(finding, "sensitiveForms").length > 0) &&
        !/no sensitive forms were detected|sensitiveformcount":0|sensitiveFormCount":0/i.test(text)
      );
    });
  const passwordGroupingSignal =
    Boolean(passwordFinding) &&
    statusIsIssue(passwordFinding!) &&
    (evidenceNumber(passwordFinding!, "passwordFormCount") > 0 ||
      evidenceRecordArray(passwordFinding!, "passwordForms").length > 0 ||
      /password input|password forms were evaluated|sampled password forms expose/i.test(fullFindingText(passwordFinding!))) &&
    !/no password fields were detected|no password input was captured|passwordformcount":0|passwordFormCount":0/i.test(fullFindingText(passwordFinding!));
  const appOwnedLoginFormSignal =
    Boolean(authSurfaceFinding) &&
    statusIsIssue(authSurfaceFinding!) &&
    !evidenceBoolean(authSurfaceFinding!, "hostedProviderOnlyAuthSurface") &&
    (evidenceNumber(authSurfaceFinding!, "passwordFormCount") > 0 ||
      evidenceNumber(authSurfaceFinding!, "authRouteCount") > 0 ||
      evidenceStringArray(authSurfaceFinding!, "routeMapSignals").length > 0 ||
      /app-owned login|sampled authentication surfaces expose|auth surfaces looked/.test(fullFindingText(authSurfaceFinding!)));
  const sensitiveEndpointProtected =
    Boolean(sensitiveEndpointFinding) &&
    /protected rather than openly exposed|401|403|405|explicitly protected/.test(fullFindingText(sensitiveEndpointFinding!));
  const sensitiveEndpointReachable =
    Boolean(sensitiveEndpointFinding) &&
    statusIsIssue(sensitiveEndpointFinding!) &&
    /reachable|direct response|returned a useful response|200/.test(fullFindingText(sensitiveEndpointFinding!));
  const apiExposureLikely = Boolean(apiExposureFinding && isLikelyIssue(apiExposureFinding));

  const cspValue = String(cspFinding?.evidence.value ?? "");
  const weakCsp =
    Boolean(cspFinding) &&
    (statusIsIssue(cspFinding!) ||
      hasTag(cspFinding!, "weak-csp") ||
      /unsafe-inline|unsafe-eval|report-only|missing/.test(fullFindingText(cspFinding!)) ||
      hasOnlyUpgradeInsecureRequests(cspValue));
  const missingCsp = Boolean(cspFinding && /missing/.test(fullFindingText(cspFinding)));
  const missingFrameProtection =
    Boolean(clickjackingFinding && statusIsIssue(clickjackingFinding)) ||
    Boolean(xfoFinding && statusIsIssue(xfoFinding));
  const missingHsts = Boolean(hstsFinding && statusIsIssue(hstsFinding));
  const missingXcto = Boolean(xctoFinding && statusIsIssue(xctoFinding));
  const missingReferrer = Boolean(referrerFinding && statusIsIssue(referrerFinding));
  const securityTxtMissing = Boolean(securityTxtFinding && /not found|missing|not reachable/.test(fullFindingText(securityTxtFinding)));

  const wordpressDetected = /wordpress|wp-content|wp-includes|wpforms|wp-json/.test(allText);
  const highDynamicPlatform =
    /hostedprovideronlyauthsurface|hosted authentication-provider|search-provider-server|auth-provider-flow|dynamic-nonce-heavy-page|servicelogin|weblitesignin|server is set to \\"gws\\"|server is set to "gws"/.test(
      allText,
    );
  const wordpressExactVersionExposed = /wordpress\s+\d+(?:\.\d+){1,3}/.test(allText);
  const phpVersionExposed = /x-powered-by[^"]*php|php\/?\d+(?:\.\d+){1,3}|php\s+\d+(?:\.\d+){1,3}/.test(allText);
  const versionExposure = wordpressExactVersionExposed || phpVersionExposed || Boolean(techFinding && hasTag(techFinding, "version-exposure")) || Boolean(poweredByFinding && statusIsIssue(poweredByFinding));
  const likelyMediumSecurityFindings = findings.filter(
    (finding) => isLikelyIssue(finding) && effectiveSeverity(finding) === "medium",
  ).length;
  const likelySecurityWarnings = findings.filter((finding) => {
    if (!isLikelyIssue(finding)) {
      return false;
    }
    const text = fullFindingText(finding);
    return /auth|password|upload|xss|reflected|header|hsts|frame|wordpress|php|technology|csp|coverage/.test(text);
  }).length;
  const securityWarningCount = findings.filter(statusIsIssue).length;
  const formsOrSearchDetected = authSurfaceDetected || passwordFormDetected || uploadFormDetected || reflectedInputCount > 0;
  const testedParametersLow = formsOrSearchDetected && (attackSurface?.testedParameters ?? 0) <= 3;
  const crawledPagesLow = (attackSurface?.crawledPages ?? 0) > 0 && (attackSurface?.crawledPages ?? 0) <= 3 && formsOrSearchDetected;
  const noAuthenticatedContextWithAuthSurface =
    authSurfaceDetected && !findings.some((finding) => /authenticated session context|protected api access|session reuse/.test(fullFindingText(finding)));

  return {
    reflectedInputCount,
    authSurfaceDetected,
    passwordFieldWeakness,
    passwordFormDetected,
    uploadFormDetected,
    uploadGroupingSignal,
    sensitiveFormSignal,
    passwordGroupingSignal,
    appOwnedLoginFormSignal,
    xssIndicators,
    sensitiveEndpointProtected,
    sensitiveEndpointReachable,
    apiExposureLikely,
    browserRenderingFailed,
    browserAppShellCoverageGap,
    browserLowCoverage,
    crawledPagesLow,
    testedParametersLow,
    noAuthenticatedContextWithAuthSurface,
    weakCsp,
    missingCsp,
    missingFrameProtection,
    missingHsts,
    missingXcto,
    missingReferrer,
    securityTxtMissing,
    wordpressDetected,
    highDynamicPlatform,
    knownVulnerableTrainingApp,
    wordpressExactVersionExposed,
    phpVersionExposed,
    versionExposure,
    likelyMediumSecurityFindings,
    likelySecurityWarnings,
    securityWarningCount,
    authSurfaceFinding,
    passwordFinding,
    uploadFinding,
    xssFinding,
    reflectedFinding,
    browserFinding,
    clickjackingFinding,
    cspFinding,
    hstsFinding,
    xctoFinding,
    referrerFinding,
  };
}

export function scoreFixCandidate(finding: ScanFinding, attackPaths: AttackPath[] = []) {
  let score = finding.riskScore ?? 0;
  const evidenceStrength = effectiveEvidenceStrength(finding);

  if (finding.confidence === "confirmed" && evidenceStrength !== "weak") score += 20;
  if (finding.confidence === "likely") score += 5;

  const severity = effectiveSeverity(finding);
  if (severity === "critical") score += 15;
  if (severity === "high") score += 10;
  if (severity === "medium") score += 4;

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

  if (evidenceStrength === "weak") {
    score -= 20;
  } else if (evidenceStrength === "moderate") {
    score -= 6;
  }

  return score;
}

function groupedFixPriorityLabel(riskScore: number) {
  return priorityLabel(riskScore);
}

function groupedFixes(findings: ScanFinding[]): GroupedFix[] {
  const context = buildSecurityContext(findings);
  const confirmedConcrete = findings.some(isConfirmedExploitableVulnerability);
  const groups: GroupedFix[] = [];

  const collect = (...items: Array<ScanFinding | undefined>) => items.filter((item): item is ScanFinding => Boolean(item));

  if (!confirmedConcrete && context.authSurfaceDetected) {
    const related = collect(
      context.authSurfaceFinding,
      context.passwordFinding,
      context.clickjackingFinding,
      context.reflectedFinding,
      context.xssFinding,
      context.uploadGroupingSignal ? context.uploadFinding : undefined,
    );
    const riskScore =
      context.wordpressDetected || context.passwordFieldWeakness || context.missingFrameProtection ? 72 : 64;
    groups.push({
      id: "auth-form-surface-hardening",
      title: "Harden authentication and form attack surface",
      riskScore,
      priorityLabel: groupedFixPriorityLabel(riskScore),
      findings: related.map((finding) => finding.id),
      affectedUrls: related.flatMap(findingUrlList).slice(0, 10),
      reason:
        "Login and form endpoints are high-value attack surfaces. The scan found baseline weaknesses, reflected/form signals, or coverage limits that make lower-level header fixes too narrow as the first action.",
      recommendation:
        "Review authentication routes, enforce anti-framing, verify CSRF protection, validate form handling, harden password pages, and run a Deep or Authenticated scan for proof-level authorization checks.",
      confidence: "likely",
      isFixableVulnerability: false,
    });
  }

  if (context.xssIndicators || context.reflectedInputCount > 0) {
    const related = collect(context.xssFinding, context.reflectedFinding, context.cspFinding);
    const riskScore = context.reflectedInputCount >= 5 || context.weakCsp ? 68 : 58;
    groups.push({
      id: "xss-reflection-review",
      title: context.weakCsp
        ? "Review unconfirmed reflected input indicators and CSP/header hardening"
        : "Review unconfirmed reflected input indicators",
      riskScore,
      priorityLabel: groupedFixPriorityLabel(riskScore),
      findings: related.map((finding) => finding.id),
      affectedUrls: related.flatMap(findingUrlList).slice(0, 10),
      reason:
        "The scanner observed reflected input or DOM patterns, but active XSS probes did not confirm browser execution. Review output encoding and CSP posture for defense-in-depth.",
      recommendation:
        "Review reflected parameters by output context, add regression tests, encode untrusted values, and strengthen CSP with script-src, object-src, base-uri, and frame-ancestors directives.",
      confidence: "likely",
      isFixableVulnerability: false,
    });
  }

  if (
    context.uploadGroupingSignal ||
    context.sensitiveFormSignal ||
    context.passwordGroupingSignal ||
    context.appOwnedLoginFormSignal
  ) {
    const related = collect(
      context.uploadFinding,
      context.authSurfaceFinding,
      context.passwordFinding,
      context.xssFinding,
      context.reflectedFinding,
    );
    const riskScore = context.wordpressDetected || context.xssIndicators ? 64 : 54;
    groups.push({
      id: "upload-form-handling-review",
      title: "Review upload and form handling protections",
      riskScore,
      priorityLabel: groupedFixPriorityLabel(riskScore),
      findings: related.map((finding) => finding.id),
      affectedUrls: related.flatMap(findingUrlList).slice(0, 10),
      reason:
        "Upload and form surfaces can become high-impact when validation, CSRF, output encoding, or storage handling is weak.",
      recommendation:
        "Validate uploads server-side, restrict allowed file types, require CSRF protection, keep forms same-origin over HTTPS, and review rendering of submitted content.",
      confidence: "likely",
      isFixableVulnerability: false,
    });
  }

  if (context.browserRenderingFailed || context.browserLowCoverage) {
    const related = collect(context.browserFinding, context.authSurfaceFinding, context.xssFinding);
    const riskScore = context.authSurfaceDetected || context.xssIndicators ? 62 : 48;
    groups.push({
      id: "browser-rendered-coverage-fix",
      title: "Fix browser-rendered crawl coverage",
      riskScore,
      priorityLabel: groupedFixPriorityLabel(riskScore),
      findings: related.map((finding) => finding.id),
      affectedUrls: related.flatMap(findingUrlList).slice(0, 10),
      reason:
        "The scan had limited browser-rendered coverage, so JavaScript-only routes, login states, and stored-content render locations may be under-tested.",
      recommendation:
        "Enable Playwright rendering in the scan environment, confirm the target can load in Chromium, and rerun with authenticated contexts for protected surfaces.",
      confidence: "info",
      isFixableVulnerability: false,
    });
  }

  if (context.missingFrameProtection || context.missingHsts || context.missingXcto || context.missingReferrer || context.weakCsp) {
    const related = collect(context.clickjackingFinding, context.cspFinding, context.hstsFinding, context.xctoFinding, context.referrerFinding);
    const riskScore = context.authSurfaceDetected ? 58 : 42;
    groups.push({
      id: "security-header-hardening",
      title: "Strengthen security headers and anti-framing controls",
      riskScore,
      priorityLabel: groupedFixPriorityLabel(riskScore),
      findings: related.map((finding) => finding.id),
      affectedUrls: related.flatMap(findingUrlList).slice(0, 10),
      reason:
        "Browser security headers are baseline protections. They become more important when login, form, upload, or reflected-input surfaces are present.",
      recommendation:
        "Add strong iframe protection, HSTS, X-Content-Type-Options, Referrer-Policy, and a meaningful CSP rather than a CSP that only upgrades insecure requests.",
      confidence: "info",
      isFixableVulnerability: false,
    });
  }

  const unique = new Map<string, GroupedFix>();
  for (const group of groups) {
    unique.set(group.id, group);
  }
  return [...unique.values()].sort((left, right) => right.riskScore - left.riskScore);
}

function isGroupedFix(fix: FixRecommendation): fix is GroupedFix {
  return "findings" in fix && Array.isArray(fix.findings);
}

function scoreFixRecommendation(fix: FixRecommendation, attackPaths: AttackPath[] = []) {
  if (isGroupedFix(fix)) {
    return fix.riskScore;
  }
  return scoreFixCandidate(fix, attackPaths);
}

function isRobotsTopFixEligible(finding: ScanFinding) {
  if (!/robots/.test(`${finding.id} ${finding.checkKey ?? ""} ${finding.title}`.toLowerCase())) {
    return true;
  }

  return evidenceRecordArray(finding, "samples").some((sample) => {
    return (
      sample.disallowPathSampled === true &&
      sample.reachable === true &&
      sample.sensitiveDataObserved === true
    );
  });
}

function isCookieTopFixEligible(finding: ScanFinding) {
  const text = `${finding.id} ${finding.checkKey ?? ""} ${finding.title}`.toLowerCase();
  if (!/cookie|session-handling/.test(text)) {
    return true;
  }

  const sensitiveCookies = evidenceStringArray(finding, "sensitiveCookies");
  const missingSensitive =
    evidenceStringArray(finding, "sensitiveMissing").length +
    evidenceStringArray(finding, "missingSecure").length +
    evidenceStringArray(finding, "missingHttpOnly").length +
    evidenceStringArray(finding, "missingSameSite").length;

  return sensitiveCookies.length > 0 && missingSensitive > 0;
}

function isTopFixEligibleFinding(finding: ScanFinding) {
  return isRobotsTopFixEligible(finding) && isCookieTopFixEligible(finding);
}

export function chooseRecommendedFirstFix(findings: ScanFinding[], attackPaths: AttackPath[] = []): FixRecommendation | null {
  const confirmedConcrete = [...findings]
    .filter((finding) => isConcreteFixableFinding(finding) && finding.confidence === "confirmed" && effectiveEvidenceStrength(finding) !== "weak")
    .sort((left, right) => scoreFixCandidate(right, attackPaths) - scoreFixCandidate(left, attackPaths))[0];

  if (confirmedConcrete) {
    return confirmedConcrete;
  }

  return getTopFixes(findings, attackPaths, 1)[0] ?? null;
}

export function getTopFixes(findings: ScanFinding[], attackPaths: AttackPath[] = [], limit = 5): FixRecommendation[] {
  const concrete = [...findings]
    .filter((finding) => isConcreteFixableFinding(finding) && isTopFixEligibleFinding(finding))
    .sort((left, right) => scoreFixCandidate(right, attackPaths) - scoreFixCandidate(left, attackPaths));
  const groups = groupedFixes(findings);
  const hasConfirmedConcrete = concrete.some((finding) => finding.confidence === "confirmed");
  const candidates =
    !hasConfirmedConcrete && groups.length > 0
      ? ([...groups, ...concrete] as FixRecommendation[])
      : ([...groups, ...concrete] as FixRecommendation[]).sort(
          (left, right) => scoreFixRecommendation(right, attackPaths) - scoreFixRecommendation(left, attackPaths),
        );
  const selected: FixRecommendation[] = [];
  const coveredFindingIds = new Set<string>();

  for (const candidate of candidates) {
    if (isGroupedFix(candidate)) {
      selected.push(candidate);
      candidate.findings.forEach((findingId) => coveredFindingIds.add(findingId));
    } else if (!coveredFindingIds.has(candidate.id)) {
      selected.push(candidate);
    }

    if (selected.length >= limit) {
      break;
    }
  }

  return selected;
}

export function isConfirmedExploitableVulnerability(finding: ScanFinding): boolean {
  return (
    isFixableOrInferred(finding) &&
	    finding.confidence === "confirmed" &&
	    effectiveEvidenceStrength(finding) !== "weak" &&
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
  const severity = effectiveSeverity(finding);
  const surfaceTag = finding.scoringTags?.some((tag) =>
    ["auth-surface", "password-form", "upload-form", "reflected-input", "browser-coverage-failed", "weak-csp"].includes(tag),
  );

  return (
    finding.confidence === "likely" &&
    (severity === "high" || severity === "critical") &&
    (isConcreteFixableFinding(finding) || surfaceTag === true)
  );
}

function isFixableOrInferred(finding: ScanFinding) {
  return (
    finding.isFixableVulnerability === true ||
    (finding.isFixableVulnerability !== false && isConcreteFixableFinding(finding))
  );
}

function penaltyForLikelyFinding(finding: ScanFinding) {
  const severity = effectiveSeverity(finding);
  if (finding.confidence !== "likely" || !statusIsIssue(finding)) {
    return 0;
  }
  if (severity === "critical") return 18;
  if (severity === "high") return 14;
  if (severity === "medium") return 8;
  if (severity === "low") return 3;
  return 0;
}

function riskLabelForScore(score: number): SecurityScoreBreakdown["riskLabel"] {
  if (score >= 85) return "Low Risk";
  if (score >= 70) return "Medium Risk";
  if (score >= 50) return "High Risk";
  return "Critical Risk";
}

function atLeastRiskLabel(
  label: SecurityScoreBreakdown["riskLabel"],
  minimum: SecurityScoreBreakdown["riskLabel"],
) {
  const order: SecurityScoreBreakdown["riskLabel"][] = ["Low Risk", "Medium Risk", "High Risk", "Critical Risk"];
  return order.indexOf(label) < order.indexOf(minimum) ? minimum : label;
}

function pushCap(capsApplied: string[], label: string, score: number, maxScore: number) {
  if (score > maxScore) {
    capsApplied.push(label);
    return maxScore;
  }
  return score;
}

export function calculateCoverageConfidence(
  findings: ScanFinding[],
  attackSurface?: { crawledPages?: number; testedParameters?: number },
): CoverageConfidence {
  const context = buildSecurityContext(findings, attackSurface);
  const signals: string[] = [];

  if (context.browserAppShellCoverageGap) {
    signals.push("The target looked like a JavaScript app shell, but browser rendering did not produce usable route coverage.");
  } else if (context.browserRenderingFailed) {
    signals.push("Browser rendering failed and the scan fell back to fetch-only coverage.");
  } else if (context.browserLowCoverage) {
    signals.push("Browser rendering produced limited route coverage.");
  }
  if (context.noAuthenticatedContextWithAuthSurface) {
    signals.push("Authentication surface was detected, but no authenticated context was available.");
  }
  if (context.testedParametersLow) {
    signals.push("Forms or search inputs were detected, but the tested parameter count was low.");
  }
  if (context.crawledPagesLow) {
    signals.push("Crawled page count was low for a site with forms or reflected inputs.");
  }

  const level: CoverageConfidence["level"] =
    context.browserAppShellCoverageGap ||
    context.browserRenderingFailed ||
    (context.noAuthenticatedContextWithAuthSurface && (context.authSurfaceDetected || context.xssIndicators)) ||
    signals.length >= 3
      ? "Low"
      : signals.length > 0
        ? "Medium"
        : "High";

  return {
    level,
    signals,
    explanation:
      level === "Low"
        ? "Coverage confidence is limited. Treat the absence of confirmed exploits as a proof limitation, not a clean bill of health."
        : level === "Medium"
          ? "Coverage was useful but bounded. Some stateful or browser-rendered checks may need deeper validation."
          : "Coverage signals look healthy for this scan mode.",
  };
}

export function calculateSecurityScore(
  findings: ScanFinding[],
  attackPaths: AttackPath[] = [],
  attackSurface?: { crawledPages?: number; testedParameters?: number },
): SecurityScoreBreakdown {
  const context = buildSecurityContext(findings, attackSurface);
  const capsApplied: string[] = [];

  const confirmedConcreteCritical = findings.filter(
    (finding) =>
      isFixableOrInferred(finding) &&
	      finding.confidence === "confirmed" &&
	      effectiveEvidenceStrength(finding) !== "weak" &&
	      effectiveSeverity(finding) === "critical" &&
      isConcreteFixableFinding(finding),
  );
  const confirmedConcreteHigh = findings.filter(
    (finding) =>
      isFixableOrInferred(finding) &&
	      finding.confidence === "confirmed" &&
	      effectiveEvidenceStrength(finding) !== "weak" &&
	      effectiveSeverity(finding) === "high" &&
      isConcreteFixableFinding(finding),
  );
  const confirmedConcreteMedium = findings.filter(
    (finding) =>
      isFixableOrInferred(finding) &&
	      finding.confidence === "confirmed" &&
	      effectiveEvidenceStrength(finding) !== "weak" &&
	      effectiveSeverity(finding) === "medium" &&
      isConcreteFixableFinding(finding),
  );
  const likelyIssues = findings.filter((finding) =>
    finding.confidence === "likely" &&
    statusIsIssue(finding) &&
    !isHeaderFinding(finding) &&
    !finding.scoringTags?.some((tag) =>
      ["auth-surface", "password-form", "upload-form", "reflected-input", "browser-coverage-failed", "wordpress", "version-exposure"].includes(tag),
    ) &&
    !/authentication surface review|password field security|file upload risk indicators|xss evidence review|reflected input exposure|browser-rendered crawl coverage|technology fingerprinting/i.test(
      `${finding.checkKey ?? ""} ${finding.title}`,
    ) &&
    finding.isExploitSupportingEvidence !== true,
  );

  const confirmedExploitPenalty =
    confirmedConcreteCritical.length * 30 +
    confirmedConcreteHigh.length * 20 +
    confirmedConcreteMedium.length * 10;
  const likelyIssuePenalty = Math.min(
    likelyIssues.reduce((total, finding) => total + penaltyForLikelyFinding(finding), 0),
    28,
  );

  let attackSurfacePenalty = 0;
  if (context.authSurfaceDetected) attackSurfacePenalty += 12;
  if (context.passwordFieldWeakness) attackSurfacePenalty += 10;
  if (context.uploadFormDetected) attackSurfacePenalty += 10;
  if (context.xssIndicators) attackSurfacePenalty += 10;
  if (context.reflectedInputCount >= 6) attackSurfacePenalty += 12;
  else if (context.reflectedInputCount >= 3) attackSurfacePenalty += 8;
  else if (context.reflectedInputCount >= 1) attackSurfacePenalty += 5;
  if (context.sensitiveEndpointProtected) attackSurfacePenalty += 4;
  if (context.sensitiveEndpointReachable) attackSurfacePenalty += 8;
  if (context.apiExposureLikely) attackSurfacePenalty += 6;
  attackSurfacePenalty = Math.min(attackSurfacePenalty, 18);

  let coveragePenalty = 0;
  if (context.browserAppShellCoverageGap) coveragePenalty += 18;
  else if (context.browserRenderingFailed) coveragePenalty += 12;
  else if (context.browserLowCoverage) coveragePenalty += 6;
  if (context.crawledPagesLow) coveragePenalty += 5;
  if (context.testedParametersLow) coveragePenalty += 5;
  if (context.noAuthenticatedContextWithAuthSurface) coveragePenalty += 6;
  if (findings.some((finding) => /stored xss.*skipped|not allowlisted/.test(fullFindingText(finding)))) coveragePenalty += 2;
  coveragePenalty = Math.min(coveragePenalty, context.browserAppShellCoverageGap ? 22 : 10);

  let platformRiskPenalty = 0;
  if (context.wordpressExactVersionExposed) platformRiskPenalty += 4;
  if (context.phpVersionExposed) platformRiskPenalty += 5;
  if (context.wordpressDetected && context.authSurfaceDetected) platformRiskPenalty += 5;
  if (context.wordpressDetected && context.uploadFormDetected) platformRiskPenalty += 5;
  if (context.wordpressDetected && context.reflectedInputCount > 0) platformRiskPenalty += 5;
  if (context.wordpressDetected && context.browserRenderingFailed) platformRiskPenalty += 5;
  if (/third-party scripts without sri|subresource integrity|without sri/.test(findings.map(fullFindingText).join(" "))) {
    platformRiskPenalty += 5;
  }
  if (context.securityTxtMissing) platformRiskPenalty += 2;
  platformRiskPenalty = Math.min(platformRiskPenalty, 8);

  let headerPenalty = 0;
  if (context.missingFrameProtection) headerPenalty += context.passwordFormDetected || context.authSurfaceDetected ? 10 : 6;
  if (context.missingHsts) headerPenalty += 4;
  if (context.missingXcto) headerPenalty += 4;
  if (context.missingReferrer) headerPenalty += 3;
  if (context.weakCsp) headerPenalty += context.xssIndicators || context.authSurfaceDetected ? 8 : context.wordpressDetected ? 6 : 5;
  if (context.missingCsp) headerPenalty += 6;
  headerPenalty = Math.min(headerPenalty, 10);

  let score =
    100 -
    confirmedExploitPenalty -
    likelyIssuePenalty -
    attackSurfacePenalty -
    coveragePenalty -
    platformRiskPenalty -
    headerPenalty;

  const hasConfirmedAuthBypass = findings.some(
    (finding) =>
      normalized(finding.title).includes("authentication bypass") &&
	      finding.confidence === "confirmed" &&
	      effectiveEvidenceStrength(finding) !== "weak" &&
	      isFixableOrInferred(finding),
  );
  const hasConfirmedSqli = findings.some(
    (finding) =>
      (normalized(finding.title).includes("sql injection") ||
        normalized(finding.findingClass).includes("injection")) &&
	      finding.confidence === "confirmed" &&
	      effectiveEvidenceStrength(finding) !== "weak" &&
	      isFixableOrInferred(finding),
  );
  const hasConfirmedDbErrorOrBlindSql = findings.some(
    (finding) =>
      /(database error|db error|error disclosure|blind sql)/i.test(`${finding.checkKey ?? ""} ${finding.title}`) &&
      finding.confidence === "confirmed" &&
      effectiveEvidenceStrength(finding) !== "weak" &&
      isFixableOrInferred(finding),
  );
  const hasConfirmedDataExposure = findings.some(
    (finding) =>
      finding.confidence === "confirmed" &&
      effectiveEvidenceStrength(finding) !== "weak" &&
      statusIsIssue(finding) &&
      (finding.dataExposure === true || finding.evidence?.dataExposure === true),
  );
  const hasPrimaryAttackPath = attackPaths.length > 0;

  if (confirmedConcreteCritical.length > 0) score = pushCap(capsApplied, "confirmed critical exploitable vulnerability", score, 40);
  if (hasConfirmedSqli || hasConfirmedAuthBypass) score = pushCap(capsApplied, "confirmed SQLi/auth bypass", score, 30);
  if (hasConfirmedSqli && hasConfirmedAuthBypass) score = pushCap(capsApplied, "confirmed SQLi and auth bypass", score, 25);
  if (hasPrimaryAttackPath && (hasConfirmedSqli || hasConfirmedAuthBypass)) score = pushCap(capsApplied, "primary confirmed attack path", score, 25);
  if (context.knownVulnerableTrainingApp) score = pushCap(capsApplied, "known intentionally vulnerable application", score, 35);

  if (context.browserAppShellCoverageGap) score = pushCap(capsApplied, "unrendered SPA app shell", score, 58);
  if (context.authSurfaceDetected && context.browserRenderingFailed) score = pushCap(capsApplied, "auth surface with failed browser rendering", score, 75);
  if (context.authSurfaceDetected && context.passwordFieldWeakness) score = pushCap(capsApplied, "auth surface with password weakness", score, 72);
  if (context.authSurfaceDetected && context.missingFrameProtection) score = pushCap(capsApplied, "auth surface with missing iframe protection", score, 72);
  if (context.authSurfaceDetected && context.passwordFieldWeakness && context.missingFrameProtection) {
    score = pushCap(capsApplied, "auth + password + missing iframe protection", score, 68);
  }
  if (context.wordpressDetected && context.authSurfaceDetected && context.likelySecurityWarnings >= 3) {
    score = pushCap(capsApplied, "WordPress auth surface with likely warnings", score, 70);
  }
  if (context.wordpressDetected && context.uploadFormDetected && context.reflectedInputCount > 0) {
    score = pushCap(capsApplied, "WordPress upload surface with reflected inputs", score, 68);
  }
  if (context.browserRenderingFailed && context.xssIndicators) {
    score = pushCap(capsApplied, "failed browser rendering with XSS indicators", score, 70);
  }
  if (context.reflectedInputCount >= 5) score = pushCap(capsApplied, "five or more reflected inputs", score, 75);
  if (context.likelyMediumSecurityFindings >= 4) score = pushCap(capsApplied, "four or more likely medium security findings", score, 72);
  if (context.likelySecurityWarnings >= 6) score = pushCap(capsApplied, "six or more likely security warnings", score, 68);
	  if (context.browserRenderingFailed && context.noAuthenticatedContextWithAuthSurface && context.authSurfaceDetected) {
	    score = pushCap(capsApplied, "weak coverage on authentication surface", score, 70);
	  }

  const highLikelyConcrete = likelyIssues.some((finding) => {
    const severity = effectiveSeverity(finding);
    return severity === "high" || severity === "critical";
  });
  const highDynamicNoConfirmedExploit =
    context.highDynamicPlatform &&
    confirmedConcreteCritical.length === 0 &&
    confirmedConcreteHigh.length === 0 &&
    confirmedConcreteMedium.length === 0 &&
    !highLikelyConcrete &&
    !hasConfirmedDataExposure &&
    !hasConfirmedAuthBypass &&
    !hasConfirmedSqli &&
    !hasConfirmedDbErrorOrBlindSql;
  if (highDynamicNoConfirmedExploit) {
    const raisedScore = Math.max(score, 90);
    if (raisedScore > score) {
      capsApplied.push("high-dynamic platform weak signals deweighted");
      score = raisedScore;
    }
  }

  const confirmedExploitableCount = findings.filter(isConfirmedExploitableVulnerability).length;
  const likelyHighImpactIssues = findings.filter(isLikelyHighImpactIssue).length;
  const coverageConfidence = calculateCoverageConfidence(findings, attackSurface);
  const highCoverageNoConfirmedExploit =
    confirmedExploitableCount === 0 &&
    likelyHighImpactIssues === 0 &&
    coverageConfidence.level === "High" &&
    attackPaths.length === 0 &&
    !hasConfirmedDataExposure &&
    !hasConfirmedAuthBypass &&
    !hasConfirmedSqli &&
    !hasConfirmedDbErrorOrBlindSql;
  const manyMediumLikelySignals =
    context.likelyMediumSecurityFindings >= 4 ||
    context.reflectedInputCount >= 6 ||
    context.likelySecurityWarnings >= 6;
  const onlyLowHeaderCookieHardening =
    highCoverageNoConfirmedExploit &&
    !context.authSurfaceDetected &&
    !context.passwordFieldWeakness &&
    !context.uploadFormDetected &&
    !context.xssIndicators &&
    context.reflectedInputCount === 0 &&
    !highLikelyConcrete &&
    findings
      .filter(statusIsIssue)
      .every((finding) => {
        const text = `${finding.checkKey ?? ""} ${finding.title}`.toLowerCase();
        return effectiveSeverity(finding) === "low" && /header|hsts|csp|frame|referrer|permissions|cookie|security\.txt/.test(text);
      });

  if (highCoverageNoConfirmedExploit && !manyMediumLikelySignals) {
    const floor = onlyLowHeaderCookieHardening ? 85 : 82;
    if (score < floor) {
      capsApplied.push(
        onlyLowHeaderCookieHardening
          ? "high coverage with only low hardening notes"
          : "high coverage without confirmed exploitable vulnerabilities",
      );
      score = floor;
    }
  } else if (highCoverageNoConfirmedExploit && context.highDynamicPlatform && score < 90) {
    capsApplied.push("high-dynamic platform with unconfirmed medium signals");
    score = 90;
  }

	  const catastrophic =
    confirmedConcreteCritical.length >= 5 ||
    findings.some(
      (finding) =>
        normalized(finding.title).includes("admin compromise") &&
        finding.confidence === "confirmed",
    );

  score = catastrophic ? Math.max(score, 0) : Math.max(score, 10);
  const finalScore = clamp(Math.round(score), 0, 100);

  let riskLabel = riskLabelForScore(finalScore);
  const cannotBeLow =
    context.authSurfaceDetected ||
    context.passwordFieldWeakness ||
    context.uploadFormDetected ||
    context.xssIndicators ||
    context.reflectedInputCount >= 3 ||
    context.browserRenderingFailed ||
    (context.wordpressDetected && context.phpVersionExposed) ||
    context.securityWarningCount >= 4;
  if (cannotBeLow && !highDynamicNoConfirmedExploit) {
    riskLabel = atLeastRiskLabel(riskLabel, "Medium Risk");
  }

  const mustBeHigh =
    (context.authSurfaceDetected && context.passwordFieldWeakness && context.missingFrameProtection) ||
    (context.wordpressDetected && context.authSurfaceDetected && context.reflectedInputCount > 0) ||
    (context.browserRenderingFailed && context.authSurfaceDetected && context.xssIndicators) ||
    (context.uploadFormDetected && context.xssIndicators);
	  if (mustBeHigh) {
	    riskLabel = atLeastRiskLabel(riskLabel, "High Risk");
	  }
  if (highDynamicNoConfirmedExploit) {
    riskLabel = riskLabelForScore(finalScore);
  } else if (
    context.highDynamicPlatform &&
    confirmedConcreteCritical.length === 0 &&
    confirmedConcreteHigh.length === 0 &&
    !highLikelyConcrete
  ) {
    riskLabel = atLeastRiskLabel(riskLabelForScore(finalScore), "Medium Risk");
  }
	  if (context.knownVulnerableTrainingApp || confirmedConcreteCritical.length > 0 || (hasConfirmedSqli && hasConfirmedAuthBypass)) {
	    riskLabel = atLeastRiskLabel(riskLabel, "Critical Risk");
	  }

  return {
    baseScore: 100,
    confirmedExploitPenalty,
    likelyIssuePenalty,
    attackSurfacePenalty,
    coveragePenalty,
    platformRiskPenalty,
    headerPenalty,
    capsApplied,
    finalScore,
    riskLabel,
    explanation:
      "Security score combines confirmed exploit risk, likely issue risk, attack surface, coverage confidence, platform exposure, and browser/header hardening. Unconfirmed issues are not marked confirmed, but they lower the score when they create meaningful attack surface or reduce scan confidence.",
  };
}

export function topFixes(findings: ScanFinding[], limit = 5) {
  return getTopFixes(findings, [], limit);
}
