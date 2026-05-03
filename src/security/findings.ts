import {
  type FindingConfidence,
  type ScanFinding,
  type ScanFindingEvidence,
  type SecurityFindingCategory,
  type Severity,
  type StructuredEvidence,
} from "@/lib/types";
import { deriveFindingStatus } from "@/lib/utils";
import { calculateFindingRisk } from "@/security/analysis/riskPrioritizer";

const secretValuePattern =
  /\b(eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9._-]{8,}\.[A-Za-z0-9._-]{8,}|[A-Za-z0-9._-]{28,})\b/g;

export function maskSecretPreview(value: string, head = 6, tail = 4) {
  const compact = value.trim();
  if (compact.length <= head + tail + 3) {
    return `${compact.slice(0, Math.max(2, head))}...`;
  }

  return `${compact.slice(0, head)}...${compact.slice(-tail)}`;
}

function maskString(value: string) {
  return value.replace(secretValuePattern, (match) => maskSecretPreview(match));
}

function maskEvidenceValue(value: unknown): unknown {
  if (typeof value === "string") {
    return maskString(value);
  }
  if (Array.isArray(value)) {
    return value.map(maskEvidenceValue);
  }
  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value).map(([key, entry]) => [key, maskEvidenceValue(entry)]),
    );
  }
  return value;
}

function inferFindingClass(finding: Pick<ScanFinding, "checkKey" | "title" | "severity">): SecurityFindingCategory {
  const key = `${finding.checkKey ?? ""} ${finding.title}`.toLowerCase();
  if (/sql|injection|graphql/.test(key)) {
    return "injection";
  }
  if (/xss|cross-site|script/.test(key)) {
    return "xss";
  }
  if (/auth.*bypass|login|password|credential/.test(key)) {
    return "authentication";
  }
  if (/idor|authorization|access control|role|admin|object/.test(key)) {
    return "authorization";
  }
  if (/session|cookie|token|jwt|csrf/.test(key)) {
    return "session";
  }
  if (/cors/.test(key)) {
    return "cors";
  }
  if (/hsts|csp|header|frame|content-type|referrer|permissions/.test(key)) {
    return "headers";
  }
  if (/https|tls|transport|redirect/.test(key)) {
    return "transport";
  }
  if (/exposed|exposure|secret|source map|git|env|backup|file|directory|robots/.test(key)) {
    return "exposure";
  }
  if (/attack path|chain/.test(key)) {
    return "attack-path";
  }
  if (/technology|fingerprint|waf|coverage|surface|crawler|api/.test(key)) {
    return "recon";
  }
  if (finding.severity === "info") {
    return "recon";
  }
  return "other";
}

function firstString(value: unknown) {
  return typeof value === "string" && value.trim() ? value.trim() : null;
}

function numberOrNull(value: unknown) {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

function evidenceFromObject(evidence: ScanFindingEvidence): StructuredEvidence[] {
  const structured = Array.isArray(evidence.structuredEvidence)
    ? (evidence.structuredEvidence as StructuredEvidence[])
    : [];
  const rows: StructuredEvidence[] = [...structured];
  const statusBefore = numberOrNull(evidence.beforeStatus);
  const statusAfter = numberOrNull(evidence.afterStatus);
  const url = firstString(evidence.url) ?? firstString(evidence.checkedUrl) ?? undefined;
  const parameter = firstString(evidence.parameter) ?? undefined;
  const payload = firstString(evidence.payload) ?? firstString(evidence.probePayload) ?? undefined;

  if (url || statusBefore !== null || statusAfter !== null || payload || parameter) {
    rows.push({
      type: "request-response",
      url,
      parameter,
      sanitizedPayload: payload ? maskString(payload) : undefined,
      statusBefore,
      statusAfter,
      responseDiff: firstString(evidence.responseDiff) ?? undefined,
      notes: firstString(evidence.summary) ?? undefined,
    });
  }

  const resultItems = Array.isArray(evidence.results)
    ? evidence.results
    : Array.isArray(evidence.activeProbes)
      ? evidence.activeProbes
      : [];
  for (const item of resultItems.slice(0, 8)) {
    if (!item || typeof item !== "object") {
      continue;
    }
    const row = item as Record<string, unknown>;
    const rowUrl = firstString(row.url) ?? firstString(row.originalUrl) ?? firstString(row.mutatedUrl) ?? undefined;
    rows.push({
      type:
        row.executed === true
          ? "browser-execution"
          : row.crossUserAccess === true || row.ownershipConfirmed === true
            ? "ownership"
            : row.timeDelay === true
              ? "timing"
              : "request-response",
      url: rowUrl,
      method: firstString(row.method) ?? undefined,
      statusBefore: numberOrNull(row.baselineStatus) ?? numberOrNull(row.originalStatus),
      statusAfter: numberOrNull(row.status) ?? numberOrNull(row.trueStatus) ?? numberOrNull(row.secondaryStatus),
      parameter: firstString(row.parameter) ?? undefined,
      sanitizedPayload: firstString(row.payload) ? maskString(firstString(row.payload)!) : undefined,
      responseDiff:
        row.recordExpansion === true
          ? "record-count expansion"
          : row.responseDifference === true
            ? "stable response difference"
            : row.comparableResponse === true
              ? "comparable success after identifier mutation"
              : undefined,
      browserSignal: row.executed === true ? "payload execution observed" : undefined,
      ownerContext: firstString(row.ownerContext) ?? undefined,
      attackerContext: firstString(row.attackerContext) ?? undefined,
      victimContext: firstString(row.victimContext) ?? undefined,
      leakedFields: Array.isArray(row.leakedFields) ? row.leakedFields.filter((entry): entry is string => typeof entry === "string") : undefined,
    });
  }

  return rows;
}

function hasBrowserExecutionProof(evidence: ScanFindingEvidence, structuredEvidence: StructuredEvidence[]) {
  return (
    structuredEvidence.some(
      (entry) =>
        entry.type === "browser-execution" &&
        Boolean(entry.browserSignal || entry.dialogMessage || entry.consoleMessage || entry.domMarker),
    ) ||
    /confirmed-browser-execution|browser.*execut/i.test(String(evidence.confidence ?? "")) ||
    /executed in browser|browser.*execut/i.test(String(evidence.summary ?? evidence.responseDiff ?? ""))
  );
}

function hasOwnershipProof(evidence: ScanFindingEvidence, structuredEvidence: StructuredEvidence[]) {
  return (
    evidence.ownershipConfirmed === true ||
    evidence.confidence === "confirmed-cross-user-ownership" ||
    structuredEvidence.some((entry) => entry.type === "ownership" && Boolean(entry.ownerContext || entry.leakedFields?.length))
  );
}

function hasRepeatedBlindSqlProof(evidence: ScanFindingEvidence) {
  return (
    evidence.repeatedProbeConfirmed === true ||
    /confirmed-(?:boolean|time).*repeated|stable.*repeated/i.test(String(evidence.confidence ?? evidence.summary ?? ""))
  );
}

function classifyReportRole(input: ScanFinding, findingClass: SecurityFindingCategory) {
  const text = `${input.checkKey ?? ""} ${input.title} ${input.shortDescription}`.toLowerCase();
  const status = deriveFindingStatus(input);
  const isMetaFinding =
    input.isMetaFinding === true ||
    findingClass === "attack-path" ||
    /attack path analysis|attack-surface-summary|attack surface summary|session model|role-based access matrix|browser-rendered crawl coverage|technology fingerprinting|fingerprinting|crawl coverage|authentication surface review/i.test(text);
  const isExploitSupportingEvidence =
    input.isExploitSupportingEvidence === true ||
    /authenticated session context|protected api access|session reuse/i.test(text);
  const isClearlyFixable =
    input.isFixableVulnerability === true ||
    /sql injection|authentication bypass|stored xss|active xss|idor|cors|content-security-policy|hsts|x-frame-options|x-content-type-options|referrer-policy|permissions-policy|open redirect|exposed \.env|exposed \.git|exposed source maps|sensitive files|backup files|directory listing|graphql exposure|api exposure|cache-control|trace method|dangerous methods|host header|csrf|jwt/i.test(text);
  const isFixableVulnerability =
    input.isFixableVulnerability ??
    (isClearlyFixable && !isMetaFinding && !isExploitSupportingEvidence && status !== "pass" && status !== "info");

  return {
    isMetaFinding,
    isExploitSupportingEvidence,
    isFixableVulnerability,
  };
}

function stringifyEvidenceForScoring(evidence: ScanFindingEvidence) {
  try {
    return JSON.stringify(evidence).toLowerCase();
  } catch {
    return "";
  }
}

function evidenceArrayLength(evidence: ScanFindingEvidence, key: string) {
  const value = evidence[key];
  return Array.isArray(value) ? value.length : 0;
}

function inferScoringTags(input: ScanFinding, evidence: ScanFindingEvidence, structuredEvidence: StructuredEvidence[]) {
  const text = `${input.checkKey ?? ""} ${input.title} ${input.shortDescription} ${input.whyItMatters} ${input.recommendation}`.toLowerCase();
  const evidenceText = stringifyEvidenceForScoring(evidence);
  const combined = `${text} ${evidenceText}`;
  const tags = new Set(input.scoringTags ?? []);

  const add = (tag: string, condition: boolean) => {
    if (condition) {
      tags.add(tag);
    }
  };

  add("wordpress", /wordpress|wp-content|wp-includes|wpforms|wp-json/.test(combined));
  add("auth-surface", /authentication surface|login|signin|password reset|account-recovery|authroutecount|authsurfacedetected/.test(combined));
  add("password-form", /password field|passwordformcount|haspasswordfield|current-password|new-password/.test(combined));
  add("upload-form", /file upload|upload form|multipart|wpforms|upload-oriented/.test(combined));
  add("reflected-input", /reflected input|reflectedparameters|reflection|raw-reflection/.test(combined));
  add("browser-coverage-failed", /browser-rendered crawl coverage|fetch-only|did not produce a rendered page snapshot|rendered":false/.test(combined));
  add(
    "weak-csp",
    /content-security-policy|csp/.test(combined) &&
      /weak|missing|unsafe-inline|unsafe-eval|upgrade-insecure-requests|report-only/.test(combined),
  );
  add("missing-frame-protection", /x-frame-options|clickjacking|frame-ancestors/.test(combined) && /missing|partial|weaker|not expose/.test(combined));
  add("missing-hsts", /hsts|strict-transport-security/.test(combined) && /missing/.test(combined));
  add("missing-x-content-type-options", /x-content-type-options/.test(combined) && /missing|nosniff/.test(combined));
  add("missing-referrer-policy", /referrer-policy/.test(combined) && /missing/.test(combined));
  add("version-exposure", /version hints|x-powered-by|generator|php\/?\d|wordpress\s+\d|\b\d+(?:\.\d+){1,3}\b/.test(combined));
  add("php-version-exposure", /x-powered-by[^"]*php|php\/?\d|php\s*\d/.test(combined));
  add("sensitive-endpoint", /sensitive endpoint|admin|debug|configuration|protected/.test(combined));

  if (structuredEvidence.some((entry) => entry.type === "browser-execution")) {
    tags.add("browser-execution");
  }

  return [...tags];
}

function severityRank(severity: Severity) {
  return ["info", "low", "medium", "high", "critical"].indexOf(severity);
}

function maxSeverity(...severities: Severity[]) {
  return severities.reduce((highest, severity) =>
    severityRank(severity) > severityRank(highest) ? severity : highest,
  "info" as Severity);
}

function inferComputedRiskSeverity(input: ScanFinding, evidence: ScanFindingEvidence, scoringTags: string[]) {
  const status = deriveFindingStatus(input);
  if (status === "pass" || status === "info") {
    return input.computedRiskSeverity ?? input.severity;
  }

  const text = `${input.checkKey ?? ""} ${input.title} ${input.shortDescription}`.toLowerCase();
  const tags = new Set(scoringTags);
  const reflectedCount = evidenceArrayLength(evidence, "reflectedParameters");
  const passwordFormCount =
    typeof evidence.passwordFormCount === "number" ? evidence.passwordFormCount : evidenceArrayLength(evidence, "passwordForms");
  const authSurface =
    tags.has("auth-surface") ||
    evidence.authSurfaceDetected === true ||
    (typeof evidence.authRouteCount === "number" && evidence.authRouteCount > 0);
  const browserFailed = tags.has("browser-coverage-failed");
  const weakCsp = tags.has("weak-csp");
  const missingFrame = tags.has("missing-frame-protection");
  const wordpress = tags.has("wordpress");
  const reflected = tags.has("reflected-input") || reflectedCount > 0;
  const upload = tags.has("upload-form");

  let computed = input.computedRiskSeverity ?? input.severity;

  if (/authentication surface review/.test(text) && (passwordFormCount > 0 || missingFrame || wordpress || weakCsp)) {
    computed = maxSeverity(computed, "high");
  }
  if (/password field security/.test(text) && (missingFrame || tags.has("missing-hsts") || wordpress || browserFailed)) {
    computed = maxSeverity(computed, "high");
  }
  if (/file upload risk indicators/.test(text) && (wordpress || reflected || upload)) {
    computed = maxSeverity(computed, "high");
  }
  if (/xss evidence review|reflected input exposure/.test(text) && (reflectedCount >= 3 || weakCsp || wordpress || browserFailed)) {
    computed = maxSeverity(computed, "high");
  }
  if (/browser-rendered crawl coverage/.test(text) && (authSurface || reflected || wordpress || upload)) {
    computed = maxSeverity(computed, browserFailed ? "high" : "medium");
  }
  if (/technology fingerprinting|x-powered-by disclosure/.test(text) && tags.has("version-exposure") && (authSurface || wordpress || upload)) {
    computed = maxSeverity(computed, "medium");
  }

  return computed;
}

export function calculateConfidence(finding: ScanFinding): FindingConfidence {
  const confidence = finding.confidence ?? "info";
  const key = `${finding.checkKey ?? ""} ${finding.title}`.toLowerCase();
  const evidence = finding.evidence ?? {};
  const structuredEvidence = finding.structuredEvidence ?? evidenceFromObject(evidence);
  const status = deriveFindingStatus(finding);

  if (status === "pass" || status === "info") {
    return confidence === "confirmed" ? "info" : confidence;
  }

  if (confidence !== "confirmed") {
    return confidence;
  }

  if (/xss/.test(key) && !hasBrowserExecutionProof(evidence, structuredEvidence)) {
    return evidence.retrievable === true || /retrievable|persist/i.test(String(evidence.summary ?? "")) ? "likely" : "info";
  }

  if (/idor|object.*authorization|cross-user/.test(key) && !hasOwnershipProof(evidence, structuredEvidence)) {
    return "likely";
  }

  if (/blind.*sql/.test(key) && !hasRepeatedBlindSqlProof(evidence)) {
    return "likely";
  }

  if (/authentication.*bypass|auth.*bypass/.test(key)) {
    const verified =
      evidence.authenticatedVerification === true ||
      evidence.reusableSessionVerified === true ||
      /verified|reused/i.test(String(evidence.confidence ?? evidence.summary ?? ""));
    return verified ? "confirmed" : "likely";
  }

  return "confirmed";
}

export function normalizeFinding(input: ScanFinding): ScanFinding {
  const maskedEvidence = maskEvidenceValue(input.evidence ?? {}) as ScanFindingEvidence;
  const structuredEvidence = input.structuredEvidence ?? evidenceFromObject(maskedEvidence);
  const findingClass = input.findingClass ?? inferFindingClass(input);
  const confidence = calculateConfidence({
    ...input,
    evidence: maskedEvidence,
    structuredEvidence,
    findingClass,
  });
  const proofSummary =
    input.proofSummary ??
    firstString(maskedEvidence.summary) ??
    (structuredEvidence.length
      ? structuredEvidence
          .slice(0, 2)
          .map((entry) => entry.responseDiff ?? entry.browserSignal ?? entry.notes ?? entry.type)
          .filter(Boolean)
          .join("; ")
      : "Structured proof was not available for this check.");
  const affectedUrl =
    input.affectedUrl ??
    firstString(maskedEvidence.url) ??
    firstString(maskedEvidence.checkedUrl) ??
    structuredEvidence.find((entry) => entry.url)?.url;
  const affectedParameter =
    input.affectedParameter ??
    firstString(maskedEvidence.parameter) ??
    structuredEvidence.find((entry) => entry.parameter)?.parameter;
  const affectedMethod =
    input.affectedMethod ??
    firstString(maskedEvidence.method) ??
    structuredEvidence.find((entry) => entry.method)?.method;
  const status = deriveFindingStatus(input);
  const reportRole = classifyReportRole(input, findingClass);
  const scoringTags = inferScoringTags(input, maskedEvidence, structuredEvidence);
  const computedRiskSeverity = inferComputedRiskSeverity(input, maskedEvidence, scoringTags);
  const dataExposure =
    input.dataExposure ??
    (maskedEvidence.dataExposure === true ||
      /token|email|invoice|account|basket|order|secret|private|sensitive/i.test(
        `${input.title} ${input.shortDescription} ${proofSummary}`,
      ));
  const publicEndpoint =
    input.publicEndpoint ??
    (maskedEvidence.publicEndpoint === true ||
      (!input.authRequired && !/authenticated|session|user a|user b/i.test(`${input.title} ${input.shortDescription}`)));
  const authRequired =
    input.authRequired ??
    (maskedEvidence.authRequired === true ||
      /authenticated|session|user a|user b|role/i.test(`${input.title} ${input.shortDescription}`));
  const attackPathParticipant =
    input.attackPathParticipant ??
    (maskedEvidence.attackPathParticipant === true ||
      findingClass === "attack-path" ||
      Boolean(input.capabilitiesGained?.length));
  const risk = calculateFindingRisk({
    ...input,
    findingClass,
    confidence,
    computedRiskSeverity,
    scoringTags,
    evidence: maskedEvidence,
    structuredEvidence,
    proofSummary,
    publicEndpoint,
    authRequired,
    dataExposure,
    attackPathParticipant,
  });

  return {
    ...input,
    status,
    confidence,
    findingClass,
    computedRiskSeverity,
    scoringTags,
    evidence: {
      ...maskedEvidence,
      proofSummary,
      riskScore: risk.riskScore,
      priorityLabel: risk.priorityLabel,
    },
    structuredEvidence,
    proofSummary,
    affectedUrl,
    affectedParameter,
    affectedMethod,
    ...risk,
    publicEndpoint,
    authRequired,
    dataExposure,
    attackPathParticipant,
    capabilitiesGained: input.capabilitiesGained ?? [],
    requiresCapabilities: input.requiresCapabilities ?? [],
    falsePositiveNotes:
      input.falsePositiveNotes ??
      (confidence === "likely"
        ? "This finding is intentionally not marked confirmed because the scanner did not collect full exploitability proof."
        : undefined),
    ...reportRole,
  };
}
