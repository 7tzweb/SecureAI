import type { FindingConfidence, ScanFinding, Severity } from "@/lib/types";
import { deriveFindingStatus } from "@/lib/utils";

export type AttackPathStep = {
  stepNumber: number;
  title: string;
  findingId: string;
  severity: Severity;
  confidence: FindingConfidence;
  attackerAction: string;
  evidence: string;
  technicalEvidence: string;
  gainedCapability: string;
  businessImpact: string;
  affectedUrl?: string;
  affectedParameter?: string;
  isConfirmedChainStep: boolean;
  supportingEvidence?: boolean;
};

export type AttackPath = {
  id: string;
  title: string;
  summary: string;
  entryPoint: string;
  finalImpact: string;
  confirmedSteps: AttackPathStep[];
  likelyExtensions: AttackPathStep[];
  steps: AttackPathStep[];
  fixFirstFindingId: string;
  fixFirstTitle: string;
  fixFirstReason: string;
  collapsedFindingsIfFixed: string[];
  riskScore: number;
  suppressedRelatedPathCount?: number;
};

function defaultCapabilities(finding: ScanFinding) {
  const key = `${finding.checkKey ?? ""} ${finding.title}`.toLowerCase();
  if (/sql/.test(key)) {
    return ["database_query_manipulation", "data_exposure_possible"];
  }
  if (/auth.*bypass|authentication.*bypass/.test(key)) {
    return ["authenticated_context"];
  }
  if (/authenticated.*session|protected.*api/.test(key)) {
    return ["protected_api_access"];
  }
  if (/idor|object.*access|cross-user/.test(key)) {
    return ["cross_user_data_access"];
  }
  if (/xss/.test(key)) {
    return ["browser_code_execution"];
  }
  if (/admin/.test(key)) {
    return ["admin_surface_access"];
  }
  return [];
}

function defaultRequirements(finding: ScanFinding) {
  const key = `${finding.checkKey ?? ""} ${finding.title}`.toLowerCase();
  if (/idor|authenticated|protected|session|role/.test(key)) {
    return ["authenticated_context"];
  }
  return [];
}

function actionFor(finding: ScanFinding) {
  const key = `${finding.checkKey ?? ""} ${finding.title}`.toLowerCase();
  if (/sql/.test(key)) {
    return "Send a SQL-style payload to the affected public parameter.";
  }
  if (/auth.*bypass|authentication.*bypass/.test(key)) {
    return "Submit a controlled bypass payload to the login endpoint.";
  }
  if (/authenticated.*session|protected.*api/.test(key)) {
    return "Reuse the authenticated context against protected endpoint candidates.";
  }
  if (/idor|object.*access|cross-user/.test(key)) {
    return "Replay or mutate object identifiers while authenticated.";
  }
  if (/xss/.test(key)) {
    return "Deliver the controlled marker payload and open the affected page in a browser.";
  }
  return "Use the finding as the next step in the attack path.";
}

function finalImpactFor(capability: string) {
  switch (capability) {
    case "authenticated_context":
      return "The attacker gains authenticated application access.";
    case "protected_api_access":
      return "The attacker can reach protected APIs.";
    case "cross_user_data_access":
      return "The attacker may access another user's private data.";
    case "browser_code_execution":
      return "The attacker can execute code in a victim browser context.";
    case "admin_surface_access":
      return "The attacker can reach administrative or configuration surface.";
    default:
      return "The attacker can increase access or data exposure.";
  }
}

function evidenceFor(finding: ScanFinding) {
  return (
    finding.proofSummary ||
    (typeof finding.evidence.summary === "string" ? finding.evidence.summary : "") ||
    (typeof finding.evidence.responseDiff === "string" ? finding.evidence.responseDiff : "") ||
    "Structured evidence is attached to the finding."
  );
}

function isMetaFinding(finding: ScanFinding) {
  const key = `${finding.checkKey ?? ""} ${finding.title} ${finding.findingClass ?? ""}`.toLowerCase();
  return finding.isMetaFinding === true || /attack path analysis|attack-surface|coverage|crawl/.test(key);
}

function isSupportingFinding(finding: ScanFinding) {
  const key = `${finding.checkKey ?? ""} ${finding.title}`.toLowerCase();
  return finding.isExploitSupportingEvidence === true || /authenticated session context|protected api access/.test(key);
}

function chainOrder(entry: {
  finding: ScanFinding;
  gained: string[];
}) {
  const key = `${entry.finding.checkKey ?? ""} ${entry.finding.title}`.toLowerCase();
  if (/sql/.test(key)) return 10;
  if (/auth.*bypass|authentication.*bypass/.test(key)) return 20;
  if (/authenticated.*session|protected.*api|session reuse/.test(key)) return 30;
  if (/admin/.test(key)) return 40;
  if (/idor|object.*access|cross-user/.test(key)) return 50;
  if (/xss/.test(key)) return 60;
  return 90;
}

function stepFromEntry(
  entry: {
    finding: ScanFinding;
    gained: string[];
  },
  index: number,
  isConfirmedChainStep: boolean,
) {
  const capability = entry.gained[0] ?? "access";
  const evidence = evidenceFor(entry.finding);
  return {
    stepNumber: index + 1,
    title: entry.finding.title,
    findingId: entry.finding.id,
    severity: entry.finding.severity,
    confidence: entry.finding.confidence ?? "info",
    attackerAction: actionFor(entry.finding),
    evidence,
    technicalEvidence: evidence,
    gainedCapability: capability,
    businessImpact: finalImpactFor(capability),
    affectedUrl: entry.finding.affectedUrl,
    affectedParameter: entry.finding.affectedParameter,
    isConfirmedChainStep,
    supportingEvidence: isSupportingFinding(entry.finding),
  } satisfies AttackPathStep;
}

export function buildAttackPaths(findings: ScanFinding[]) {
  const issues = findings
    .filter((finding) => {
      const status = deriveFindingStatus(finding);
      return (status === "fail" || status === "warning") && !isMetaFinding(finding);
    })
    .map((finding) => ({
      finding,
      gained: finding.capabilitiesGained?.length ? finding.capabilitiesGained : defaultCapabilities(finding),
      requires: finding.requiresCapabilities?.length ? finding.requiresCapabilities : defaultRequirements(finding),
    }))
    .filter((entry) => entry.gained.length > 0)
    .sort((left, right) => {
      const confidenceDelta =
        (right.finding.confidence === "confirmed" ? 2 : right.finding.confidence === "likely" ? 1 : 0) -
        (left.finding.confidence === "confirmed" ? 2 : left.finding.confidence === "likely" ? 1 : 0);
      if (confidenceDelta !== 0) {
        return confidenceDelta;
      }
      return (right.finding.riskScore ?? 0) - (left.finding.riskScore ?? 0);
    });

  const gained = new Set<string>();
  const confirmedEntries = issues
    .filter((entry) => entry.finding.confidence === "confirmed")
    .sort((left, right) => chainOrder(left) - chainOrder(right));
  const confirmedChain: typeof confirmedEntries = [];

  for (const candidate of confirmedEntries) {
    const requirementsMet =
      candidate.requires.length === 0 ||
      candidate.requires.every((requirement) => gained.has(requirement)) ||
      isSupportingFinding(candidate.finding);

    if (!requirementsMet) {
      continue;
    }

    confirmedChain.push(candidate);
    candidate.gained.forEach((capability) => gained.add(capability));
  }

  const likelyExtensions = issues
    .filter(
      (entry) =>
        entry.finding.confidence === "likely" &&
        !confirmedChain.some((confirmed) => confirmed.finding.id === entry.finding.id),
    )
    .sort((left, right) => chainOrder(left) - chainOrder(right))
    .slice(0, 4);

  if (confirmedChain.length + likelyExtensions.length < 2) {
    return [];
  }

  const confirmedSteps = confirmedChain.map((entry, index) => stepFromEntry(entry, index, true));
  const likelyExtensionSteps = likelyExtensions.map((entry, index) =>
    stepFromEntry(entry, index, false),
  );
  const finalCapability =
    confirmedSteps.at(-1)?.gainedCapability ??
    likelyExtensionSteps.at(-1)?.gainedCapability ??
    "access";
  const fixFirst =
    confirmedChain.find((entry) => !isSupportingFinding(entry.finding)) ??
    confirmedChain[0] ??
    likelyExtensions[0];
  const title =
    confirmedSteps.some((step) => /sql/i.test(step.title)) &&
    confirmedSteps.some((step) => /auth/i.test(step.title))
      ? "From public SQL injection to authenticated access"
      : `From ${confirmedSteps[0]?.title ?? likelyExtensionSteps[0]?.title} to ${finalImpactFor(finalCapability).replace(/\.$/, "").toLowerCase()}`;
  const summary =
    confirmedSteps.length > 0
      ? "The scanner connected confirmed evidence into a practical attacker narrative. Likely downstream issues are listed separately because they require stronger proof."
      : "The scanner found likely chainable issues, but no confirmed multi-step attack path was proven.";

  return [
    {
      id: `attack-path-primary-${fixFirst?.finding.checkKey ?? fixFirst?.finding.id ?? "sampled"}`,
      title,
      summary,
      entryPoint: confirmedSteps[0]?.affectedUrl ?? likelyExtensionSteps[0]?.affectedUrl ?? title,
      finalImpact:
        confirmedSteps.length > 0 && likelyExtensionSteps.length > 0
          ? `${finalImpactFor(finalCapability)} Additional likely issues suggest possible downstream impact, but those require stronger proof.`
          : finalImpactFor(finalCapability),
      confirmedSteps,
      likelyExtensions: likelyExtensionSteps,
      steps: confirmedSteps,
      fixFirstFindingId: fixFirst?.finding.id ?? "",
      fixFirstTitle: fixFirst?.finding.title ?? "No concrete fixable step",
      fixFirstReason: fixFirst
        ? `${fixFirst.finding.title} is the strongest confirmed early step and may remove downstream attack-chain risk if fixed.`
        : "No concrete confirmed step was available.",
      collapsedFindingsIfFixed: [...confirmedChain, ...likelyExtensions]
        .filter((entry) => entry.finding.id !== fixFirst?.finding.id)
        .map((entry) => entry.finding.id),
      riskScore: Math.min(
        100,
        Math.max(...[...confirmedChain, ...likelyExtensions].map((entry) => entry.finding.riskScore ?? 0)) +
          Math.max(0, confirmedSteps.length - 1) * 5,
      ),
      suppressedRelatedPathCount: Math.max(0, issues.filter((entry) => entry.requires.length === 0).length - 1),
    },
  ];
}
