import type { FindingConfidence, ScanFinding, Severity } from "@/lib/types";
import { deriveFindingStatus } from "@/lib/utils";

export type AttackPathStep = {
  stepNumber: number;
  title: string;
  findingId: string;
  severity: Severity;
  confidence: FindingConfidence;
  attackerAction: string;
  technicalEvidence: string;
  gainedCapability: string;
  businessImpact: string;
  affectedUrl?: string;
  affectedParameter?: string;
};

export type AttackPath = {
  id: string;
  title: string;
  summary: string;
  entryPoint: string;
  finalImpact: string;
  steps: AttackPathStep[];
  fixFirstFindingId: string;
  fixFirstReason: string;
  collapsedFindingsIfFixed: string[];
  riskScore: number;
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

export function buildAttackPaths(findings: ScanFinding[]) {
  const issues = findings
    .filter((finding) => {
      const status = deriveFindingStatus(finding);
      return status === "fail" || status === "warning";
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

  const paths: AttackPath[] = [];
  for (const start of issues.filter((entry) => entry.requires.length === 0).slice(0, 3)) {
    const gained = new Set(start.gained);
    const steps = [start];

    for (const candidate of issues) {
      if (candidate.finding.id === start.finding.id) {
        continue;
      }
      if (candidate.requires.every((requirement) => gained.has(requirement))) {
        steps.push(candidate);
        candidate.gained.forEach((capability) => gained.add(capability));
      }
      if (steps.length >= 5) {
        break;
      }
    }

    if (steps.length < 2) {
      continue;
    }

    const stepModels = steps.map((entry, index) => {
      const capability = entry.gained[0] ?? "access";
      return {
        stepNumber: index + 1,
        title: entry.finding.title,
        findingId: entry.finding.id,
        severity: entry.finding.severity,
        confidence: entry.finding.confidence ?? "info",
        attackerAction: actionFor(entry.finding),
        technicalEvidence: evidenceFor(entry.finding),
        gainedCapability: capability,
        businessImpact: finalImpactFor(capability),
        affectedUrl: entry.finding.affectedUrl,
        affectedParameter: entry.finding.affectedParameter,
      } satisfies AttackPathStep;
    });
    const finalCapability = stepModels.at(-1)?.gainedCapability ?? "access";
    const fixFirst = steps.find((entry) => entry.finding.confidence === "confirmed") ?? steps[0];

    paths.push({
      id: `attack-path-${start.finding.checkKey ?? start.finding.id}`,
      title: `From ${start.finding.title} to ${finalImpactFor(finalCapability).replace(/\.$/, "").toLowerCase()}`,
      summary: `The scanner connected ${stepModels.length} findings into a practical attacker narrative.`,
      entryPoint: start.finding.affectedUrl ?? start.finding.title,
      finalImpact: finalImpactFor(finalCapability),
      steps: stepModels,
      fixFirstFindingId: fixFirst.finding.id,
      fixFirstReason: `${fixFirst.finding.title} is the strongest early step and may remove downstream access if fixed.`,
      collapsedFindingsIfFixed: steps
        .filter((entry) => entry.finding.id !== fixFirst.finding.id)
        .map((entry) => entry.finding.id),
      riskScore: Math.min(100, Math.max(...steps.map((entry) => entry.finding.riskScore ?? 0)) + (stepModels.length - 1) * 5),
    });
  }

  return paths.slice(0, 3);
}
