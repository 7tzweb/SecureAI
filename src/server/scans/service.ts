import { randomUUID } from "node:crypto";
import {
  type CategoryKey,
  type ScanQuotaSummary,
  type ScanEvent,
  type ScanFinding,
  type ScanRecord,
  type ScanSummaryResponse,
} from "@/lib/types";
import { emptyCategoryState } from "@/lib/utils";
import { notFound, paymentRequired, unauthorized } from "@/server/api/errors";
import { getQueueDriver } from "@/server/queue";
import { getRepository } from "@/server/repository";
import { validateTarget } from "@/server/scans/helpers";

export const FREE_SCAN_LIMIT = 5;
export const SCAN_PLAN_PRICE_USD = 9;
const PRIVILEGED_SCAN_EMAIL = "7tzweb@gmail.com";
const PRIVILEGED_SCAN_LIMIT = 999_999;

function buildEvent(input: Omit<ScanEvent, "id" | "createdAt">): ScanEvent {
  return {
    id: randomUUID(),
    createdAt: new Date().toISOString(),
    ...input,
  };
}

function canAccessFixes(sessionUserId: string | null) {
  return Boolean(sessionUserId);
}

function hasPrivilegedScanAllowance(email: string | null | undefined) {
  return email?.trim().toLowerCase() === PRIVILEGED_SCAN_EMAIL;
}

async function resumeIncompleteScanIfStale(scan: ScanRecord) {
  if (scan.status === "completed" || scan.status === "failed") {
    return scan;
  }

  const ageMs = Date.now() - new Date(scan.updatedAt).getTime();
  if (ageMs < 10_000) {
    return scan;
  }

  const repository = getRepository();
  const resumedAt = new Date().toISOString();
  const resumedScan = await repository.updateScan(scan.id, {
    latestPhase: "Resuming incomplete scan",
    updatedAt: resumedAt,
  });

  await repository.addEvent(
    scan.id,
    buildEvent({
      type: "system",
      message: "Scan resumed after an incomplete or stalled run.",
      phase: "resume",
      progress: resumedScan.progress,
      metadata: {},
    }),
  );
  await getQueueDriver().enqueueScan(scan.id);
  return resumedScan;
}

function redactFindings(findings: ScanFinding[], viewerCanAccessFixes: boolean) {
  return findings.map((finding) =>
    !viewerCanAccessFixes
      ? {
          ...finding,
          locked: true,
          whyItMatters: "Sign in with Google to view the full remediation context for this check.",
          recommendation: "Connect a verified Google session to unlock exact locations and fix guidance.",
          evidence: {},
          references: [],
        }
      : { ...finding, locked: false },
  );
}

export async function getScanQuotaSummary(userId: string): Promise<ScanQuotaSummary> {
  const repository = getRepository();
  const [user, usedScans] = await Promise.all([
    repository.getUser(userId),
    repository.countUserScans(userId),
  ]);

  const privilegedAllowance = hasPrivilegedScanAllowance(user?.email);
  const hasUnlimitedPlan =
    privilegedAllowance || user?.subscriptionStatus === "premium" || user?.entitlementLevel === "premium";
  const freeLimit = privilegedAllowance ? PRIVILEGED_SCAN_LIMIT : FREE_SCAN_LIMIT;
  const remainingScans = hasUnlimitedPlan
    ? Math.max(0, freeLimit - usedScans)
    : Math.max(0, freeLimit - usedScans);

  return {
    usedScans,
    freeLimit,
    remainingScans,
    requiresUpgrade: !hasUnlimitedPlan && usedScans >= freeLimit,
    hasUnlimitedPlan,
    canCreateScans: hasUnlimitedPlan || usedScans < freeLimit,
    upgradePriceUsd: SCAN_PLAN_PRICE_USD,
  };
}

async function assertCanCreateScan(userId: string) {
  const quota = await getScanQuotaSummary(userId);
  if (!quota.canCreateScans) {
    throw paymentRequired(
      `You reached the ${quota.freeLimit} free scans included with your Google account. Upgrade for $${quota.upgradePriceUsd} to keep creating scans.`,
      "SCAN_QUOTA_EXCEEDED",
      quota,
    );
  }

  return quota;
}

export async function createScan(targetInput: string, userId: string | null) {
  if (!userId) {
    throw unauthorized("Sign in with Google to start a new scan.");
  }

  await assertCanCreateScan(userId);
  const target = await validateTarget(targetInput);
  const repository = getRepository();
  const now = new Date().toISOString();
  const scan: ScanRecord = {
    id: randomUUID(),
    target: target.originalInput,
    normalizedTarget: target.normalizedTarget,
    targetHostname: target.targetHostname,
    createdByUserId: userId,
    createdAt: now,
    updatedAt: now,
    status: "queued",
    progress: 10,
    overallScore: null,
    securityScore: null,
    seoScore: null,
    performanceScore: null,
    isAnonymous: !userId,
    premiumUnlocked: false,
    visibility: userId ? "private" : "link",
    latestPhase: "Queued for asynchronous scanning",
    errorSummary: null,
    categoryStatus: emptyCategoryState(now),
  };

  await repository.createScan(scan);
  await repository.addEvent(
    scan.id,
    buildEvent({
      type: "status",
      message: "Scan queued and ready for background workers.",
      phase: "queued",
      progress: 10,
      metadata: {},
    }),
  );
  await getQueueDriver().enqueueScan(scan.id);

  return scan;
}

export async function getScanSummary(scanId: string, sessionUserId: string | null) {
  const repository = getRepository();
  const initialScan = await repository.getScan(scanId);
  const scan = initialScan ? await resumeIncompleteScanIfStale(initialScan) : null;
  if (!scan) {
    return null;
  }

  const viewerCanAccessFixes = canAccessFixes(sessionUserId);
  const response: ScanSummaryResponse = {
    scan,
    viewerCanAccessFixes,
    session: {
      isAuthenticated: Boolean(sessionUserId),
      userId: sessionUserId,
    },
  };
  return response;
}

export async function getScanFindings(
  scanId: string,
  sessionUserId: string | null,
  category?: CategoryKey,
) {
  const repository = getRepository();
  const scan = await repository.getScan(scanId);
  if (!scan) {
    return null;
  }

  const findings = await repository.listFindings(scanId, category);
  const viewerCanAccessFixes = canAccessFixes(sessionUserId);
  return {
    viewerCanAccessFixes,
    findings: redactFindings(findings, viewerCanAccessFixes),
  };
}

export async function getScanEvents(scanId: string) {
  return getRepository().listEvents(scanId);
}

export async function claimScanToUser(scanId: string, userId: string) {
  const repository = getRepository();
  const scan = await repository.claimScan(scanId, userId);
  await repository.addEvent(
    scanId,
    buildEvent({
      type: "auth",
      message: "Scan linked to signed-in account.",
      phase: "claim",
      progress: scan.progress,
      metadata: {
        userId,
      },
    }),
  );
  return scan;
}

export async function listScansForUser(userId: string) {
  return getRepository().listUserScans(userId);
}

export async function listRecentScansForSidebar(sessionUserId: string | null, limit = 8) {
  const scans = await getRepository().listRecentScans(limit * 3);
  return scans
    .filter(
      (scan) =>
        scan.visibility === "link" ||
        (sessionUserId !== null && scan.createdByUserId === sessionUserId),
    )
    .slice(0, limit);
}

export async function unlockPremiumForScan(scanId: string, userId: string) {
  const repository = getRepository();
  const scan = await repository.unlockScan(scanId, userId);
  await repository.addEvent(
    scanId,
    buildEvent({
      type: "billing",
      message: "Premium details unlocked for this scan.",
      phase: "billing",
      progress: scan.progress,
      metadata: {
        userId,
      },
    }),
  );
  return scan;
}

export async function requireOwnedScan(scanId: string, userId: string) {
  const repository = getRepository();
  const scan = await repository.getScan(scanId);
  if (!scan) {
    throw notFound("Scan not found.");
  }
  if (scan.createdByUserId !== userId) {
    throw notFound("Scan not found.");
  }
  return scan;
}
