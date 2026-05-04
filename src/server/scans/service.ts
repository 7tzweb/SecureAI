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
import { badRequest, notFound, paymentRequired } from "@/server/api/errors";
import { getQueueDriver } from "@/server/queue";
import { getRepository } from "@/server/repository";
import { setScanAuthContext, type ScanAuthContext } from "@/server/scans/auth-context";
import { validateTarget } from "@/server/scans/helpers";

export const FREE_SCAN_LIMIT = 3;
export const ANONYMOUS_SCAN_LIMIT = 3;
export const SCAN_CREDIT_PACK_SIZE = 20;
export const SCAN_CREDIT_PACK_PRICE_USD = 10;
const PRIVILEGED_SCAN_EMAIL = "7tzweb@gmail.com";
const PRIVILEGED_SCAN_LIMIT = 999_999;

function buildEvent(input: Omit<ScanEvent, "id" | "createdAt">): ScanEvent {
  return {
    id: randomUUID(),
    createdAt: new Date().toISOString(),
    ...input,
  };
}

function canAccessFixes(scan: ScanRecord, sessionUserId: string | null) {
  return Boolean(sessionUserId && scan.createdByUserId === sessionUserId);
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
  const hasUnlimitedPlan = privilegedAllowance;
  const freeLimit = privilegedAllowance ? PRIVILEGED_SCAN_LIMIT : FREE_SCAN_LIMIT;
  const purchasedScanCredits = privilegedAllowance ? 0 : (user?.purchasedScanCredits ?? 0);
  const totalScanAllowance = hasUnlimitedPlan
    ? PRIVILEGED_SCAN_LIMIT
    : freeLimit + purchasedScanCredits;
  const remainingScans = Math.max(0, totalScanAllowance - usedScans);

  return {
    usedScans,
    freeLimit,
    purchasedScanCredits,
    totalScanAllowance,
    remainingScans,
    requiresUpgrade: !hasUnlimitedPlan && usedScans >= totalScanAllowance,
    hasUnlimitedPlan,
    canCreateScans: hasUnlimitedPlan || usedScans < totalScanAllowance,
    upgradePriceUsd: SCAN_CREDIT_PACK_PRICE_USD,
    upgradeScanCredits: SCAN_CREDIT_PACK_SIZE,
  };
}

async function assertCanCreateScan(userId: string) {
  const quota = await getScanQuotaSummary(userId);
  if (!quota.canCreateScans) {
    throw paymentRequired(
      `You reached your ${quota.freeLimit} free scans. Buy ${quota.upgradeScanCredits} more scan credits for $${quota.upgradePriceUsd.toFixed(2)} to continue.`,
      "SCAN_QUOTA_EXCEEDED",
      quota,
    );
  }

  return quota;
}

async function assertCanCreateAnonymousScan(anonymousClientId: string) {
  const usedScans = await getRepository().countAnonymousScans(anonymousClientId);
  if (usedScans >= ANONYMOUS_SCAN_LIMIT) {
    throw paymentRequired(
      `You reached the ${ANONYMOUS_SCAN_LIMIT} free scans available without Google sign-in. Sign in with Google to continue.`,
      "ANONYMOUS_SCAN_QUOTA_EXCEEDED",
      {
        usedScans,
        freeLimit: ANONYMOUS_SCAN_LIMIT,
        remainingScans: 0,
        canCreateScans: false,
      },
    );
  }
}

export async function createScan(
  targetInput: string,
  userId: string | null,
  anonymousClientId: string | null,
  authContext: ScanAuthContext = {},
) {
  if (userId) {
    await assertCanCreateScan(userId);
  } else if (anonymousClientId) {
    await assertCanCreateAnonymousScan(anonymousClientId);
  } else {
    throw badRequest(
      "Anonymous scan session is missing.",
      "ANONYMOUS_SCAN_SESSION_REQUIRED",
    );
  }

  const target = await validateTarget(targetInput);
  const repository = getRepository();
  const now = new Date().toISOString();
  const scan: ScanRecord = {
    id: randomUUID(),
    target: target.originalInput,
    normalizedTarget: target.normalizedTarget,
    targetHostname: target.targetHostname,
    createdByUserId: userId,
    anonymousClientId: userId ? null : anonymousClientId,
    createdAt: now,
    updatedAt: now,
    status: "queued",
    currentPhase: "init",
    partialSummary: {},
    phaseTimings: [],
    scanMode: authContext.scanMode ?? (authContext.authCookieHeader || authContext.authUsername ? "Authenticated" : "Fast"),
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
  setScanAuthContext(scan.id, {
    scanMode: authContext.scanMode ?? null,
    authCookieHeader: authContext.authCookieHeader?.trim() || null,
    secondaryAuthCookieHeader: authContext.secondaryAuthCookieHeader?.trim() || null,
    authLoginUrl: authContext.authLoginUrl?.trim() || null,
    authUsername: authContext.authUsername?.trim() || null,
    authPassword: authContext.authPassword?.trim() || null,
    authRoleLabel: authContext.authRoleLabel?.trim() || null,
    secondaryAuthLoginUrl: authContext.secondaryAuthLoginUrl?.trim() || null,
    secondaryAuthUsername: authContext.secondaryAuthUsername?.trim() || null,
    secondaryAuthPassword: authContext.secondaryAuthPassword?.trim() || null,
    secondaryAuthRoleLabel: authContext.secondaryAuthRoleLabel?.trim() || null,
  });
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

  const viewerCanAccessFixes = canAccessFixes(scan, sessionUserId);
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
  const viewerCanAccessFixes = canAccessFixes(scan, sessionUserId);
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
  const currentScan = await repository.getScan(scanId);
  if (!currentScan) {
    throw notFound("Scan not found.");
  }

  if (!currentScan.createdByUserId) {
    await assertCanCreateScan(userId);
  }

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
  if (!sessionUserId) {
    return [];
  }

  const scans = await getRepository().listUserScans(sessionUserId);
  return scans.slice(0, limit);
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
