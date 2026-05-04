import {
  categoryKeys,
  type CategoryKey,
  type CategoryState,
  type ScanEvent,
  type ScanFinding,
  type ScanPhase,
  type ScanRecord,
} from "@/lib/types";
import { getRepository } from "@/server/repository";
import { getScanAuthContext } from "@/server/scans/auth-context";
import { runPerformanceScan } from "@/server/scans/performance";
import { runSecurityScan } from "@/server/scans/security";
import { runSeoScan } from "@/server/scans/seo";
import { type CategoryScanResult, type NormalizedTarget, type ScanProgressUpdate } from "@/server/scans/types";

function buildTarget(scan: ScanRecord): NormalizedTarget {
  const authContext = getScanAuthContext(scan.id);
  return {
    originalInput: scan.target,
    normalizedTarget: scan.normalizedTarget,
    targetHostname: scan.targetHostname,
    httpsUrl: `https://${scan.targetHostname}`,
    httpUrl: `http://${scan.targetHostname}`,
    authCookieHeader: authContext.authCookieHeader ?? null,
    secondaryAuthCookieHeader: authContext.secondaryAuthCookieHeader ?? null,
    authLoginUrl: authContext.authLoginUrl ?? null,
    authUsername: authContext.authUsername ?? null,
    authPassword: authContext.authPassword ?? null,
    authRoleLabel: authContext.authRoleLabel ?? null,
    secondaryAuthLoginUrl: authContext.secondaryAuthLoginUrl ?? null,
    secondaryAuthUsername: authContext.secondaryAuthUsername ?? null,
    secondaryAuthPassword: authContext.secondaryAuthPassword ?? null,
    secondaryAuthRoleLabel: authContext.secondaryAuthRoleLabel ?? null,
    scanMode: authContext.scanMode ?? scan.scanMode ?? null,
  };
}

async function runCategory(
  category: CategoryKey,
  target: NormalizedTarget,
  options: { onProgress?: (update: ScanProgressUpdate) => Promise<void> | void } = {},
): Promise<CategoryScanResult> {
  switch (category) {
    case "security":
      return runSecurityScan(target, options);
    case "seo":
      return runSeoScan(target);
    case "performance":
      return runPerformanceScan(target);
  }
}

function categoryTimeoutMs(category: CategoryKey, target: NormalizedTarget) {
  if (category !== "security") {
    return 60_000;
  }

  switch (target.scanMode) {
    case "Deep":
      return 150_000;
    case "Authenticated":
      return 95_000;
    case "Fast":
    default:
      return 65_000;
  }
}

async function withTimeout<T>(promise: Promise<T>, timeoutMs: number, message: string) {
  let timeout: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      promise,
      new Promise<T>((_, reject) => {
        timeout = setTimeout(() => reject(new Error(message)), timeoutMs);
      }),
    ]);
  } finally {
    if (timeout) {
      clearTimeout(timeout);
    }
  }
}

function computeProgress(categoryState: Record<CategoryKey, CategoryState>) {
  const completed = categoryKeys.filter((category) => categoryState[category].status === "completed").length;
  const failed = categoryKeys.filter((category) => categoryState[category].status === "failed").length;
  const running = categoryKeys.filter((category) => categoryState[category].status === "running").length;

  if (completed + failed === categoryKeys.length) {
    return 100;
  }

  return Math.min(95, 10 + completed * 28 + failed * 24 + running * 8);
}

function deriveStatus(categoryState: Record<CategoryKey, CategoryState>): ScanRecord["status"] {
  const completed = categoryKeys.filter((category) => categoryState[category].status === "completed").length;
  const failed = categoryKeys.filter((category) => categoryState[category].status === "failed").length;
  const running = categoryKeys.filter((category) => categoryState[category].status === "running").length;
  const hasVisiblePartialResults = categoryKeys.some(
    (category) => categoryState[category].findingCount > 0 && categoryState[category].status === "running",
  );

  if (running > 0) {
    return hasVisiblePartialResults ? "partial-results" : "running";
  }

  if (completed === 0 && failed === 0) {
    return "queued";
  }

  if (completed + failed < categoryKeys.length) {
    return completed > 0 || failed > 0 ? "running" : "queued";
  }

  if (completed === 0 && failed === categoryKeys.length) {
    return "failed";
  }

  return failed > 0 ? "partial" : "completed";
}

function computeOverallScore(scores: {
  securityScore: number | null;
  seoScore: number | null;
  performanceScore: number | null;
}) {
  const weightedScores = [
    { score: scores.securityScore, weight: 0.7 },
    { score: scores.seoScore, weight: 0.15 },
    { score: scores.performanceScore, weight: 0.15 },
  ].filter((entry): entry is { score: number; weight: number } => typeof entry.score === "number");

  if (!weightedScores.length) {
    return null;
  }

  const weightTotal = weightedScores.reduce((sum, entry) => sum + entry.weight, 0);
  let overallScore = Math.round(
    weightedScores.reduce((sum, entry) => sum + entry.score * entry.weight, 0) / weightTotal,
  );

  if (typeof scores.securityScore === "number") {
    if (scores.securityScore <= 25) {
      overallScore = Math.min(overallScore, 45);
    } else if (scores.securityScore <= 40) {
      overallScore = Math.min(overallScore, 58);
    } else if (scores.securityScore <= 60) {
      overallScore = Math.min(overallScore, 72);
    }
  }

  return Math.max(0, Math.min(100, overallScore));
}

function buildEvent(scan: ScanRecord, category: CategoryKey, message: string) {
  return {
    id: crypto.randomUUID(),
    type: "status" as const,
    message,
    phase: category,
    progress: scan.progress,
    createdAt: new Date().toISOString(),
    metadata: {
      category,
    },
  };
}

function buildProgressEvent(
  scan: ScanRecord,
  category: CategoryKey,
  update: ScanProgressUpdate,
): ScanEvent {
  return {
    id: crypto.randomUUID(),
    type: "status",
    message: update.message,
    phase: update.phase,
    progress: scan.progress,
    createdAt: new Date().toISOString(),
    metadata: {
      category,
      phase: update.phase,
      partialResults: Boolean(update.findings?.length),
      findings: update.findings?.length ?? 0,
      urlsChecked: update.urlsChecked ?? 0,
      errors: update.errors ?? 0,
    },
  };
}

function summarizePartialFindings(findings: ScanFinding[]) {
  const warningCount = findings.filter((finding) => finding.status === "warning").length;
  const confirmedCount = findings.filter((finding) => finding.confidence === "confirmed").length;
  const likelyCount = findings.filter((finding) => finding.confidence === "likely").length;
  const infoCount = findings.filter((finding) => finding.status === "info" || finding.severity === "info").length;
  const firstFix =
    findings.find((finding) => finding.status === "fail" || finding.status === "warning")?.title ??
    findings[0]?.title ??
    "Initial baseline review";

  return {
    confirmedCount,
    likelyCount,
    warningCount,
    infoCount,
    firstFix,
  };
}

function appendPhaseTiming(
  scan: ScanRecord,
  phase: ScanPhase,
  startedAtMs: number,
  update: ScanProgressUpdate,
) {
  const endedAt = new Date().toISOString();
  return [
    ...(scan.phaseTimings ?? []).filter((timing) => timing.phase !== phase),
    {
      phase,
      startedAt: new Date(startedAtMs).toISOString(),
      endedAt,
      durationMs: Date.now() - startedAtMs,
      findingsAdded: update.findings?.length ?? 0,
      urlsChecked: update.urlsChecked ?? 0,
      errors: update.errors ?? 0,
    },
  ].slice(-20);
}

export async function processCategoryJob(scanId: string, category: CategoryKey) {
  const repository = getRepository();
  const current = await repository.getScan(scanId);
  if (!current) {
    return;
  }
  const target = buildTarget(current);
  const timeoutMs = categoryTimeoutMs(category, target);
  const runStartedAt = Date.now();
  const phaseStartedAt = new Map<ScanPhase, number>();

  const startedAt = new Date().toISOString();
  const runningScan = await repository.mutateScan(scanId, (scan) => {
    const categoryStatus = {
      ...scan.categoryStatus,
      [category]: {
        ...scan.categoryStatus[category],
        status: "running" as const,
        updatedAt: startedAt,
        error: null,
      },
    };

    return {
      ...scan,
      categoryStatus,
      status: deriveStatus(categoryStatus),
      currentPhase: category === "security" ? "init" : scan.currentPhase,
      progress: computeProgress(categoryStatus),
      latestPhase: `Running ${category} checks`,
      updatedAt: startedAt,
    };
  });
  await repository.addEvent(
    scanId,
    buildEvent(runningScan, category, `${category} checks started.`),
  );
  console.info(
    `[fixnx][scan:${scanId}][${category}] started target=${target.targetHostname} mode=${target.scanMode ?? "Fast"} timeout=${timeoutMs}ms`,
  );

  try {
    const handleProgress = async (update: ScanProgressUpdate) => {
      if (category !== "security") {
        return;
      }

      if (!phaseStartedAt.has(update.phase)) {
        phaseStartedAt.set(update.phase, Date.now());
      }

      if (update.findings?.length) {
        await repository.replaceFindingsForCategory(scanId, category, update.findings);
      }

      const now = new Date().toISOString();
      const scan = await repository.mutateScan(scanId, (latest) => {
        const categoryStatus = {
          ...latest.categoryStatus,
          [category]: {
            ...latest.categoryStatus[category],
            status: "running" as const,
            score: typeof update.score === "number" ? update.score : latest.categoryStatus[category].score,
            findingCount: update.findings?.length ?? latest.categoryStatus[category].findingCount,
            updatedAt: now,
            error: null,
          },
        };
        const progress = Math.max(
          latest.progress,
          update.percent ?? computeProgress(categoryStatus),
        );
        const partialSummary = update.findings?.length
          ? {
              ...latest.partialSummary,
              securityScore: typeof update.score === "number" ? update.score : latest.partialSummary?.securityScore,
              securityRiskLabel:
                typeof update.score === "number"
                  ? update.score >= 85
                    ? "Low Risk"
                    : update.score >= 70
                      ? "Medium Risk"
                      : update.score >= 50
                        ? "High Risk"
                        : "Critical Risk"
                  : latest.partialSummary?.securityRiskLabel,
              ...summarizePartialFindings(update.findings),
            }
          : latest.partialSummary;

        return {
          ...latest,
          categoryStatus,
          status: update.findings?.length ? "partial-results" : deriveStatus(categoryStatus),
          currentPhase: update.phase,
          progress,
          latestPhase: update.message,
          updatedAt: now,
          securityScore: typeof update.score === "number" ? update.score : latest.securityScore,
          partialSummary,
          phaseTimings: appendPhaseTiming(
            latest,
            update.phase,
            phaseStartedAt.get(update.phase) ?? Date.now(),
            update,
          ),
        };
      });

      await repository.addEvent(scanId, buildProgressEvent(scan, category, update));
      console.info(
        `[fixnx][scan:${scanId}][${category}] progress phase=${update.phase} progress=${scan.progress}% findings=${update.findings?.length ?? 0}`,
      );
    };

    const result = await withTimeout(
      runCategory(category, target, { onProgress: handleProgress }),
      timeoutMs,
      `${category} checks exceeded ${timeoutMs}ms timeout. Check the [fixnx][${category}] console phase logs for the last completed step.`,
    );
    console.info(
      `[fixnx][scan:${scanId}][${category}] completed duration=${Date.now() - runStartedAt}ms findings=${result.findings.length}`,
    );
    await repository.replaceFindingsForCategory(scanId, category, result.findings);

    const finishedAt = new Date().toISOString();
    const scan = await repository.mutateScan(scanId, (latest) => {
      const categoryStatus = {
        ...latest.categoryStatus,
        [category]: {
          status: "completed" as const,
          score: result.score,
          findingCount: result.findings.length,
          updatedAt: finishedAt,
          error: null,
        },
      };

      const scores = {
        securityScore:
          category === "security" ? result.score : latest.securityScore,
        seoScore: category === "seo" ? result.score : latest.seoScore,
        performanceScore:
          category === "performance" ? result.score : latest.performanceScore,
      };

      return {
        ...latest,
        categoryStatus,
        status: deriveStatus(categoryStatus),
        currentPhase: category === "security" ? "report" : latest.currentPhase,
        progress: computeProgress(categoryStatus),
        latestPhase: `${category} checks completed`,
        updatedAt: finishedAt,
        overallScore: computeOverallScore(scores),
        ...scores,
      };
    });

    await repository.addEvent(
      scanId,
      buildEvent(scan, category, `${category} checks completed.`),
    );
  } catch (error) {
    console.error(
      `[fixnx][scan:${scanId}][${category}] failed duration=${Date.now() - runStartedAt}ms`,
      error,
    );
    const failedAt = new Date().toISOString();
    const scan = await repository.mutateScan(scanId, (latest) => {
      const categoryStatus = {
        ...latest.categoryStatus,
        [category]: {
          ...latest.categoryStatus[category],
          status: "failed" as const,
          updatedAt: failedAt,
          error: error instanceof Error ? error.message : "Unknown worker failure.",
        },
      };

      return {
        ...latest,
        categoryStatus,
        status: deriveStatus(categoryStatus),
        currentPhase: category === "security" ? latest.currentPhase ?? "analysis" : latest.currentPhase,
        progress: computeProgress(categoryStatus),
        latestPhase: `${category} checks failed`,
        updatedAt: failedAt,
        errorSummary: error instanceof Error ? error.message : "Unknown worker failure.",
      };
    });

    await repository.addEvent(
      scanId,
      buildEvent(scan, category, `${category} checks failed.`),
    );
  }
}
