import { average } from "@/lib/utils";
import { categoryKeys, type CategoryKey, type CategoryState, type ScanRecord } from "@/lib/types";
import { getRepository } from "@/server/repository";
import { getScanAuthContext } from "@/server/scans/auth-context";
import { runPerformanceScan } from "@/server/scans/performance";
import { runSecurityScan } from "@/server/scans/security";
import { runSeoScan } from "@/server/scans/seo";
import { type CategoryScanResult, type NormalizedTarget } from "@/server/scans/types";

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
): Promise<CategoryScanResult> {
  switch (category) {
    case "security":
      return runSecurityScan(target);
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

  if (running > 0) {
    return "running";
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

export async function processCategoryJob(scanId: string, category: CategoryKey) {
  const repository = getRepository();
  const current = await repository.getScan(scanId);
  if (!current) {
    return;
  }
  const target = buildTarget(current);
  const timeoutMs = categoryTimeoutMs(category, target);
  const runStartedAt = Date.now();

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
    const result = await withTimeout(
      runCategory(category, target),
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
        progress: computeProgress(categoryStatus),
        latestPhase: `${category} checks completed`,
        updatedAt: finishedAt,
        overallScore: average([
          scores.securityScore,
          scores.seoScore,
          scores.performanceScore,
        ]),
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
