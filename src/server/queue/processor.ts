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

  if (completed === 0 && failed === 0) {
    return "queued";
  }

  if (completed === 0 && failed < categoryKeys.length) {
    return "running";
  }

  if (completed + failed < categoryKeys.length) {
    return "partial";
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

  try {
    const result = await runCategory(category, buildTarget(current));
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
