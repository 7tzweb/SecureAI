"use client";

import type { CSSProperties } from "react";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { startTransition, useEffect, useMemo, useState } from "react";
import { Clock3, Download, FileText, History, Shield, Wrench, X } from "lucide-react";
import { PaypalCreditsDialog } from "@/components/billing/paypal-credits-dialog";
import { FindingCard } from "@/components/results/finding-card";
import { useAuth } from "@/components/providers/auth-provider";
import { dispatchQuotaRefresh } from "@/lib/quota-events";
import {
  categoryKeys,
  type CategoryKey,
  type ScanEvent,
  type ScanFinding,
  type ScanRecord,
  type ScanQuotaSummary,
  type ScanSummaryResponse,
} from "@/lib/types";
import {
  cn,
  deriveFindingStatus,
  formatRelative,
  formatScore,
  getSeverityStyles,
  getScoreTone,
  getStatusStyles,
  titleCaseCategory,
} from "@/lib/utils";

type SidebarScan = Pick<
  ScanRecord,
  "id" | "targetHostname" | "createdAt" | "status" | "overallScore" | "progress"
>;

type ViewState = {
  scan: ScanRecord | null;
  findings: Record<CategoryKey, ScanFinding[]>;
  events: ScanEvent[];
  recentScans: SidebarScan[];
  viewerCanAccessFixes: boolean;
  sessionUserId: string | null;
  error: string | null;
};

function emptyFindings() {
  return {
    security: [],
    seo: [],
    performance: [],
  } as Record<CategoryKey, ScanFinding[]>;
}

function sanitizeFilename(value: string) {
  const normalized = value
    .toLowerCase()
    .replace(/^https?:\/\//, "")
    .replace(/^www\./, "")
    .replace(/[^a-z0-9.-]+/g, "-")
    .replace(/^-+|-+$/g, "");

  return normalized || "scan-report";
}

function buildPdfFilename(scan: ScanRecord) {
  const stamp = new Date(scan.updatedAt).toISOString().slice(0, 10);
  return `${sanitizeFilename(scan.targetHostname)}-${stamp}.pdf`;
}

function findingAccentTone(finding: ScanFinding) {
  const status = deriveFindingStatus(finding);
  if (status === "fail") {
    return finding.severity === "critical" ? "#dc2626" : "#e11d48";
  }
  if (status === "warning") {
    return finding.severity === "medium" ? "#d97706" : "#2563eb";
  }
  if (status === "pass") {
    return "#0c9156";
  }
  return "#64748b";
}

function findingSurfaceClasses(finding: ScanFinding) {
  const status = deriveFindingStatus(finding);
  if (status === "fail") {
    return finding.severity === "critical"
      ? "border-red-200 bg-[linear-gradient(180deg,rgba(255,255,255,0.98),rgba(254,242,242,0.92))]"
      : "border-rose-200 bg-[linear-gradient(180deg,rgba(255,255,255,0.98),rgba(255,241,242,0.92))]";
  }
  if (status === "warning") {
    return finding.severity === "medium"
      ? "border-amber-200 bg-[linear-gradient(180deg,rgba(255,255,255,0.98),rgba(255,251,235,0.92))]"
      : "border-sky-200 bg-[linear-gradient(180deg,rgba(255,255,255,0.98),rgba(239,246,255,0.92))]";
  }
  if (status === "pass") {
    return "border-emerald-200 bg-[linear-gradient(180deg,rgba(255,255,255,0.98),rgba(236,253,245,0.9))]";
  }
  return "border-slate-200 bg-[linear-gradient(180deg,rgba(255,255,255,0.98),rgba(248,250,252,0.96))]";
}

function detailPanelClasses(finding: ScanFinding) {
  const status = deriveFindingStatus(finding);
  if (status === "fail") {
    return "border border-white/70 bg-white/75 shadow-[0_10px_28px_rgba(248,113,113,0.08)]";
  }
  if (status === "warning") {
    return "border border-white/70 bg-white/75 shadow-[0_10px_28px_rgba(245,158,11,0.08)]";
  }
  if (status === "pass") {
    return "border border-white/70 bg-white/80 shadow-[0_10px_28px_rgba(16,185,129,0.07)]";
  }
  return "border border-white/70 bg-white/80 shadow-[0_10px_28px_rgba(148,163,184,0.08)]";
}

async function downloadReportPdf(
  scan: ScanRecord,
  findings: Record<CategoryKey, ScanFinding[]>,
) {
  const { jsPDF } = await import("jspdf");
  type PdfColor = readonly [number, number, number];
  const doc = new jsPDF({
    unit: "pt",
    format: "a4",
    compress: true,
  });

  const palette = {
    ink: [15, 23, 42] as const,
    muted: [100, 116, 139] as const,
    primary: [22, 103, 217] as const,
    border: [226, 232, 240] as const,
    surface: [248, 250, 252] as const,
    white: [255, 255, 255] as const,
  };
  const pageWidth = doc.internal.pageSize.getWidth();
  const pageHeight = doc.internal.pageSize.getHeight();
  const marginX = 42;
  const marginY = 48;
  const contentWidth = pageWidth - marginX * 2;
  const lineHeightFor = (fontSize: number) => fontSize * 1.45;
  const colorFromHex = (hex: string): PdfColor => {
    const normalized = hex.replace("#", "");
    return [
      Number.parseInt(normalized.slice(0, 2), 16),
      Number.parseInt(normalized.slice(2, 4), 16),
      Number.parseInt(normalized.slice(4, 6), 16),
    ];
  };
  const splitLines = (text: string, fontSize: number, maxWidth: number) => {
    doc.setFont("helvetica", "normal");
    doc.setFontSize(fontSize);
    return doc.splitTextToSize(text, maxWidth) as string[];
  };
  const getSeverityTheme = (
    severity: ScanFinding["severity"],
  ): { accent: PdfColor; soft: PdfColor; border: PdfColor; text: PdfColor } => {
    switch (severity) {
      case "critical":
        return {
          accent: [220, 38, 38] as const,
          soft: [254, 242, 242] as const,
          border: [254, 202, 202] as const,
          text: [185, 28, 28] as const,
        };
      case "high":
        return {
          accent: [225, 29, 72] as const,
          soft: [255, 241, 242] as const,
          border: [251, 207, 232] as const,
          text: [190, 24, 93] as const,
        };
      case "medium":
        return {
          accent: [217, 119, 6] as const,
          soft: [255, 251, 235] as const,
          border: [253, 230, 138] as const,
          text: [180, 83, 9] as const,
        };
      case "low":
        return {
          accent: [37, 99, 235] as const,
          soft: [239, 246, 255] as const,
          border: [191, 219, 254] as const,
          text: [29, 78, 216] as const,
        };
      case "info":
      default:
        return {
          accent: [100, 116, 139] as const,
          soft: [248, 250, 252] as const,
          border: [226, 232, 240] as const,
          text: [71, 85, 105] as const,
        };
    }
  };
  const getStatusTheme = (
    status: ScanFinding["status"],
  ): { fill: PdfColor; border: PdfColor; text: PdfColor } => {
    switch (status) {
      case "pass":
        return {
          fill: [236, 253, 245] as const,
          border: [167, 243, 208] as const,
          text: [6, 95, 70] as const,
        };
      case "warning":
        return {
          fill: [255, 251, 235] as const,
          border: [253, 230, 138] as const,
          text: [180, 83, 9] as const,
        };
      case "fail":
        return {
          fill: [254, 242, 242] as const,
          border: [254, 202, 202] as const,
          text: [185, 28, 28] as const,
        };
      case "info":
      default:
        return {
          fill: [248, 250, 252] as const,
          border: [226, 232, 240] as const,
          text: [71, 85, 105] as const,
        };
    }
  };
  const getPillWidth = (text: string, fontSize = 8.5, horizontalPadding = 10) => {
    doc.setFont("helvetica", "bold");
    doc.setFontSize(fontSize);
    return doc.getTextWidth(text) + horizontalPadding * 2;
  };
  const drawPill = ({
    x,
    y,
    text,
    fill,
    border,
    color,
    fontSize = 8.5,
    height = 20,
  }: {
    x: number;
    y: number;
    text: string;
    fill: readonly [number, number, number];
    border: readonly [number, number, number];
    color: readonly [number, number, number];
    fontSize?: number;
    height?: number;
  }) => {
    const width = getPillWidth(text, fontSize);
    doc.setFillColor(...fill);
    doc.setDrawColor(...border);
    doc.roundedRect(x, y, width, height, height / 2, height / 2, "FD");
    doc.setFont("helvetica", "bold");
    doc.setFontSize(fontSize);
    doc.setTextColor(...color);
    doc.text(text, x + width / 2, y + height / 2 + fontSize * 0.32, {
      align: "center",
    });
    return width;
  };

  let cursorY = marginY;

  const ensureSpace = (height: number) => {
    if (cursorY + height <= pageHeight - marginY) {
      return;
    }

    doc.addPage();
    cursorY = marginY;
  };

  const drawTextBlock = ({
    text,
    x = marginX,
    maxWidth = contentWidth,
    fontSize,
    color,
    fontStyle = "normal",
    gapAfter = 0,
  }: {
    text: string;
    x?: number;
    maxWidth?: number;
    fontSize: number;
    color: readonly [number, number, number];
    fontStyle?: "normal" | "bold";
    gapAfter?: number;
  }) => {
    const lines = splitLines(text, fontSize, maxWidth);
    const lineHeight = lineHeightFor(fontSize);

    doc.setFont("helvetica", fontStyle);
    doc.setFontSize(fontSize);
    doc.setTextColor(...color);

    lines.forEach((line) => {
      ensureSpace(lineHeight);
      doc.text(line, x, cursorY);
      cursorY += lineHeight;
    });

    cursorY += gapAfter;
  };

  const drawMetricCard = ({
    x,
    label,
    value,
    score,
  }: {
    x: number;
    label: string;
    value: string;
    score: number | null;
  }) => {
    const cardWidth = (contentWidth - 24) / 4;
    const y = cursorY;
    const tone = colorFromHex(getScoreTone(score));
    const progressWidth = Math.max(0, Math.min(1, (score ?? 0) / 100)) * (cardWidth - 28);

    doc.setFillColor(...palette.white);
    doc.setDrawColor(...palette.border);
    doc.roundedRect(x, y, cardWidth, 72, 16, 16, "FD");

    doc.setFont("helvetica", "bold");
    doc.setFontSize(9);
    doc.setTextColor(...palette.muted);
    doc.text(label.toUpperCase(), x + 14, y + 22);

    doc.setFont("helvetica", "bold");
    doc.setFontSize(24);
    doc.setTextColor(...tone);
    doc.text(value, x + 14, y + 52);

    doc.setDrawColor(...palette.border);
    doc.setLineWidth(3);
    doc.line(x + 14, y + 60, x + cardWidth - 14, y + 60);
    if (progressWidth > 0) {
      doc.setDrawColor(...tone);
      doc.line(x + 14, y + 60, x + 14 + progressWidth, y + 60);
    }
  };

  const drawFindingCard = (finding: ScanFinding) => {
    const cardX = marginX;
    const cardWidth = contentWidth;
    const statusTheme = getStatusTheme(finding.status);
    const severityTheme = getSeverityTheme(finding.severity);
    const issueDetected = finding.status === "warning" || finding.status === "fail";
    const innerX = cardX + (issueDetected ? 26 : 18);
    const innerWidth = cardWidth - (issueDetected ? 44 : 36);
    const statusLabel = finding.status.toUpperCase();
    const severityLabel =
      finding.status === "warning" || finding.status === "fail"
        ? `${finding.severity.toUpperCase()} SEVERITY`
        : null;
    const chipGap = 8;
    const chipHeight = 20;
    const statusChipWidth = getPillWidth(statusLabel);
    const severityChipWidth = severityLabel ? getPillWidth(severityLabel) : 0;
    const chipsWidth = statusChipWidth + (severityLabel ? chipGap + severityChipWidth : 0);
    const titleLines = splitLines(finding.title, 16, Math.max(180, innerWidth - chipsWidth - 18));
    const summaryLines = splitLines(finding.shortDescription, 11, innerWidth);
    const detailPanelGap = 12;
    const detailPanelWidth = finding.locked ? innerWidth : (innerWidth - detailPanelGap) / 2;
    const detailPanelTextWidth = detailPanelWidth - 28;
    const whyLines = finding.locked
      ? splitLines(
          "Sign in with Google to unlock the full remediation details for this check.",
          10,
          detailPanelTextWidth,
        )
      : splitLines(finding.whyItMatters, 10, detailPanelTextWidth);
    const recommendationLines = finding.locked
      ? []
      : splitLines(finding.recommendation, 10, detailPanelTextWidth);
    const titleHeight = titleLines.length * lineHeightFor(16);
    const summaryHeight = summaryLines.length * lineHeightFor(11);
    const whyHeight = whyLines.length * lineHeightFor(10);
    const recommendationHeight = recommendationLines.length * lineHeightFor(10);
    const headerHeight = Math.max(titleHeight, chipHeight);
    const panelHeadingHeight = lineHeightFor(9);
    const whyPanelHeight = 14 + panelHeadingHeight + 6 + whyHeight + 14;
    const recommendationPanelHeight = finding.locked
      ? 0
      : 14 + panelHeadingHeight + 6 + recommendationHeight + 14;
    const detailPanelsHeight = finding.locked
      ? whyPanelHeight
      : Math.max(whyPanelHeight, recommendationPanelHeight);
    const cardHeight =
      18 +
      headerHeight +
      10 +
      12 +
      summaryHeight +
      16 +
      detailPanelsHeight +
      18;

    if (cursorY !== marginY) {
      ensureSpace(cardHeight + 12);
    }

    const startY = cursorY;
    let localY = startY + 18;
    const cardBorderColor = issueDetected ? severityTheme.border : palette.border;

    doc.setFillColor(...palette.white);
    doc.setDrawColor(...cardBorderColor);
    doc.roundedRect(cardX, startY, cardWidth, cardHeight, 18, 18, "FD");
    if (issueDetected) {
      doc.setFillColor(...severityTheme.accent);
      doc.roundedRect(cardX + 8, startY + 14, 5, cardHeight - 28, 3, 3, "F");
    }

    doc.setFont("helvetica", "bold");
    doc.setFontSize(16);
    doc.setTextColor(...palette.ink);
    titleLines.forEach((line) => {
      doc.text(line, innerX, localY);
      localY += lineHeightFor(16);
    });

    const chipsY = startY + 18;
    let chipCursorX = cardX + cardWidth - 18 - statusChipWidth;
    if (severityLabel) {
      const severityX = cardX + cardWidth - 18 - severityChipWidth;
      chipCursorX = severityX - chipGap - statusChipWidth;
      drawPill({
        x: severityX,
        y: chipsY,
        text: severityLabel,
        fill: severityTheme.soft,
        border: severityTheme.border,
        color: severityTheme.text,
      });
    }
    drawPill({
      x: chipCursorX,
      y: chipsY,
      text: statusLabel,
      fill: statusTheme.fill,
      border: statusTheme.border,
      color: statusTheme.text,
    });

    localY = startY + 18 + headerHeight + 12;
    doc.setFont("helvetica", "normal");
    doc.setFontSize(11);
    doc.setTextColor(...palette.muted);
    summaryLines.forEach((line) => {
      doc.text(line, innerX, localY);
      localY += lineHeightFor(11);
    });

    localY += 16;
    const detailStartY = localY;
    const drawDetailPanel = ({
      x,
      width,
      title,
      lines,
      accent,
      soft,
    }: {
      x: number;
      width: number;
      title: string;
      lines: string[];
      accent: readonly [number, number, number];
      soft: readonly [number, number, number];
    }) => {
      const panelHeight = 14 + panelHeadingHeight + 6 + lines.length * lineHeightFor(10) + 14;
      let panelY = detailStartY + 14;
      doc.setFillColor(...soft);
      doc.setDrawColor(...palette.border);
      doc.roundedRect(x, detailStartY, width, panelHeight, 14, 14, "FD");
      doc.setFont("helvetica", "bold");
      doc.setFontSize(9);
      doc.setTextColor(...accent);
      doc.text(title, x + 14, panelY);
      panelY += panelHeadingHeight + 6;
      doc.setFont("helvetica", "normal");
      doc.setFontSize(10);
      doc.setTextColor(...palette.ink);
      lines.forEach((line) => {
        doc.text(line, x + 14, panelY);
        panelY += lineHeightFor(10);
      });
    };

    drawDetailPanel({
      x: innerX,
      width: detailPanelWidth,
      title: finding.locked ? "DETAILS" : "WHY IT MATTERS",
      lines: whyLines,
      accent: issueDetected ? severityTheme.accent : palette.primary,
      soft: palette.surface,
    });

    if (!finding.locked) {
      drawDetailPanel({
        x: innerX + detailPanelWidth + detailPanelGap,
        width: detailPanelWidth,
        title: "RECOMMENDATION",
        lines: recommendationLines,
        accent: palette.primary,
        soft: [239, 246, 255],
      });
    }

    cursorY += cardHeight + 12;
  };

  const headerBadgeRadius = 30;
  const headerRightX = pageWidth - marginX - 68;
  const headerBadgeCenterY = marginY + 40;

  doc.setFont("helvetica", "bold");
  doc.setFontSize(10);
  doc.setTextColor(...palette.primary);
  doc.text("CYBERAUDIT FULL REPORT", marginX, cursorY);

  cursorY += 24;
  doc.setFont("helvetica", "bold");
  doc.setFontSize(26);
  doc.setTextColor(...palette.ink);
  doc.text(scan.targetHostname, marginX, cursorY);

  cursorY += 22;
  drawTextBlock({
    text: `Target: ${scan.target}`,
    fontSize: 11,
    color: palette.muted,
    gapAfter: 0,
  });
  drawTextBlock({
    text: `Generated: ${new Date(scan.updatedAt).toLocaleString()}`,
    fontSize: 11,
    color: palette.muted,
    gapAfter: 0,
  });
  drawTextBlock({
    text: `Status: ${scan.status}`,
    fontSize: 11,
    color: palette.muted,
    gapAfter: 20,
  });

  const overallTone = colorFromHex(getScoreTone(scan.overallScore));
  doc.setDrawColor(...overallTone);
  doc.setLineWidth(6);
  doc.circle(headerRightX, headerBadgeCenterY, headerBadgeRadius, "S");
  doc.setFont("helvetica", "bold");
  doc.setFontSize(24);
  doc.setTextColor(...overallTone);
  doc.text(formatScore(scan.overallScore), headerRightX, headerBadgeCenterY + 4, {
    align: "center",
  });
  doc.setFont("helvetica", "bold");
  doc.setFontSize(7);
  doc.setTextColor(...palette.muted);
  doc.text("OVERALL", headerRightX, headerBadgeCenterY + 16, { align: "center" });

  ensureSpace(84);
  const metricWidth = (contentWidth - 24) / 4;
  drawMetricCard({
    x: marginX,
    label: "Overall Score",
    value: formatScore(scan.overallScore),
    score: scan.overallScore,
  });
  drawMetricCard({
    x: marginX + metricWidth + 8,
    label: "Security",
    value: formatScore(scan.securityScore),
    score: scan.securityScore,
  });
  drawMetricCard({
    x: marginX + (metricWidth + 8) * 2,
    label: "SEO",
    value: formatScore(scan.seoScore),
    score: scan.seoScore,
  });
  drawMetricCard({
    x: marginX + (metricWidth + 8) * 3,
    label: "Performance",
    value: formatScore(scan.performanceScore),
    score: scan.performanceScore,
  });
  cursorY += 96;

  categoryKeys.forEach((category) => {
    ensureSpace(40);
    doc.setFont("helvetica", "bold");
    doc.setFontSize(18);
    doc.setTextColor(...palette.ink);
    doc.text(titleCaseCategory(category), marginX, cursorY);

    doc.setFont("helvetica", "normal");
    doc.setFontSize(11);
    doc.setTextColor(...palette.muted);
    doc.text(`${findings[category].length} checks`, pageWidth - marginX, cursorY, {
      align: "right",
    });

    cursorY += 10;
    doc.setDrawColor(...palette.border);
    doc.setLineWidth(1);
    doc.line(marginX, cursorY, pageWidth - marginX, cursorY);
    cursorY += 20;

    if (findings[category].length === 0) {
      drawTextBlock({
        text: "No checks were returned for this category.",
        fontSize: 11,
        color: palette.muted,
        gapAfter: 12,
      });
      return;
    }

    findings[category].forEach((finding) => {
      drawFindingCard(finding);
    });
    cursorY += 6;
  });

  const pageCount = doc.getNumberOfPages();
  for (let pageNumber = 1; pageNumber <= pageCount; pageNumber += 1) {
    doc.setPage(pageNumber);
    doc.setFont("helvetica", "normal");
    doc.setFontSize(9);
    doc.setTextColor(...palette.muted);
    doc.text(
      `Page ${pageNumber} of ${pageCount}`,
      pageWidth - marginX,
      pageHeight - 18,
      { align: "right" },
    );
  }

  doc.save(buildPdfFilename(scan));
}

async function fetchJson<T>(url: string) {
  const response = await fetch(url, { cache: "no-store" });
  const payload = (await response.json().catch(() => null)) as T | { error?: string } | null;

  if (!response.ok) {
    const message =
      payload && typeof payload === "object" && "error" in payload && typeof payload.error === "string"
        ? payload.error
        : "Request failed";
    throw new Error(message);
  }

  return payload as T;
}

async function fetchWorkspaceData(scanId: string) {
  const [summary, findingsPayload, eventsPayload, recentPayload] = await Promise.all([
    fetchJson<ScanSummaryResponse>(`/api/scans/${scanId}`),
    fetchJson<{ findings: ScanFinding[]; viewerCanAccessFixes: boolean }>(
      `/api/scans/${scanId}/findings`,
    ),
    fetchJson<{ events: ScanEvent[] }>(`/api/scans/${scanId}/events`),
    fetchJson<{ scans: SidebarScan[] }>(`/api/scans/recent`),
  ]);

  const grouped = emptyFindings();
  findingsPayload.findings.forEach((finding) => {
    grouped[finding.category].push(finding);
  });

  return {
    scan: summary.scan,
    findings: grouped,
    events: eventsPayload.events,
    recentScans: recentPayload.scans,
    viewerCanAccessFixes: findingsPayload.viewerCanAccessFixes,
    sessionUserId: summary.session.userId,
  };
}

export function ResultsClient({ scanId }: { scanId: string }) {
  const router = useRouter();
  const pathname = usePathname();
  const searchParams = useSearchParams();
  const { user, status, isConfigured, signInWithGoogle, ensureServerSession } = useAuth();
  const [state, setState] = useState<ViewState>({
    scan: null,
    findings: emptyFindings(),
    events: [],
    recentScans: [],
    viewerCanAccessFixes: false,
    sessionUserId: null,
    error: null,
  });
  const [actionError, setActionError] = useState<string | null>(null);
  const [actionPending, setActionPending] = useState(false);
  const [downloadPending, setDownloadPending] = useState(false);
  const [reportOpen, setReportOpen] = useState(false);
  const [quota, setQuota] = useState<ScanQuotaSummary | null>(null);
  const [paypalOpen, setPaypalOpen] = useState(false);
  const [displayProgress, setDisplayProgress] = useState(0);

  const requestedTab = (searchParams.get("tab") as CategoryKey | null) ?? "security";
  const activeTab = categoryKeys.includes(requestedTab) ? requestedTab : "security";

  useEffect(() => {
    let cancelled = false;

    const loadWorkspace = async () => {
      try {
        const next = await fetchWorkspaceData(scanId);
        if (!cancelled) {
          startTransition(() => {
            setState({
              ...next,
              error: null,
            });
          });
        }
      } catch (error) {
        const message = error instanceof Error ? error.message : "Unable to load the report.";
        if (!cancelled) {
          startTransition(() => {
            setState((current) => ({ ...current, error: message }));
          });
        }
      }
    };

    void loadWorkspace();
    const interval = window.setInterval(() => {
      void loadWorkspace();
    }, 2500);

    return () => {
      cancelled = true;
      window.clearInterval(interval);
    };
  }, [scanId, status, user?.uid]);

  const scan = state.scan;
  const progressTarget = scan ? Math.max(0, Math.min(100, scan.progress)) : 0;
  const shouldAnimateProgress = scan ? scan.status === "queued" || scan.status === "running" : false;

  useEffect(() => {
    setDisplayProgress(0);
  }, [scanId]);

  useEffect(() => {
    if (!scan) {
      return;
    }

    if (!shouldAnimateProgress) {
      setDisplayProgress(progressTarget);
      return;
    }

    if (displayProgress > progressTarget) {
      setDisplayProgress(progressTarget);
      return;
    }

    if (displayProgress === progressTarget) {
      return;
    }

    if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
      setDisplayProgress(progressTarget);
      return;
    }

    const remaining = progressTarget - displayProgress;
    const delay = remaining > 40 ? 16 : remaining > 15 ? 24 : 36;
    const timer = window.setTimeout(() => {
      setDisplayProgress((current) => Math.min(current + 1, progressTarget));
    }, delay);

    return () => {
      window.clearTimeout(timer);
    };
  }, [displayProgress, progressTarget, scan, shouldAnimateProgress]);

  const categoryCards = useMemo(
    () =>
      categoryKeys.map((category) => {
        const snapshot = scan?.categoryStatus[category];
        const findings = state.findings[category];
        const count = snapshot?.findingCount ?? findings.length;
        const passCount = findings.filter((finding) => {
          const status = deriveFindingStatus(finding);
          return status === "pass" || status === "info";
        }).length;
        const score =
          category === "security"
            ? scan?.securityScore ?? null
            : category === "seo"
              ? scan?.seoScore ?? null
              : scan?.performanceScore ?? null;

        return {
          category,
          status: snapshot?.status ?? "queued",
          count,
          passCount,
          failCount: Math.max(count - passCount, 0),
          score,
        };
      }),
    [scan, state.findings],
  );

  const activeFindings = state.findings[activeTab];
  const latestEvent = state.events[0] ?? null;
  const allFindings = useMemo(() => categoryKeys.flatMap((category) => state.findings[category]), [state.findings]);
  const criticalIssueCount = useMemo(
    () =>
      allFindings.filter(
        (finding) => deriveFindingStatus(finding) === "fail" && finding.severity === "critical",
      ).length,
    [allFindings],
  );
  const warningIssueCount = useMemo(
    () => allFindings.filter((finding) => deriveFindingStatus(finding) === "warning").length,
    [allFindings],
  );
  const failingIssueCount = useMemo(
    () => allFindings.filter((finding) => deriveFindingStatus(finding) === "fail").length,
    [allFindings],
  );

  const handleChangeTab = (tab: CategoryKey) => {
    const nextParams = new URLSearchParams(searchParams.toString());
    nextParams.set("tab", tab);
    router.replace(`${pathname}?${nextParams.toString()}`, { scroll: false });
  };

  const refreshWorkspace = async () => {
    const next = await fetchWorkspaceData(scanId);
    setState({
      ...next,
      error: null,
    });
  };

  const handleContinueWithGoogle = async () => {
    setActionError(null);

    if (!isConfigured) {
      setActionError("Firebase client setup is missing, so Google sign-in is disabled.");
      return;
    }

    setActionPending(true);
    try {
      const sessionUser =
        user && status === "signed-in" ? await ensureServerSession() : await signInWithGoogle();
      const shouldClaimScan =
        Boolean(scan?.isAnonymous) || Boolean(scan?.createdByUserId === sessionUser.uid);

      if (shouldClaimScan) {
        const claimResponse = await fetch(`/api/scans/${scanId}/claim`, { method: "POST" });
        const claimPayload = (await claimResponse.json().catch(() => null)) as
          | { error?: string; code?: string; details?: unknown }
          | null;
        if (!claimResponse.ok) {
          if (
            claimPayload?.code === "SCAN_QUOTA_EXCEEDED" &&
            claimPayload.details &&
            typeof claimPayload.details === "object"
          ) {
            setQuota(claimPayload.details as ScanQuotaSummary);
            setPaypalOpen(true);
          }
          throw new Error(claimPayload?.error ?? "Unable to link this scan.");
        }

        dispatchQuotaRefresh();
      }

      await refreshWorkspace();
    } catch (error) {
      setActionError(error instanceof Error ? error.message : "Unable to continue with Google.");
    } finally {
      setActionPending(false);
    }
  };

  const handleDownloadPdf = async () => {
    if (!scan) {
      return;
    }

    setActionError(null);
    setDownloadPending(true);

    try {
      await downloadReportPdf(scan, state.findings);
    } catch (error) {
      setActionError(
        error instanceof Error ? error.message : "Unable to generate the PDF report.",
      );
    } finally {
      setDownloadPending(false);
    }
  };

  if (!scan && !state.error) {
    return (
      <div className="workspace-gradient min-h-screen">
        <div className="mx-auto flex min-h-screen max-w-[1440px] items-start gap-6 px-6 py-24">
          <div className="h-[700px] w-72 animate-pulse rounded-[2rem] bg-white/60" />
          <div className="flex-1 space-y-6">
            <div className="h-52 animate-pulse rounded-[2rem] bg-white/60" />
            <div className="h-20 animate-pulse rounded-[2rem] bg-white/60" />
            <div className="h-48 animate-pulse rounded-[2rem] bg-white/60" />
          </div>
        </div>
      </div>
    );
  }

  if (state.error || !scan) {
    return (
      <div className="workspace-gradient min-h-screen px-6 py-24">
        <div className="glass-panel mx-auto max-w-[820px] rounded-[2rem] p-10">
          <p className="text-xs font-bold uppercase tracking-[0.22em] text-[var(--danger)]">
            Report unavailable
          </p>
          <h1 className="mt-4 text-4xl font-semibold tracking-[-0.03em] text-slate-900">
            {state.error ?? "The report could not be loaded."}
          </h1>
          <p className="mt-4 max-w-[620px] text-sm leading-7 text-slate-500">
            This scan may have expired, storage may not be configured yet, or the current link is invalid. Start a new scan to generate a fresh live report.
          </p>
          <button
            type="button"
            onClick={() => router.push("/")}
            className="mt-8 rounded-full bg-[var(--primary)] px-6 py-3 text-sm font-semibold text-white transition-all hover:bg-[#004ca1]"
          >
            Start a new scan
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="workspace-gradient min-h-screen text-[var(--ink)]">
      <div className="mx-auto flex max-w-[1440px] pt-16">
        <aside className="soft-scrollbar sticky top-16 hidden h-[calc(100vh-64px)] w-72 shrink-0 flex-col overflow-y-auto border-r border-white/20 bg-white/40 px-6 py-8 shadow-[10px_0_40px_rgba(0,0,0,0.02)] backdrop-blur-[30px] lg:flex">
          <div className="mb-8">
            <h3 className="text-lg font-black text-blue-600">CyberAudit</h3>
            <p className="mt-1 text-xs font-medium text-slate-500">
              Live website scan workspace
            </p>
          </div>

          <div className="flex flex-1 flex-col gap-6">
            <div>
              <span className="mb-4 block px-4 text-[10px] font-bold uppercase tracking-[0.24em] text-slate-400">
                Navigation
              </span>
              <div className="space-y-2">
                <div className="flex items-center gap-3 rounded-full bg-blue-600 px-4 py-3 text-white shadow-[0_4px_12px_rgba(0,122,255,0.3)]">
                  <Shield className="h-4 w-4" />
                  <span className="text-sm font-semibold">Home</span>
                </div>
                <button
                  type="button"
                  onClick={() => router.push("/history")}
                  className="flex w-full items-center gap-3 rounded-full px-4 py-3 text-slate-600 transition-all hover:bg-white/40"
                >
                  <History className="h-4 w-4" />
                  <span className="text-sm font-medium">Scans</span>
                </button>
              </div>
            </div>

            <div className="min-h-0 flex-1">
              <span className="mb-4 block px-4 text-[10px] font-bold uppercase tracking-[0.24em] text-slate-400">
                Your Scans
              </span>
              <div className="soft-scrollbar max-h-[320px] space-y-1 overflow-y-auto pr-2">
                {state.recentScans.length ? (
                  state.recentScans.map((recent) => (
                    <button
                      key={recent.id}
                      type="button"
                      onClick={() => router.push(`/scans/${recent.id}`)}
                      className={cn(
                        "w-full rounded-[1rem] p-3 text-left transition-all hover:bg-white/60",
                        recent.id === scanId && "bg-white/70 shadow-sm",
                      )}
                    >
                      <p className="text-sm font-medium text-slate-900">{recent.targetHostname}</p>
                      <p className="mt-1 text-[11px] text-slate-500">
                        {recent.id === scanId
                          ? `Current scan • ${recent.progress}%`
                          : `Last scan ${formatRelative(recent.createdAt)}`}
                      </p>
                    </button>
                  ))
                ) : (
                  <div className="rounded-[1rem] bg-white/50 p-4 text-sm text-slate-500">
                    Recent scans will appear here.
                  </div>
                )}
              </div>
            </div>
          </div>

          <button
            type="button"
            onClick={() => router.push("/#scan-launch")}
            className="mt-8 w-full rounded-full bg-[var(--primary)] px-5 py-4 text-sm font-bold text-white shadow-lg shadow-[var(--primary)]/20 transition-all active:scale-[0.98]"
          >
            New Scan
          </button>
        </aside>

        <main className="min-w-0 flex-1 px-5 py-8 md:px-10 md:py-12">
          <div className="glass-panel rounded-[2rem] p-6 shadow-[0_8px_32px_rgba(0,0,0,0.03)] md:p-8">
            <div className="grid gap-8 lg:grid-cols-[minmax(0,1fr)_240px]">
              <div>
                <div className="mb-4 flex flex-wrap items-center gap-3">
                  <span className="rounded-full bg-blue-50 px-3 py-1 text-[11px] font-bold uppercase tracking-[0.18em] text-blue-600">
                    Live Analysis
                  </span>
                  <span className="inline-flex items-center gap-2 rounded-full bg-white/70 px-3 py-1 text-sm text-slate-500">
                    <span
                      className={cn(
                        "loader-dot inline-flex",
                        scan.status === "completed"
                          ? "text-[var(--success)]"
                          : scan.status === "failed"
                            ? "text-[var(--danger)]"
                            : "text-[var(--primary)]",
                      )}
                    />
                    {latestEvent?.message ?? scan.latestPhase}
                  </span>
                </div>
                <h1 className="text-4xl font-semibold tracking-[-0.03em] text-slate-900 md:text-5xl">
                  {scan.targetHostname}
                </h1>
                <div className="mt-6 flex items-end justify-between gap-4">
                  <div>
                    <p className="text-sm font-medium text-slate-500">Overall progress</p>
                    <p className="mt-1 text-xs uppercase tracking-[0.2em] text-slate-400">
                      {scan.status}
                    </p>
                  </div>
                  <div className="text-right">
                    <span className="text-3xl font-semibold text-[var(--primary)]">
                      {displayProgress}%
                    </span>
                    <p className="text-xs font-semibold uppercase tracking-[0.18em] text-slate-400">
                      Audited
                    </p>
                  </div>
                </div>
                <div className="mt-4 h-3 overflow-hidden rounded-full bg-slate-100 shadow-inner">
                  <div
                    className={cn(
                      "progress-stripes h-full rounded-full bg-[var(--primary)] shadow-[0_0_20px_rgba(0,88,188,0.35)] transition-all duration-700",
                      scan.status === "completed" && "after:hidden",
                    )}
                    style={{ width: `${displayProgress}%` }}
                  />
                </div>
                <p className="mt-4 text-sm text-slate-500">
                  Live site checks across Security, SEO, and Performance.
                </p>
                <div className="mt-6 grid gap-3 md:grid-cols-3">
                  {categoryCards.map((item) => (
                    <div key={item.category} className="rounded-[1.3rem] bg-white/55 px-4 py-4">
                      <div className="flex items-center justify-between gap-3">
                        <div>
                          <p className="text-xs font-bold uppercase tracking-[0.18em] text-slate-400">
                            {titleCaseCategory(item.category)}
                          </p>
                          <p className="mt-2 text-lg font-semibold text-slate-900">
                            {formatScore(item.score)}
                          </p>
                        </div>
                        <span
                          className={cn(
                            "rounded-full px-3 py-1 text-[10px] font-bold uppercase tracking-[0.16em]",
                            item.status === "completed" && "bg-emerald-50 text-emerald-700",
                            item.status === "running" && "bg-blue-50 text-blue-700",
                            item.status === "failed" && "bg-red-50 text-red-700",
                            item.status === "queued" && "bg-slate-100 text-slate-500",
                          )}
                        >
                          {item.status}
                        </span>
                      </div>
                      <p className="mt-2 text-xs text-slate-500">{item.count} checks</p>
                      <div className="mt-3 flex flex-wrap gap-2">
                        <span className="rounded-full bg-emerald-50 px-2.5 py-1 text-[11px] font-semibold text-emerald-700">
                          {item.passCount} passed
                        </span>
                        <span className="rounded-full bg-rose-50 px-2.5 py-1 text-[11px] font-semibold text-rose-700">
                          {item.failCount} failed
                        </span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              <div className="glass-panel flex flex-col items-center justify-center rounded-[2rem] bg-white/70 p-6">
                <div
                  className="score-ring-modern h-40 w-40"
                  style={
                    {
                      "--score": scan.overallScore ?? scan.progress,
                      "--ring-color": getScoreTone(scan.overallScore ?? null),
                    } as CSSProperties
                  }
                >
                  <div className="relative z-10 flex flex-col items-center">
                    <span className="text-5xl font-semibold text-slate-900">
                      {formatScore(scan.overallScore ?? null)}
                    </span>
                    <span className="mt-2 text-xs font-semibold uppercase tracking-[0.24em] text-slate-400">
                      Overall score
                    </span>
                  </div>
                </div>
                <p className="mt-5 text-sm text-slate-500">
                  Updated {formatRelative(scan.updatedAt)}
                </p>
              </div>
            </div>
          </div>

          <div className="mt-8 flex flex-col items-start justify-between gap-5 xl:flex-row xl:items-center">
            <div className="flex flex-wrap gap-2 rounded-full bg-white/50 p-1.5 shadow-sm backdrop-blur-xl">
              {categoryCards.map((item) => (
                <button
                  key={item.category}
                  type="button"
                  onClick={() => handleChangeTab(item.category)}
                  className={cn(
                    "rounded-full px-6 py-2.5 text-sm font-semibold transition-all",
                    activeTab === item.category
                      ? "bg-white text-[var(--primary)] shadow-sm"
                      : "text-slate-500 hover:text-slate-800",
                  )}
                >
                  {titleCaseCategory(item.category)}
                </button>
              ))}
            </div>
            <div className="flex flex-wrap items-center gap-3">
              <button
                type="button"
                onClick={() => setReportOpen(true)}
                className="inline-flex items-center gap-2 rounded-full border border-white/50 bg-white px-6 py-3 text-sm font-semibold text-slate-700 shadow-sm transition-all hover:shadow-md"
              >
                <FileText className="h-4 w-4 text-[var(--primary)]" />
                Full Report
              </button>
              <button
                type="button"
                onClick={() => void handleContinueWithGoogle()}
                disabled={actionPending || state.viewerCanAccessFixes || !isConfigured}
                className="inline-flex items-center gap-2 rounded-full border border-white/50 bg-white px-6 py-3 text-sm font-semibold text-slate-700 shadow-sm transition-all hover:shadow-md disabled:cursor-not-allowed disabled:opacity-60"
              >
                <Wrench className="h-4 w-4 text-[var(--primary)]" />
                {!isConfigured
                  ? "Google login unavailable"
                  : state.viewerCanAccessFixes
                    ? "Google connected"
                    : "Sign in"}
              </button>
            </div>
          </div>

          {actionError ? (
            <p className="mt-4 text-sm font-medium text-[var(--danger)]">{actionError}</p>
          ) : null}

          <div
            id="threats-panel"
            className="soft-scrollbar mt-8 space-y-6 overflow-y-auto pb-10"
          >
            {activeFindings.length ? (
              activeFindings.map((finding) => (
                <FindingCard
                  key={finding.id}
                  finding={finding}
                  onUnlock={handleContinueWithGoogle}
                  unlockDisabled={actionPending || state.viewerCanAccessFixes || !isConfigured}
                />
              ))
            ) : (
              <div className="glass-panel rounded-[2rem] bg-white/60 p-8 text-center">
                <div className="mx-auto inline-flex h-12 w-12 items-center justify-center rounded-full bg-blue-50 text-blue-600">
                  <Clock3 className="h-5 w-5" />
                </div>
                <p className="mt-4 text-lg font-semibold text-slate-900">
                  {titleCaseCategory(activeTab)} checks are still running
                </p>
                <p className="mt-2 text-sm leading-7 text-slate-500">
                  The worker is still collecting checks. Stay on this page and the results will stream in automatically.
                </p>
              </div>
            )}
          </div>
        </main>
      </div>

      <PaypalCreditsDialog
        open={paypalOpen}
        quota={quota}
        onClose={() => setPaypalOpen(false)}
        onApproved={async (nextQuota) => {
          setQuota(nextQuota);
          setPaypalOpen(false);
          dispatchQuotaRefresh();
          await handleContinueWithGoogle();
        }}
      />

      {reportOpen && scan ? (
        <div className="fixed inset-0 z-[70] flex items-center justify-center bg-slate-950/45 px-4 py-8 backdrop-blur-[6px]">
          <div className="relative flex h-[min(860px,92vh)] w-full max-w-[1140px] flex-col overflow-hidden rounded-[2.2rem] border border-white/60 bg-[linear-gradient(180deg,rgba(255,255,255,0.98),rgba(248,250,252,0.96))] shadow-[0_30px_120px_rgba(15,23,42,0.24)]">
            <div className="flex items-start justify-between gap-4 border-b border-slate-200/80 bg-white/75 px-6 py-5 backdrop-blur-xl">
              <div>
                <p className="text-xs font-bold uppercase tracking-[0.22em] text-[var(--primary)]">
                  Full Report
                </p>
                <h2 className="mt-2 text-3xl font-semibold tracking-[-0.03em] text-slate-900">
                  {scan.targetHostname}
                </h2>
                <div className="mt-3 flex flex-wrap items-center gap-2">
                  {criticalIssueCount > 0 ? (
                    <span className="rounded-full border border-red-200 bg-red-50 px-3 py-1 text-[10px] font-bold uppercase tracking-[0.14em] text-red-700">
                      {criticalIssueCount} Critical Issues Found
                    </span>
                  ) : null}
                  {failingIssueCount > 0 && criticalIssueCount === 0 ? (
                    <span className="rounded-full border border-rose-200 bg-rose-50 px-3 py-1 text-[10px] font-bold uppercase tracking-[0.14em] text-rose-700">
                      {failingIssueCount} Failing Checks
                    </span>
                  ) : null}
                  {warningIssueCount > 0 ? (
                    <span className="rounded-full border border-amber-200 bg-amber-50 px-3 py-1 text-[10px] font-bold uppercase tracking-[0.14em] text-amber-700">
                      {warningIssueCount} Warnings
                    </span>
                  ) : null}
                </div>
                <p className="mt-2 text-sm text-slate-500">
                  Updated {formatRelative(scan.updatedAt)} • {scan.status}
                </p>
              </div>
              <div className="flex items-center gap-3">
                <button
                  type="button"
                  onClick={handleDownloadPdf}
                  disabled={downloadPending}
                  className="inline-flex items-center gap-2 rounded-full border border-slate-200 bg-white px-5 py-2.5 text-sm font-semibold text-slate-800 shadow-sm transition-colors hover:bg-slate-50 disabled:cursor-not-allowed disabled:opacity-60"
                >
                  <Download className="h-4 w-4 text-[var(--primary)]" />
                  {downloadPending ? "Preparing PDF..." : "Download PDF"}
                </button>
                <button
                  type="button"
                  onClick={() => setReportOpen(false)}
                  className="inline-flex h-11 w-11 items-center justify-center rounded-full border border-slate-200 bg-white text-slate-600 transition-colors hover:bg-slate-50"
                >
                  <X className="h-5 w-5" />
                </button>
              </div>
            </div>

            <div className="overflow-y-auto px-6 py-6">
              <div className="rounded-[2rem] border border-white/70 bg-[linear-gradient(180deg,rgba(255,255,255,0.95),rgba(244,247,255,0.88))] p-5 shadow-[0_12px_48px_rgba(15,23,42,0.06)]">
                <div className="grid gap-4 md:grid-cols-4">
                  {[
                    {
                      label: "Overall Score",
                      value: scan.overallScore,
                      countLabel:
                        criticalIssueCount > 0
                          ? `${criticalIssueCount} critical issues`
                          : `${failingIssueCount} failing checks`,
                    },
                    {
                      label: "Security",
                      value: scan.securityScore,
                      countLabel: `${state.findings.security.length} checks`,
                    },
                    {
                      label: "SEO",
                      value: scan.seoScore,
                      countLabel: `${state.findings.seo.length} checks`,
                    },
                    {
                      label: "Performance",
                      value: scan.performanceScore,
                      countLabel: `${state.findings.performance.length} checks`,
                    },
                  ].map((metric) => (
                    <div
                      key={`report-metric-${metric.label}`}
                      className="rounded-[1.5rem] border border-white/80 bg-white/80 p-4 shadow-[0_10px_28px_rgba(148,163,184,0.08)]"
                    >
                      <p className="text-[11px] font-bold uppercase tracking-[0.18em] text-slate-400">
                        {metric.label}
                      </p>
                      <div className="mt-3 flex items-end gap-2">
                        <p
                          className="text-4xl font-semibold tracking-[-0.03em]"
                          style={{ color: getScoreTone(metric.value) }}
                        >
                          {formatScore(metric.value)}
                        </p>
                        <span className="pb-1 text-xs font-semibold text-slate-400">/100</span>
                      </div>
                      <div className="mt-4 h-1.5 overflow-hidden rounded-full bg-slate-200">
                        <div
                          className="h-full rounded-full"
                          style={{
                            width: `${Math.max(0, Math.min(100, metric.value ?? 0))}%`,
                            backgroundColor: getScoreTone(metric.value),
                          }}
                        />
                      </div>
                      <p className="mt-3 text-xs font-medium text-slate-500">{metric.countLabel}</p>
                    </div>
                  ))}
                </div>
              </div>

              <div className="mt-8 space-y-8">
                {categoryKeys.map((category) => (
                  <section key={`report-${category}`}>
                    <div className="flex items-center justify-between gap-3 border-b border-slate-200/80 pb-3">
                      <div>
                        <h3 className="text-2xl font-semibold tracking-[-0.02em] text-slate-900">
                          {titleCaseCategory(category)}
                        </h3>
                        <p className="mt-1 text-sm text-slate-500">
                          {state.findings[category].length} checks in this category
                        </p>
                      </div>
                    </div>

                    <div className="mt-4 space-y-4">
                      {state.findings[category].map((finding) => (
                        <article
                          key={`report-card-${finding.id}`}
                          className={cn(
                            "relative overflow-hidden rounded-[1.7rem] border p-5 shadow-[0_16px_44px_rgba(15,23,42,0.05)]",
                            findingSurfaceClasses(finding),
                          )}
                        >
                          {(deriveFindingStatus(finding) === "warning" ||
                            deriveFindingStatus(finding) === "fail") && (
                            <div
                              className="absolute inset-y-5 left-0 w-1 rounded-r-full"
                              style={{ backgroundColor: findingAccentTone(finding) }}
                            />
                          )}
                          <div className="flex flex-wrap items-start justify-between gap-3">
                            <div>
                              <h4 className="text-lg font-semibold text-slate-900">{finding.title}</h4>
                              <p className="mt-2 max-w-[760px] text-sm leading-7 text-slate-500">
                                {finding.shortDescription}
                              </p>
                            </div>
                            <div className="flex flex-wrap gap-2">
                              <span
                                className={cn(
                                  "rounded-full px-3 py-1 text-[10px] font-bold uppercase tracking-[0.14em]",
                                  getStatusStyles(deriveFindingStatus(finding)),
                                )}
                              >
                                {deriveFindingStatus(finding)}
                              </span>
                              {(deriveFindingStatus(finding) === "warning" ||
                                deriveFindingStatus(finding) === "fail") && (
                                <span
                                  className={cn(
                                    "rounded-full px-3 py-1 text-[10px] font-bold uppercase tracking-[0.14em]",
                                    getSeverityStyles(finding.severity),
                                  )}
                                >
                                  {finding.severity} severity
                                </span>
                              )}
                            </div>
                          </div>

                          {finding.locked ? (
                            <div className="mt-4 rounded-[1.3rem] border border-dashed border-slate-300 bg-white/80 p-4 text-sm text-slate-500">
                              Sign in with Google to unlock the full remediation details for this check.
                            </div>
                          ) : (
                            <div className="mt-4 grid gap-3 lg:grid-cols-2">
                              <div className={cn("rounded-[1.3rem] p-4", detailPanelClasses(finding))}>
                                <p
                                  className="text-[11px] font-bold uppercase tracking-[0.18em]"
                                  style={{ color: findingAccentTone(finding) }}
                                >
                                  Why It Matters
                                </p>
                                <p className="mt-2 text-sm leading-7 text-slate-600">
                                  {finding.whyItMatters}
                                </p>
                              </div>
                              <div className="rounded-[1.3rem] border border-white/70 bg-[linear-gradient(180deg,rgba(255,255,255,0.82),rgba(239,246,255,0.9))] p-4 shadow-[0_10px_28px_rgba(59,130,246,0.07)]">
                                <p className="text-[11px] font-bold uppercase tracking-[0.18em] text-[var(--primary)]">
                                  Recommendation
                                </p>
                                <p className="mt-2 text-sm leading-7 text-slate-600">
                                  {finding.recommendation}
                                </p>
                              </div>
                            </div>
                          )}
                        </article>
                      ))}
                    </div>
                  </section>
                ))}
              </div>
            </div>
          </div>
        </div>
      ) : null}
    </div>
  );
}
