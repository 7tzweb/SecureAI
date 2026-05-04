import { loadAttempt } from "@/server/scans/helpers";
import {
  buildSqlResponseSignature,
  classifyParameter,
  highDynamicResponseSignal,
  responseDiffDimensions,
  type ParameterContext,
} from "@/security/probes/sqlEvidence";

export type ResponseSignature = {
  status: number;
  contentType: string;
  length: number;
  normalizedHash: string;
  stableTextHash: string;
  lengthBucket: string;
  stableTextLength: number;
  jsonShape?: string[];
  recordCount?: number | null;
  importantTokens: string[];
  isCaptchaOrBotPage?: boolean;
  isLoginPage?: boolean;
  isSearchPage?: boolean;
  isRedirectValidationPage?: boolean;
  responseClass: string;
  durationMs: number;
};

export type BlindSqlProbeResult = {
  url: string;
  method: string;
  parameter: string;
  parameterContext?: ParameterContext;
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
  evidenceStrength?: "weak" | "moderate" | "strong" | "exploit-proof";
  falsePositiveRisk?: "low" | "medium" | "high";
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
  const sqlSignature = buildSqlResponseSignature({
    status: attempt.status,
    contentType: attempt.headers["content-type"] ?? "",
    bodyText: attempt.bodyText,
    url,
  });
  return {
    status: attempt.status,
    contentType: sqlSignature.contentType,
    length: sqlSignature.stableTextLength,
    normalizedHash: sqlSignature.normalizedHash,
    stableTextHash: sqlSignature.stableTextHash,
    lengthBucket: sqlSignature.lengthBucket,
    stableTextLength: sqlSignature.stableTextLength,
    jsonShape: parsed ? jsonShape(parsed).slice(0, 40) : undefined,
    recordCount: sqlSignature.recordCount ?? recordCount(attempt.bodyText),
    importantTokens: sqlSignature.importantTokens,
    isCaptchaOrBotPage: sqlSignature.isCaptchaOrBotPage,
    isLoginPage: sqlSignature.isLoginPage,
    isSearchPage: sqlSignature.isSearchPage,
    isRedirectValidationPage: sqlSignature.isRedirectValidationPage,
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
  const dimensions = responseDiffDimensions(leftFirst, rightFirst).filter((dimension) => {
    const noisyHtml =
      leftFirst.isCaptchaOrBotPage ||
      rightFirst.isCaptchaOrBotPage ||
      leftFirst.isLoginPage ||
      rightFirst.isLoginPage ||
      leftFirst.isRedirectValidationPage ||
      rightFirst.isRedirectValidationPage;
    return !noisyHtml || (dimension !== "stable-text" && dimension !== "length-bucket");
  });
  return dimensions.length;
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
    const parameterContext = classifyParameter(config.parameter, config.url);
    const lowSqlContext = parameterContext === "redirect" || parameterContext === "auth-flow" || parameterContext === "tracking";
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
    const highDynamic = [...baselineRows, ...trueRows, ...falseRows, ...controlRows].some((row) =>
      highDynamicResponseSignal({
        url: config.url,
        bodyText: row.importantTokens?.join(" ") ?? "",
        signature: {
          status: row.status,
          contentType: row.contentType,
          normalizedHash: row.normalizedHash,
          stableTextHash: row.stableTextHash,
          lengthBucket: row.lengthBucket,
          importantTokens: row.importantTokens ?? [],
          recordCount: row.recordCount,
          jsonShape: row.jsonShape,
          isCaptchaOrBotPage: row.isCaptchaOrBotPage,
          isLoginPage: row.isLoginPage,
          isSearchPage: row.isSearchPage,
          isRedirectValidationPage: row.isRedirectValidationPage,
          stableTextLength: row.length,
        },
      }).highDynamic,
    );
    const confirmed =
      !lowSqlContext &&
      trueRows.length >= 2 &&
      falseRows.length >= 2 &&
      trueFalseDimensions >= 2 &&
      baselineControlDimensions <= 1;
    const likely = !lowSqlContext && !highDynamic && trueFalseDimensions >= 2;
    const contextNote = lowSqlContext
      ? " Parameter appears to control redirect/auth/tracking flow; response differences are treated as validation behavior, not SQL injection proof."
      : highDynamic
        ? " The response surface is highly dynamic, so weak content differences were suppressed."
        : "";

    results.push({
      url: config.url,
      method: "GET",
      parameter: config.parameter,
      parameterContext,
      technique: trueFalseDimensions >= 2 ? "boolean" : trueFalseDimensions === 1 ? "content-diff" : "boolean",
      baseline: baselineRows,
      trueCondition: trueRows,
      falseCondition: falseRows,
      control: controlRows,
      confidence: confirmed ? "CONFIRMED" : likely ? "LIKELY" : "INFO",
      evidenceSummary: confirmed
        ? `Boolean true/false payloads were stable across repeated probes in ${trueFalseDimensions} dimensions.`
        : likely
          ? "Boolean payloads showed a multi-dimension difference, but repeated proof was not strong enough to confirm exploitability."
          : `No stable boolean blind SQL behavior was observed.${contextNote}`,
      evidenceStrength: confirmed ? "strong" : likely ? "moderate" : "weak",
      falsePositiveRisk: lowSqlContext || highDynamic ? "high" : trueFalseDimensions > 0 ? "medium" : "low",
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
      parameterContext,
      technique: "time",
      baseline: baselineRows,
      control: controlRows,
      trueCondition: delayRows,
      baselineMedianMs,
      testMedianMs,
      controlMedianMs,
      confidence: lowSqlContext ? "INFO" : timeConfirmed ? "CONFIRMED" : testMedianMs >= baselineMedianMs + threshold ? "LIKELY" : "INFO",
      evidenceSummary: timeConfirmed
        ? "Time-based delay was stable across repeated baseline/control/test probes."
        : lowSqlContext
          ? "No time-based blind SQL delay was confirmed. Parameter context is redirect/auth/tracking, so validation behavior is not treated as SQLi."
          : "No stable time-based blind SQL delay was confirmed.",
      evidenceStrength: timeConfirmed ? "strong" : "weak",
      falsePositiveRisk: lowSqlContext ? "high" : "medium",
    });
  }

  return results;
}
