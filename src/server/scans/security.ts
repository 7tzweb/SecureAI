import { load as loadHtml } from "cheerio";
import { type FindingStatus, type Severity } from "@/lib/types";
import { applyPremiumGating, computeScore } from "@/lib/utils";
import {
  type PageFormSnapshot,
  type PageResource,
  getPrimaryOrigin,
  getConfiguredAuthCookieHeader,
  loadAuditArtifacts,
} from "@/server/scans/artifacts";
import {
  createFinding,
  createResponseLocation,
  describeDomLocation,
  isHtmlLikeResponse,
  isLikelyEdgeInterstitial,
  loadAttempt,
} from "@/server/scans/helpers";
import { type CategoryScanResult, type HttpAttempt, type NormalizedTarget } from "@/server/scans/types";

function buildSecurityCheck(input: {
  checkKey: string;
  title: string;
  status: FindingStatus;
  severity: Severity;
  scoreWeight?: number;
  shortDescription: string;
  whyItMatters: string;
  recommendation: string;
  evidence?: Record<string, unknown>;
  premiumOnly?: boolean;
}) {
  return createFinding({
    ...input,
    category: "security",
  });
}

function cookieName(cookie: string) {
  return cookie.split("=")[0]?.trim() || "Unnamed cookie";
}

function parseCookieFlags(cookie: string) {
  const attributes = cookie
    .split(";")
    .slice(1)
    .map((part) => part.trim().toLowerCase())
    .filter(Boolean);

  return {
    secure: attributes.includes("secure"),
    httpOnly: attributes.includes("httponly"),
    sameSite: attributes.some((attribute) => attribute === "samesite" || attribute.startsWith("samesite=")),
  };
}

function isCsrfCookie(name: string) {
  return /(csrf|xsrf)/i.test(name);
}

function isSensitiveCookie(name: string) {
  const lower = name.toLowerCase();

  return (
    /^(?:phpsessid|jsessionid|sessionid|connect\.sid)$/i.test(name) ||
    /(?:^|[_.-])(?:session|sess|sid)(?:$|[_.-])/i.test(lower) ||
    /(?:auth(?:entication)?|access|refresh|id)[_.-]?token|jwt/i.test(lower)
  );
}

function isInfrastructureCookie(name: string) {
  return /^(?:__cf|cf_|_cfuvid|ak_bmsc|bm_sz|bm_sv|datadome|didomi_token|incap_ses|visid_incap|nlbi_|aka_)/i.test(
    name,
  );
}

function headerEvidence(url: string, headerName: string, summary: string) {
  return {
    checkedUrl: url,
    expectedLocation: `response.headers["${headerName}"]`,
    summary,
    locations: [
      createResponseLocation({
        label: "Primary document response",
        url,
        path: `response.headers["${headerName}"]`,
      }),
    ],
  };
}

function exposedResourceLocations(resources: PageResource[], note: string) {
  return resources.slice(0, 8).map((resource, index) => ({
    ...resource.location,
    label: `${resource.kind} ${index + 1}`,
    note,
  }));
}

function parseMaxAge(value: string) {
  const match = value.match(/max-age=(\d+)/i);
  return match ? Number(match[1]) : null;
}

function directoryListingDetected(bodyText: string) {
  return /<title>\s*Index of\s|Directory listing for|Index of \//i.test(bodyText);
}

function isSuccessfulNonChallengeResponse(attempt: HttpAttempt) {
  return attempt.status >= 200 && attempt.status < 300 && !isLikelyEdgeInterstitial(attempt);
}

function looksLikeEnvFile(attempt: HttpAttempt) {
  if (!isSuccessfulNonChallengeResponse(attempt) || isHtmlLikeResponse(attempt.headers, attempt.bodyText)) {
    return false;
  }

  const envLines = attempt.bodyText
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line && !line.startsWith("#"))
    .filter((line) => /^[A-Za-z_][A-Za-z0-9_]{1,80}\s*=\s*.+$/.test(line));

  return (
    envLines.length >= 2 ||
    envLines.some((line) => /(SECRET|TOKEN|KEY|DATABASE|PASSWORD|PRIVATE|REDIS|AWS|FIREBASE|STRIPE|PAYPAL|OPENAI)/i.test(line))
  );
}

function looksLikeExposedBackupArtifact(attempt: HttpAttempt, path: string) {
  if (!isSuccessfulNonChallengeResponse(attempt) || isHtmlLikeResponse(attempt.headers, attempt.bodyText)) {
    return false;
  }

  const contentType = attempt.headers["content-type"] ?? "";
  if (/\.zip$/i.test(path)) {
    return /zip|octet-stream/i.test(contentType) || attempt.bodyText.startsWith("PK");
  }

  if (/\.env/i.test(path)) {
    return looksLikeEnvFile(attempt);
  }

  return /<\?php|DB_|DATABASE|PASSWORD|SECRET|TOKEN|config/i.test(attempt.bodyText);
}

function looksLikeStructuredApiPayload(attempt: Pick<HttpAttempt, "headers" | "bodyText">) {
  const contentType = attempt.headers["content-type"] ?? "";
  const trimmedBody = attempt.bodyText.trim();
  return (
    /application\/(?:json|graphql-response\+json)|text\/plain|application\/xml|text\/xml/i.test(
      contentType,
    ) ||
    /^[{\[]/.test(trimmedBody)
  );
}

function looksLikeSensitiveApiPayload(bodyText: string) {
  return /"(?:email|token|accessToken|session|userId|invoice|account|customerId)"\s*:/i.test(bodyText);
}

function looksLikeAuthSuccessResponse(attempt: HttpAttempt) {
  const tokenLikeResponse =
    attempt.status >= 200 &&
    attempt.status < 300 &&
    (/"(?:authentication|token|accessToken|refreshToken|id_token|jwt)"\s*:\s*"[^"]{12,}"/i.test(attempt.bodyText) ||
      /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9._-]{10,}\.[A-Za-z0-9._-]{10,}\b/.test(attempt.bodyText));
  const sessionCookie = attempt.setCookies.some((cookie) => isSensitiveCookie(cookieName(cookie)));

  return {
    authSuccess: tokenLikeResponse || (attempt.status < 400 && sessionCookie),
    tokenLikeResponse,
    sessionCookie,
  };
}

type ProbeMatch = {
  url: string;
  status: number;
  finalUrl: string;
  locationHeader: string;
  headers: Record<string, string>;
  bodyText: string;
};

type ReflectionResult = {
  url: string;
  parameter: string;
  context: "text" | "html" | "attribute" | "url-attribute" | "script";
  reflectedValue: string;
};

type ActiveXssProbeResult = {
  url: string;
  parameter: string;
  status: number;
  rawPayloadReflected: boolean;
  context: ReflectionResult["context"] | null;
};

type BrowserXssExecutionResult = {
  url: string;
  parameter: string;
  status: number | null;
  executed: boolean;
  payload: string;
};

type ActiveSqlProbeResult = {
  url: string;
  parameter: string;
  payload: string;
  status: number;
  baselineStatus: number | null;
  baselineDurationMs: number | null;
  probeDurationMs: number | null;
  sqlError: boolean;
  serverError: boolean;
  baselineRecordCount: number | null;
  probeRecordCount: number | null;
  recordExpansion: boolean;
  timeDelay: boolean;
};

type IdorProbeResult = {
  originalUrl: string;
  mutatedUrl: string;
  status: number;
  originalStatus: number | null;
  secondaryStatus: number | null;
  contentType: string | null;
  comparableResponse: boolean;
  crossUserAccess: boolean;
};

type AuthBypassProbeResult = {
  url: string;
  payload: string;
  status: number;
  authSuccess: boolean;
  tokenLikeResponse: boolean;
  sessionCookie: boolean;
};

const csrfTokenNamePattern = /(csrf|xsrf|authenticity|requestverification|form[_-]?token|nonce)/i;
const sensitivePathPattern =
  /(login|signin|auth|register|signup|password|reset|forgot|admin|dashboard|account|profile|settings|billing|payment|invoice|export|download|upload|graphql|api|debug|status|metrics)/i;
const apiPathPattern = /(?:^|\/)(?:api(?:\/v\d+)?|graphql|rest(?:\/v\d+)?|rpc|ajax)(?:\/|$)/i;
const openRedirectParamPattern = /^(redirect|next|return|returnurl|continue|url|target|dest)$/i;
const riskyInputParamPattern = /^(q|query|search|keyword|term|id|sort|filter|category|redirect|next|returnurl|continue|url)$/i;
const sqlErrorPatterns = [
  /you have an error in your sql syntax/i,
  /warning:\s*(?:mysql|mysqli|pg_|sqlite_|odbc|pdo)/i,
  /\b(?:mysql|postgres(?:ql)?|sqlite|sqlserver|oracle)\b.{0,40}\b(?:syntax|error|exception|warning|query|driver|odbc|state)\b/i,
  /sqlstate/i,
  /odbc/i,
  /pdoexception/i,
  /sequelize[^<\n]{0,80}(?:error|exception)/i,
  /prisma[^<\n]{0,80}(?:error|exception)/i,
  /database error/i,
  /query failed/i,
  /syntax error at or near/i,
  /unterminated quoted string/i,
  /no such table/i,
  /unknown column/i,
];
const strongVerboseErrorPatterns = [
  /stack trace/i,
  /traceback \(most recent call last\)/i,
  /uncaught exception/i,
  /unhandled (?:exception|rejection)/i,
  /pdoexception/i,
  /sqlstate/i,
];
const sourcePathPattern = /node_modules\/|\/(?:src|app|usr|var|home)\/[^\s<]{4,}\.(?:ts|js|php|py|rb|go|java)/i;
const stackFramePattern = /\bat\s+[A-Za-z0-9_$<>.]+\s+\((?:https?:\/\/|\/)[^)]+\)/i;
const errorLabelPattern = /\b(?:error|exception|traceback)\b/i;
const staticAssetPathPattern =
  /\.(?:jpg|jpeg|png|gif|webp|avif|svg|ico|css|js|mjs|map|json|txt|xml|woff2?|ttf|eot|mp4|webm|mp3|wav|pdf)$/i;
const thirdPartyAuthMethodPattern = /(?:signin|oauth|login|identifier|session)/i;

const dangerousDomSinkPatterns: Array<[RegExp, string]> = [
  [/\.innerhtml\s*=/i, "innerHTML assignment"],
  [/\.outerhtml\s*=/i, "outerHTML assignment"],
  [/insertadjacenthtml\s*\(/i, "insertAdjacentHTML"],
  [/document\.write\s*\(/i, "document.write"],
  [/\beval\s*\(/i, "eval"],
  [/new\s+Function\s*\(/i, "new Function"],
  [/dangerouslysetinnerhtml/i, "dangerouslySetInnerHTML"],
];

type SensitiveEndpointCandidate = {
  url: string;
  source:
    | "internal-link"
    | "form"
    | "discovered-api"
    | "synthetic-operational";
};

type SensitiveEndpointAttempt = ProbeMatch & {
  sources: SensitiveEndpointCandidate["source"][];
};

const operationalSensitivePaths = [
  "/api",
  "/graphql",
  "/debug",
  "/status",
  "/metrics",
  "/export",
  "/upload",
];


async function mapLimited<T, R>(
  items: T[],
  concurrency: number,
  worker: (item: T, index: number) => Promise<R>,
) {
  const results = new Array<R>(items.length);
  let index = 0;

  await Promise.all(
    Array.from({ length: Math.min(items.length, concurrency) }, async () => {
      while (true) {
        const current = index;
        index += 1;
        if (current >= items.length) {
          break;
        }

        results[current] = await worker(items[current], current);
      }
    }),
  );

  return results;
}

function uniqueUrls(urls: string[]) {
  return [...new Set(urls.filter(Boolean))];
}

function isPresent<T>(value: T | null | undefined): value is T {
  return value != null;
}

function resolveHttpUrl(rawValue: string | null | undefined, baseUrl: string) {
  if (!rawValue) {
    return null;
  }

  const trimmedValue = rawValue.trim();
  if (
    (trimmedValue.startsWith("#") && !/^#(?:!\/?|\/)/.test(trimmedValue)) ||
    trimmedValue.startsWith("javascript:") ||
    trimmedValue.startsWith("mailto:") ||
    trimmedValue.startsWith("tel:") ||
    trimmedValue.startsWith("data:")
  ) {
    return null;
  }

  try {
    const resolved = new URL(trimmedValue, baseUrl);
    if (!["http:", "https:"].includes(resolved.protocol)) {
      return null;
    }

    return resolved.toString();
  } catch {
    return null;
  }
}

function isInternalHostMatch(hostname: string, targetHostname: string) {
  const normalizedHost = hostname.toLowerCase();
  const normalizedTarget = targetHostname.toLowerCase();

  return (
    normalizedHost === normalizedTarget ||
    normalizedHost.endsWith(`.${normalizedTarget}`) ||
    normalizedTarget.endsWith(`.${normalizedHost}`)
  );
}

function extractDirectiveValue(headerValue: string | null | undefined, directiveName: string) {
  if (!headerValue) {
    return "";
  }

  return (
    headerValue
      .split(";")
      .map((directive) => directive.trim())
      .find((directive) => directive.toLowerCase().startsWith(`${directiveName.toLowerCase()} `)) ?? ""
  );
}

function isStrongFrameAncestorsPolicy(frameAncestorsDirective: string) {
  if (!frameAncestorsDirective) {
    return false;
  }

  const normalized = frameAncestorsDirective.toLowerCase();
  return (
    normalized.includes("frame-ancestors 'none'") ||
    normalized.includes("frame-ancestors 'self'") ||
    /frame-ancestors\s+https:/.test(normalized)
  );
}

function redactValue(value: string, visible = 4) {
  const compact = value.trim();
  if (compact.length <= visible * 2) {
    return `${compact.slice(0, visible)}...`;
  }

  return `${compact.slice(0, visible)}...${compact.slice(-visible)}`;
}

function collectCookieHints(setCookies: string[]) {
  const cookies = setCookies.map((cookie) => ({
    name: cookieName(cookie),
    raw: cookie,
    infrastructure: isInfrastructureCookie(cookieName(cookie)),
    sensitive:
      isSensitiveCookie(cookieName(cookie)) &&
      !isInfrastructureCookie(cookieName(cookie)),
    ...parseCookieFlags(cookie),
  }));

  return {
    cookies,
    sensitiveCookies: cookies.filter((cookie) => cookie.sensitive),
    sensitiveMissingSecure: cookies.filter((cookie) => cookie.sensitive && !cookie.secure),
    sensitiveMissingHttpOnly: cookies.filter((cookie) => cookie.sensitive && !cookie.httpOnly),
    sensitiveMissingSameSite: cookies.filter((cookie) => cookie.sensitive && !cookie.sameSite),
  };
}

function isReachableSensitiveEndpoint(attempt: ProbeMatch) {
  if (isLikelyEdgeInterstitial(attempt)) {
    return false;
  }

  return (attempt.status >= 200 && attempt.status < 300) || [401, 403, 405].includes(attempt.status);
}

function resolvedLocationHeader(attempt: ProbeMatch) {
  return resolveHttpUrl(attempt.locationHeader, attempt.url);
}

function isProtectedSensitiveRedirect(attempt: ProbeMatch) {
  if (attempt.status < 300 || attempt.status >= 400) {
    return false;
  }

  const location = resolvedLocationHeader(attempt);
  if (!location) {
    return false;
  }

  return /(login|signin|auth|account|accounts|session|identifier|password|reset|forgot|dashboard|admin|export)/i.test(
    new URL(location).pathname,
  );
}

function classifyReflectionContext(bodyText: string, value: string) {
  const index = bodyText.indexOf(value);
  if (index < 0) {
    return null;
  }

  const before = bodyText.slice(Math.max(0, index - 240), index);
  const lowerBefore = before.toLowerCase();

  if (lowerBefore.lastIndexOf("<script") > lowerBefore.lastIndexOf("</script")) {
    return "script" as const;
  }

  if (/(href|src|action|formaction)\s*=\s*["'][^"']*$/i.test(before)) {
    return "url-attribute" as const;
  }

  if (/=\s*["'][^"']*$/i.test(before)) {
    return "attribute" as const;
  }

  if (lowerBefore.lastIndexOf("<") > lowerBefore.lastIndexOf(">")) {
    return "html" as const;
  }

  return "text" as const;
}

function detectDangerousDomSinks(text: string) {
  return dangerousDomSinkPatterns
    .filter(([pattern]) => pattern.test(text))
    .map(([, label]) => label);
}

function looksLikeSqlError(bodyText: string) {
  return sqlErrorPatterns.some((pattern) => pattern.test(bodyText));
}

function looksLikeVerboseError(bodyText: string) {
  if (strongVerboseErrorPatterns.some((pattern) => pattern.test(bodyText))) {
    return true;
  }

  return errorLabelPattern.test(bodyText) && (sourcePathPattern.test(bodyText) || stackFramePattern.test(bodyText));
}

function countStructuredRecords(bodyText: string): number | null {
  const trimmed = bodyText.trim();
  if (!trimmed || !/^[{[]/.test(trimmed)) {
    return null;
  }

  try {
    const parsed = JSON.parse(trimmed) as unknown;
    if (Array.isArray(parsed)) {
      return parsed.length;
    }
    if (!parsed || typeof parsed !== "object") {
      return null;
    }

    const record = parsed as Record<string, unknown>;
    const candidateKeys = ["data", "items", "results", "products", "orders", "users", "rows"];
    for (const key of candidateKeys) {
      const value = record[key];
      if (Array.isArray(value)) {
        return value.length;
      }
      if (value && typeof value === "object") {
        const nested = value as Record<string, unknown>;
        for (const nestedValue of Object.values(nested)) {
          if (Array.isArray(nestedValue)) {
            return nestedValue.length;
          }
        }
      }
    }
  } catch {
    return null;
  }

  return null;
}

function mutationWithNextIdentifier(url: string) {
  const parsed = new URL(url);
  let changed = false;

  for (const [key, value] of parsed.searchParams.entries()) {
    if (!/(^id$|Id$|_id$|user|account|invoice|order|download|file|document|report)/i.test(key)) {
      continue;
    }
    if (/^\d+$/.test(value)) {
      parsed.searchParams.set(key, String(Number(value) + 1));
      changed = true;
      break;
    }
    if (/^[0-9a-f]{8,}$/i.test(value)) {
      parsed.searchParams.set(key, `${value.slice(0, -1)}${value.endsWith("0") ? "1" : "0"}`);
      changed = true;
      break;
    }
  }

  if (!changed) {
    const pathSegments = parsed.pathname.split("/");
    for (let index = pathSegments.length - 1; index >= 0; index -= 1) {
      const segment = pathSegments[index];
      if (/^\d+$/.test(segment)) {
        pathSegments[index] = String(Number(segment) + 1);
        changed = true;
        break;
      }
      if (/^[0-9a-f]{8,}$/i.test(segment)) {
        pathSegments[index] = `${segment.slice(0, -1)}${segment.endsWith("0") ? "1" : "0"}`;
        changed = true;
        break;
      }
    }
    parsed.pathname = pathSegments.join("/");
  }

  return changed ? parsed.toString() : null;
}

function resolveSourceMapUrl(scriptUrl: string, scriptBody: string) {
  const match = scriptBody.match(/sourceMappingURL=([^\s"'<>]+)/i);
  const candidate = match?.[1] || (/\.(?:js|mjs)(?:[?#]|$)/i.test(scriptUrl) ? `${scriptUrl.split("#")[0].split("?")[0]}.map` : "");
  return resolveHttpUrl(candidate, scriptUrl);
}

async function runBrowserXssExecutionProbes(
  configs: Array<{ url: string; parameter: string }>,
  authCookieHeader: string,
) {
  if (configs.length === 0 || process.env.FIXNX_BROWSER_SCAN === "0") {
    return [];
  }

  let browser: Awaited<ReturnType<(typeof import("playwright"))["chromium"]["launch"]>> | null = null;
  const token = `fixnx_xss_${Date.now().toString(36)}`;
  const payload = `"><svg onload="window.__fixnxXss='${token}'"></svg>`;
  const results: BrowserXssExecutionResult[] = [];

  try {
    const { chromium } = await import("playwright");
    browser = await chromium.launch({
      headless: true,
      args: ["--disable-dev-shm-usage", "--no-sandbox"],
    });
    const context = await browser.newContext({
      ignoreHTTPSErrors: true,
      javaScriptEnabled: true,
      userAgent: "fixnx/1.0 xss-probe (+https://example.invalid/cyberaudit)",
      extraHTTPHeaders: authCookieHeader ? { cookie: authCookieHeader } : undefined,
    });
    const page = await context.newPage();
    await page.addInitScript(() => {
      Object.defineProperty(window as Window & { __fixnxXss?: string | null }, "__fixnxXss", {
        configurable: true,
        writable: true,
        value: null,
      });
    });

    for (const config of configs.slice(0, 4)) {
      const url = new URL(config.url);
      url.searchParams.set(config.parameter, payload);
      const response = await page.goto(url.toString(), {
        waitUntil: "domcontentloaded",
        timeout: 7_000,
      }).catch(() => null);
      await page.waitForTimeout(600).catch(() => undefined);
      const executed = await page
        .evaluate(
          (expectedToken) =>
            (window as Window & { __fixnxXss?: string | null }).__fixnxXss === expectedToken,
          token,
        )
        .catch(() => false);
      results.push({
        url: url.toString(),
        parameter: config.parameter,
        status: response?.status() ?? null,
        executed,
        payload,
      });
    }

    await context.close().catch(() => undefined);
  } catch {
    return results;
  } finally {
    await browser?.close().catch(() => undefined);
  }

  return results;
}

function extractComparableHtmlTitle(bodyText: string) {
  const match = bodyText.match(/<title[^>]*>([^<]*)<\/title>/i);
  return match?.[1]?.replace(/\s+/g, " ").trim().toLowerCase() ?? "";
}

function compactHtmlSignature(bodyText: string) {
  return bodyText
    .replace(/<script[\s\S]*?<\/script>/gi, " ")
    .replace(/<style[\s\S]*?<\/style>/gi, " ")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, 1400)
    .toLowerCase();
}

function looksLikePrimaryHtmlShell(primaryAttempt: HttpAttempt, attempt: ProbeMatch) {
  if (!isHtmlLikeResponse(attempt.headers, attempt.bodyText) || attempt.status < 200 || attempt.status >= 300) {
    return false;
  }

  const primaryTitle = extractComparableHtmlTitle(primaryAttempt.bodyText);
  const attemptTitle = extractComparableHtmlTitle(attempt.bodyText);
  if (!primaryTitle || !attemptTitle || primaryTitle !== attemptTitle) {
    return false;
  }

  return compactHtmlSignature(primaryAttempt.bodyText) === compactHtmlSignature(attempt.bodyText);
}

function isStaticAssetUrl(url: string) {
  try {
    return staticAssetPathPattern.test(new URL(url).pathname);
  } catch {
    return false;
  }
}

function mergeSensitiveEndpointCandidates(candidates: SensitiveEndpointCandidate[]) {
  const sourcesByUrl = new Map<string, Set<SensitiveEndpointCandidate["source"]>>();

  candidates.forEach((candidate) => {
    if (!candidate.url) {
      return;
    }

    const current = sourcesByUrl.get(candidate.url) ?? new Set<SensitiveEndpointCandidate["source"]>();
    current.add(candidate.source);
    sourcesByUrl.set(candidate.url, current);
  });

  return [...sourcesByUrl.entries()].map(([url, sources]) => ({
    url,
    sources: [...sources],
  }));
}

function collectSensitiveEndpointCandidates(
  primaryOrigin: string,
  links: Array<{ url: string; internal: boolean }>,
  forms: PageFormSnapshot[],
) {
  return [
    ...links
      .filter((link) => link.internal && sensitivePathPattern.test(new URL(link.url).pathname))
      .map((link) => ({
        url: link.url,
        source: "internal-link" as const,
      })),
    ...forms
      .filter((form) => form.sensitiveKinds.length > 0)
      .map((form) => ({
        url: form.url,
        source: "form" as const,
      })),
    ...operationalSensitivePaths.map((path) => ({
      url: `${primaryOrigin}${path}`,
      source: "synthetic-operational" as const,
    })),
  ] satisfies SensitiveEndpointCandidate[];
}

function extractEndpointCandidatesFromContent(primaryOrigin: string, contents: string[]) {
  const matches = new Set<string>();
  const pattern = /(["'`])((?:https?:\/\/[^"'`\s]+)?\/(?:api(?:\/v\d+)?|graphql|rest(?:\/v\d+)?|rpc|ajax)[^"'`\s<]*)\1/gi;

  contents.forEach((content) => {
    let match: RegExpExecArray | null;
    while ((match = pattern.exec(content)) !== null) {
      const candidate = resolveHttpUrl(match[2], primaryOrigin);
      if (candidate) {
        matches.add(candidate);
      }
    }
  });

  return [...matches].slice(0, 8);
}

function detectSensitiveDataExposure(
  bodyText: string,
  sourceLabel: string,
) {
  const matches: Array<{ severity: Severity; label: string; redacted: string }> = [];
  const patternChecks: Array<{ pattern: RegExp; label: string; severity: Severity }> = [
    { pattern: /-----BEGIN [A-Z ]*PRIVATE KEY-----/i, label: "Private key material", severity: "critical" },
    { pattern: /\bAKIA[0-9A-Z]{16}\b/, label: "AWS access key", severity: "high" },
    {
      pattern: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9._-]{10,}\.[A-Za-z0-9._-]{10,}\b/,
      label: "JWT-like token",
      severity: "high",
    },
    {
      pattern: /\b(?:secret|private[_-]?key|access[_-]?token|auth[_-]?token|refresh[_-]?token)\b[^"'`\n]{0,30}["'`:= ]+[A-Za-z0-9._-]{12,}/i,
      label: "Token-like configuration value",
      severity: "high",
    },
    {
      pattern: /\bapi[_-]?key\b[^"'`\n]{0,30}["'`:= ]+[A-Za-z0-9._-]{12,}/i,
      label: "Public API key-like configuration",
      severity: "low",
    },
    {
      pattern: /https?:\/\/(?:localhost|127\.0\.0\.1|[^/"'\s]+(?:\.internal|\.local|\.lan|\.corp|\.staging|\.dev))[^"'\s<]*/i,
      label: "Internal URL exposure",
      severity: "low",
    },
  ];

  patternChecks.forEach(({ pattern, label, severity }) => {
    const match = bodyText.match(pattern);
    if (!match?.[0]) {
      return;
    }

    matches.push({
      severity,
      label: `${label} in ${sourceLabel}`,
      redacted: redactValue(match[0]),
    });
  });

  return matches;
}

function extractSimpleForms(url: string, bodyText: string, targetHostname: string) {
  const $ = loadHtml(bodyText);

  return $("form")
    .toArray()
    .flatMap((element, index) => {
      const rawAction = $(element).attr("action")?.trim() ?? "";
      const actionUrl = resolveHttpUrl(rawAction || url, url) ?? url;
      let parsed: URL;
      try {
        parsed = new URL(actionUrl);
      } catch {
        return [];
      }

      const fields = $(element)
        .find("input, textarea, select")
        .toArray()
        .map((field, fieldIndex) => {
          const type =
            (field.tagName === "textarea"
              ? "textarea"
              : field.tagName === "select"
                ? "select"
                : $(field).attr("type"))?.trim().toLowerCase() ?? "text";
          const name =
            $(field).attr("name")?.trim() ||
            $(field).attr("id")?.trim() ||
            `field-${fieldIndex + 1}`;

          return {
            name,
            type,
            autocomplete: $(field).attr("autocomplete")?.trim() ?? null,
            required: $(field).attr("required") !== undefined,
            location: describeDomLocation($, field, url, {
              label: `Form field ${fieldIndex + 1}`,
              attribute: "name",
              note: `${name} (${type})`,
            }),
          } satisfies PageFormSnapshot["fields"][number];
        });

      const hiddenFieldNames = fields
        .filter((field) => field.type === "hidden")
        .map((field) => field.name);
      const csrfFieldNames = fields
        .filter((field) => csrfTokenNamePattern.test(field.name))
        .map((field) => field.name);
      const fieldNames = fields.map((field) => field.name);
      const method = ($(element).attr("method")?.trim().toUpperCase() || "GET");
      const actionExplicit = rawAction.length > 0;
      const lowerAction = rawAction.toLowerCase();
      const sensitiveKinds = new Set<string>();
      const hasPasswordField = fields.some((field) => field.type === "password");
      const hasAuthFieldHints =
        hasPasswordField ||
        fieldNames.some((fieldName) => /(email|username|login|signin|auth|password|otp|code|token)/i.test(fieldName)) ||
        fields.some((field) => /current-password|new-password|username|one-time-code|email/i.test(field.autocomplete ?? ""));
      const hasResetFieldHints =
        fieldNames.some((fieldName) => /(reset|forgot|recover|new[-_]?password|otp|code|token)/i.test(fieldName)) ||
        fields.some((field) => /new-password|one-time-code/i.test(field.autocomplete ?? ""));
      const hasAccountFieldHints = fieldNames.some((fieldName) =>
        /(email|address|billing|card|iban|invoice|profile|settings|phone|account)/i.test(fieldName),
      );

      if (hasPasswordField || /(login|signin|auth|session)/i.test(lowerAction) || (actionExplicit && hasAuthFieldHints)) {
        sensitiveKinds.add("login");
      }
      if (/(reset|forgot|recover|change-password|new-password)/i.test(lowerAction) || (actionExplicit && hasResetFieldHints)) {
        sensitiveKinds.add("password-reset");
      }
      if (
        method !== "GET" &&
        (/(account|profile|settings|billing|payment|invoice)/i.test(lowerAction) ||
          (actionExplicit && hasAccountFieldHints))
      ) {
        sensitiveKinds.add("account");
      }
      if (fields.some((field) => field.type === "file")) {
        sensitiveKinds.add("upload");
      }

      return [
        {
          url: actionUrl,
          sourceUrl: url,
          actionExplicit,
          method,
          enctype: $(element).attr("enctype")?.trim() || "application/x-www-form-urlencoded",
          internal: isInternalHostMatch(parsed.hostname, targetHostname),
          secure: parsed.protocol === "https:",
          hasPasswordField,
          hasFileUpload: fields.some((field) => field.type === "file"),
          fieldNames,
          hiddenFieldNames,
          csrfFieldNames,
          visibleFieldTypes: fields.filter((field) => field.type !== "hidden").map((field) => field.type),
          autocompleteHints: fields
            .map((field) => field.autocomplete)
            .filter((hint): hint is string => Boolean(hint)),
          sensitiveKinds: [...sensitiveKinds],
          fields,
          location: describeDomLocation($, element, url, {
            label: `Form ${index + 1}`,
            attribute: "action",
            note: `${$(element).attr("method")?.trim().toUpperCase() || "GET"} ${actionUrl}`,
          }),
        } satisfies PageFormSnapshot,
      ];
    });
}

export async function runSecurityScan(target: NormalizedTarget): Promise<CategoryScanResult> {
  const artifacts = await loadAuditArtifacts(target);
  const primaryAttempt = artifacts.context.primary;
  const primaryPage = artifacts.primaryPage;
  const primaryOrigin = getPrimaryOrigin(artifacts.context);

  if (!primaryAttempt || !primaryPage || !primaryOrigin) {
    throw new Error("Unable to fetch the target website.");
  }

  const findings = [];
  const configuredAuthCookie = target.authCookieHeader?.trim() || getConfiguredAuthCookieHeader();
  const configuredSecondaryAuthCookie =
    target.secondaryAuthCookieHeader?.trim() ||
    process.env.FIXNX_SCAN_SECONDARY_AUTH_COOKIE_HEADER?.trim().slice(0, 8_000) ||
    process.env.FIXNX_SCAN_SECONDARY_AUTH_COOKIES?.trim().slice(0, 8_000) ||
    "";
  const authHeadersFor = (url: string): HeadersInit | undefined => {
    if (!configuredAuthCookie) {
      return undefined;
    }

    try {
      const parsed = new URL(url);
      return isInternalHostMatch(parsed.hostname, target.targetHostname)
        ? { cookie: configuredAuthCookie }
        : undefined;
    } catch {
      return undefined;
    }
  };
  const secondaryAuthHeadersFor = (url: string): HeadersInit | undefined => {
    if (!configuredSecondaryAuthCookie || configuredSecondaryAuthCookie.startsWith("[") || configuredSecondaryAuthCookie.startsWith("{")) {
      return undefined;
    }

    try {
      const parsed = new URL(url);
      return isInternalHostMatch(parsed.hostname, target.targetHostname)
        ? { cookie: configuredSecondaryAuthCookie }
        : undefined;
    } catch {
      return undefined;
    }
  };
  const httpsDirectAttempt = artifacts.context.https;
  const tlsInfo = artifacts.tlsInfo;
  const primaryAttemptIsInterstitial =
    isLikelyEdgeInterstitial(primaryAttempt) && !artifacts.browserInspection.rendered;
  const httpDirectAttempt = await loadAttempt(target.httpUrl, {
    includeBody: false,
    followRedirects: false,
    timeoutMs: 8_000,
  });
  const pageForms = primaryAttemptIsInterstitial ? [] : primaryPage.formSnapshots;
  const metaCsrfTokenPresent = /<meta[^>]+name=["'][^"']*csrf[^"']*["'][^>]+content=["'][^"']+["']/i.test(
    primaryAttempt.bodyText,
  );
  const firstPartyScriptResources = (primaryAttemptIsInterstitial ? [] : primaryPage.resources).filter(
    (resource) => resource.kind === "script" && resource.internal,
  );
  const firstPartyScriptSamples = (
    await mapLimited(firstPartyScriptResources.slice(0, 5), 3, async (resource) => {
      const attempt = await loadAttempt(resource.url, {
        timeoutMs: 8_000,
      });
      if (!attempt || attempt.status >= 400 || !attempt.bodyText) {
        return null;
      }

      return {
        url: resource.url,
        bodyText: attempt.bodyText.slice(0, 50_000),
        location: resource.location,
      };
    })
  ).filter(
    (
      sample,
    ): sample is {
      url: string;
      bodyText: string;
      location: PageResource["location"];
    } => Boolean(sample),
  );
  const browserDiscoveredApiEndpoints = primaryAttemptIsInterstitial
    ? []
    : primaryPage.resources
        .filter((resource) => resource.internal && resource.kind === "fetch")
        .map((resource) => resource.url)
        .filter((url) => {
          try {
            return apiPathPattern.test(new URL(url).pathname);
          } catch {
            return false;
          }
        });
  const discoveredApiEndpoints = primaryAttemptIsInterstitial
    ? []
    : uniqueUrls([
        ...extractEndpointCandidatesFromContent(primaryOrigin, [
          primaryAttempt.bodyText,
          ...primaryPage.inlineScripts.map((script) => script.content),
          ...firstPartyScriptSamples.map((sample) => sample.bodyText),
        ]),
        ...browserDiscoveredApiEndpoints,
      ]);
  const sensitiveEndpointCandidates = mergeSensitiveEndpointCandidates([
    ...collectSensitiveEndpointCandidates(primaryOrigin, primaryPage.links, pageForms),
    ...discoveredApiEndpoints
      .filter((url) => sensitivePathPattern.test(new URL(url).pathname))
      .map((url) => ({
        url,
        source: "discovered-api" as const,
      })),
  ]).slice(0, 12);
  const sensitiveEndpointAttempts = (
    await mapLimited(sensitiveEndpointCandidates, 4, async (candidate) => {
      const attempt = await loadAttempt(candidate.url, {
        timeoutMs: 8_000,
        followRedirects: false,
      });
      if (!attempt) {
        return null;
      }

      return {
        url: candidate.url,
        status: attempt.status,
        finalUrl: attempt.finalUrl,
        locationHeader: attempt.headers.location ?? "",
        headers: attempt.headers,
        bodyText: attempt.bodyText,
        sources: candidate.sources,
      } satisfies SensitiveEndpointAttempt;
    })
  ).filter(isPresent);
  const notableSensitiveEndpointAttempts = sensitiveEndpointAttempts.filter(
    (attempt) =>
      (isReachableSensitiveEndpoint(attempt) || isProtectedSensitiveRedirect(attempt)) &&
      !(
        attempt.sources.every((source) => source === "synthetic-operational") &&
        attempt.status >= 200 &&
        attempt.status < 300 &&
        isHtmlLikeResponse(attempt.headers, attempt.bodyText)
      ),
  );
  const authSurfaceAttempts = notableSensitiveEndpointAttempts.filter((attempt) =>
    /(login|signin|register|signup|password|reset|forgot|auth|account|accounts|session|identifier)/i.test(
      new URL(attempt.url).pathname,
    ),
  );
  const apiSurfaceAttempts = notableSensitiveEndpointAttempts.filter((attempt) =>
    apiPathPattern.test(new URL(attempt.url).pathname),
  );
  const uploadSurfaceAttempts = notableSensitiveEndpointAttempts.filter((attempt) =>
    /upload/i.test(new URL(attempt.url).pathname),
  );
  const discoveredAuthForms = authSurfaceAttempts.flatMap((attempt) =>
    extractSimpleForms(attempt.finalUrl, attempt.bodyText, target.targetHostname),
  );
  const allKnownForms = [...pageForms, ...discoveredAuthForms];
  const allKnownFormUrls = uniqueUrls(allKnownForms.map((form) => form.url));

  const httpsProtectedOrChallenged = Boolean(
    httpsDirectAttempt &&
      ([401, 403, 405].includes(httpsDirectAttempt.status) || isLikelyEdgeInterstitial(httpsDirectAttempt)),
  );
  const browserCoverageStatus = artifacts.browserInspection.rendered
    ? { status: "pass" as const, severity: "info" as const }
    : artifacts.browserInspection.attempted
      ? { status: "warning" as const, severity: "low" as const }
      : { status: "info" as const, severity: "info" as const };
  findings.push(
    buildSecurityCheck({
      checkKey: "browser-rendered-crawl-coverage",
      title: "Browser-rendered crawl coverage",
      scoreWeight: 0.35,
      ...browserCoverageStatus,
      shortDescription: artifacts.browserInspection.rendered
        ? `Rendered ${artifacts.browserInspection.renderedPageCount} page(s) with JavaScript and observed ${artifacts.browserInspection.networkRequestCount} browser network request(s).`
        : artifacts.browserInspection.attempted
          ? "Browser rendering was attempted but did not produce a rendered page snapshot."
          : "Browser rendering is disabled for this scan environment.",
      whyItMatters:
        "Modern SPA applications often expose login routes, forms, links, and API calls only after JavaScript executes.",
      recommendation: artifacts.browserInspection.rendered
        ? "Keep JavaScript rendering enabled for production scans and add authenticated cookies when private routes need coverage."
        : "Install Playwright browser binaries or enable browser rendering so SPA routes and client-side API calls are included.",
      evidence: {
        checkedUrl: primaryAttempt.finalUrl,
        expectedLocation: "Rendered DOM, same-origin links, forms, scripts, and browser network requests",
        summary: artifacts.browserInspection.rendered
          ? "The scanner used a browser-rendered DOM snapshot for route and resource discovery."
          : "The scan fell back to fetch-only artifacts for JavaScript-dependent coverage.",
        browser: artifacts.browserInspection,
        crawledPages: artifacts.crawledPages.map((page) => page.url),
      },
    }),
  );

  findings.push(
    buildSecurityCheck({
      checkKey: "https-enabled",
      title: "HTTPS enabled",
      status:
        httpsDirectAttempt && (httpsDirectAttempt.status < 400 || httpsProtectedOrChallenged || tlsInfo?.available)
          ? "pass"
          : "fail",
      severity:
        httpsDirectAttempt && (httpsDirectAttempt.status < 400 || httpsProtectedOrChallenged || tlsInfo?.available)
          ? "info"
          : "high",
      shortDescription:
        httpsDirectAttempt && httpsDirectAttempt.status < 400
          ? "The target hostname returned a successful HTTPS response."
          : httpsProtectedOrChallenged
            ? `HTTPS responded with status ${httpsDirectAttempt?.status}, which appears to be an intentional access-control or bot-protection response.`
            : httpsDirectAttempt || tlsInfo?.available
              ? `HTTPS is reachable and the hostname presents a TLS certificate, but the sampled page response returned status ${httpsDirectAttempt?.status ?? "unknown"}.`
            : "The target hostname did not return a successful HTTPS response.",
      whyItMatters:
        "HTTPS protects data in transit and is the baseline for browser trust and secure sessions.",
      recommendation:
        httpsDirectAttempt && httpsDirectAttempt.status < 400
          ? "Keep TLS enabled on the public hostname."
          : httpsProtectedOrChallenged
            ? "Review whether the non-success status is an intentional access-control or bot-protection response."
          : httpsDirectAttempt || tlsInfo?.available
            ? "Review the non-success HTTPS response, but treat TLS availability separately from application access control."
          : "Enable HTTPS with a valid TLS certificate on the public hostname.",
      evidence: {
        checkedUrl: target.httpsUrl,
        expectedLocation: "Successful HTTPS response",
        summary:
          httpsDirectAttempt && httpsDirectAttempt.status < 400
            ? "HTTPS is available on the scanned hostname."
            : httpsProtectedOrChallenged
              ? "HTTPS is available, but the sampled response was intentionally gated."
            : httpsDirectAttempt || tlsInfo?.available
              ? "HTTPS is reachable, but the sampled response was not a directly accessible 2xx/3xx page response."
            : "HTTPS did not return a successful response for the scanned hostname.",
        statusCode: httpsDirectAttempt?.status ?? null,
      },
    }),
  );

  const httpRedirectLocation = httpDirectAttempt?.headers.location ?? "";
  const httpRedirectStatus =
    httpDirectAttempt && httpDirectAttempt.status >= 300 && httpDirectAttempt.status < 400;
  const httpRedirectToHttps = httpRedirectStatus && httpRedirectLocation.startsWith("https://");
  const httpDirectSuccess = Boolean(
    httpDirectAttempt && httpDirectAttempt.status >= 200 && httpDirectAttempt.status < 300,
  );
  findings.push(
    buildSecurityCheck({
      checkKey: "http-to-https-redirect",
      title: "HTTP to HTTPS redirect",
      scoreWeight: 0.7,
      status: httpRedirectToHttps
        ? "pass"
        : httpRedirectStatus
          ? "warning"
          : httpDirectSuccess
            ? "warning"
            : "fail",
      severity: httpRedirectToHttps ? "info" : httpRedirectStatus || httpDirectSuccess ? "low" : "medium",
      shortDescription: httpRedirectToHttps
        ? "HTTP requests redirect to HTTPS."
        : httpRedirectStatus
          ? `HTTP redirects, but the Location header does not point to HTTPS: ${httpRedirectLocation || "missing"}.`
          : httpDirectSuccess
            ? "The HTTP endpoint responded directly instead of redirecting to HTTPS."
            : "The HTTP endpoint did not issue a redirect to HTTPS.",
      whyItMatters:
        "Users can still reach insecure endpoints if the plaintext HTTP entrypoint does not force an upgrade to HTTPS.",
      recommendation:
        httpRedirectToHttps
          ? "Keep the HTTP entrypoint redirecting directly to HTTPS."
          : "Configure the HTTP endpoint to redirect directly to the HTTPS URL.",
      evidence: {
        checkedUrl: target.httpUrl,
        expectedLocation: "HTTP response Location header should start with https://",
        summary: httpRedirectToHttps
          ? "The HTTP entrypoint redirected directly to HTTPS."
          : "The HTTP entrypoint did not redirect directly to HTTPS.",
        statusCode: httpDirectAttempt?.status ?? null,
        redirectLocation: httpRedirectLocation || null,
      },
    }),
  );

  const certificateValid = Boolean(tlsInfo?.available && !tlsInfo.authorizationError);
  const tlsDaysRemaining = tlsInfo?.daysRemaining ?? null;
  const tlsValidTo = tlsInfo?.validTo ?? null;
  findings.push(
    buildSecurityCheck({
      checkKey: "ssl-certificate-valid",
      title: "SSL certificate valid",
      status: certificateValid ? "pass" : "fail",
      severity: certificateValid ? "info" : "high",
      shortDescription: certificateValid
        ? "The TLS certificate was presented and validated by the client."
        : `The TLS certificate could not be validated: ${tlsInfo?.authorizationError ?? "certificate unavailable"}.`,
      whyItMatters:
        "Invalid certificates break browser trust and can expose users to interception or service outages.",
      recommendation: certificateValid
        ? "Keep certificate renewal and issuance automated."
        : "Fix certificate issuance, trust chain, and hostname validation errors.",
      evidence: {
        checkedUrl: target.httpsUrl,
        expectedLocation: `TLS certificate presented by ${target.targetHostname}`,
        summary: certificateValid
          ? "The TLS certificate validated successfully."
          : "The TLS certificate failed validation or was unavailable.",
        issuer: tlsInfo?.issuer ?? null,
        subject: tlsInfo?.subject ?? null,
        validFrom: tlsInfo?.validFrom ?? null,
        validTo: tlsInfo?.validTo ?? null,
      },
    }),
  );

  const expirationStatus =
    !tlsInfo?.available || tlsDaysRemaining === null
      ? { status: "fail" as const, severity: "high" as const }
      : tlsDaysRemaining < 0
        ? { status: "fail" as const, severity: "high" as const }
        : tlsDaysRemaining < 30
          ? { status: "warning" as const, severity: "medium" as const }
          : { status: "pass" as const, severity: "info" as const };
  findings.push(
    buildSecurityCheck({
      checkKey: "ssl-expiration-soon",
      title: "SSL expiration window",
      ...expirationStatus,
      shortDescription:
        tlsDaysRemaining === null
          ? "Certificate expiry could not be evaluated."
          : `The certificate expires in ${tlsDaysRemaining} days.`,
      whyItMatters:
        "Certificates that are close to expiry can abruptly break availability and trust for the public site.",
      recommendation:
        expirationStatus.status === "pass"
          ? "Keep monitoring automated renewals."
          : "Renew or rotate the certificate before expiration and verify renewal jobs.",
      evidence: {
        checkedUrl: target.httpsUrl,
        expectedLocation: `TLS certificate expiry for ${target.targetHostname}`,
        summary:
          tlsDaysRemaining === null
            ? "The certificate expiry date was unavailable."
            : `The certificate expires on ${tlsValidTo}.`,
        validTo: tlsValidTo,
        daysRemaining: tlsDaysRemaining,
      },
    }),
  );

  findings.push(
    buildSecurityCheck({
      checkKey: "domain-matches-certificate",
      title: "Domain matches certificate",
      status: tlsInfo?.domainMatch ? "pass" : "fail",
      severity: tlsInfo?.domainMatch ? "info" : "high",
      shortDescription: tlsInfo?.domainMatch
        ? "The scanned hostname matches the certificate names."
        : "The scanned hostname does not match the certificate names.",
      whyItMatters:
        "A hostname mismatch causes browser trust failures even when a certificate is otherwise present.",
      recommendation: tlsInfo?.domainMatch
        ? "Keep the certificate SAN/CN entries aligned with the public hostname."
        : "Issue a certificate whose SAN or CN covers the scanned hostname.",
      evidence: {
        checkedUrl: target.httpsUrl,
        expectedLocation: "Certificate SAN/CN should cover the scanned hostname",
        summary: tlsInfo?.domainMatch
          ? "The hostname matched the certificate names."
          : "The hostname did not match any presented certificate names.",
        subjectAltName: tlsInfo?.subjectAltName ?? null,
        matchedNames: tlsInfo?.matchedNames ?? [],
      },
    }),
  );

  const hstsHeader = primaryAttempt.headers["strict-transport-security"];
  const hstsMaxAge = hstsHeader ? parseMaxAge(hstsHeader) : null;
  const hstsStatus = !hstsHeader
    ? { status: "warning" as const, severity: "low" as const }
    : hstsMaxAge !== null && hstsMaxAge >= 15_552_000
      ? { status: "pass" as const, severity: "info" as const }
      : { status: "warning" as const, severity: "low" as const };
  findings.push(
    buildSecurityCheck({
      checkKey: "hsts-header",
      title: "HSTS header",
      scoreWeight: 0.6,
      ...hstsStatus,
      shortDescription: !hstsHeader
        ? "Strict-Transport-Security is missing from the HTTPS response."
        : `Strict-Transport-Security is set to "${hstsHeader}".`,
      whyItMatters:
        "HSTS helps browsers avoid insecure protocol downgrades after the first secure visit.",
      recommendation: !hstsHeader
        ? "Add a Strict-Transport-Security header on HTTPS responses."
        : "Use a long-lived max-age and includeSubDomains/preload only when your deployment is ready.",
      evidence: hstsHeader
        ? {
            ...headerEvidence(primaryAttempt.finalUrl, "strict-transport-security", "The HSTS header was read from the HTTPS response."),
            value: hstsHeader,
            maxAge: hstsMaxAge,
          }
        : headerEvidence(primaryAttempt.finalUrl, "strict-transport-security", "The HSTS header is missing from the HTTPS response."),
    }),
  );

  const cspHeader = primaryAttempt.headers["content-security-policy"];
  const cspReportOnlyHeader = primaryAttempt.headers["content-security-policy-report-only"];
  const effectiveCspHeader = cspHeader || cspReportOnlyHeader || "";
  const cspWeak = effectiveCspHeader ? /unsafe-inline|unsafe-eval/i.test(effectiveCspHeader) : false;
  const cspStatus = cspHeader
    ? cspWeak
      ? { status: "warning" as const, severity: "low" as const }
      : { status: "pass" as const, severity: "info" as const }
    : cspReportOnlyHeader
      ? { status: "warning" as const, severity: "low" as const }
      : primaryAttemptIsInterstitial
        ? { status: "info" as const, severity: "info" as const }
      : { status: "warning" as const, severity: "low" as const };
  findings.push(
    buildSecurityCheck({
      checkKey: "content-security-policy",
      title: "Content-Security-Policy",
      scoreWeight: 0.7,
      ...cspStatus,
      shortDescription: cspHeader
        ? `Content-Security-Policy is set to "${cspHeader}".`
        : cspReportOnlyHeader
          ? `Content-Security-Policy-Report-Only is set to "${cspReportOnlyHeader}".`
          : primaryAttemptIsInterstitial
            ? "The sampled response looked like an edge interstitial, so CSP enforcement on the underlying app could not be verified."
          : "Content-Security-Policy is missing from the main response.",
      whyItMatters:
        "A strong CSP reduces exposure to XSS and limits where scripts, frames, and other content can load from.",
      recommendation: cspHeader
        ? "Tighten permissive directives like `unsafe-inline` or `unsafe-eval` when feasible."
        : cspReportOnlyHeader
          ? "Promote the report-only policy to an enforced `Content-Security-Policy` header once it is validated."
          : primaryAttemptIsInterstitial
            ? "Re-run the scan from a path or environment that can fetch the actual application HTML before treating CSP as missing."
          : "Add a Content-Security-Policy header to the main response.",
      evidence: effectiveCspHeader
        ? {
            ...headerEvidence(
              primaryAttempt.finalUrl,
              cspHeader ? "content-security-policy" : "content-security-policy-report-only",
              cspHeader
                ? "The CSP header was read from the main response."
                : "A report-only CSP header was read from the main response.",
            ),
            value: effectiveCspHeader,
            enforced: Boolean(cspHeader),
          }
        : headerEvidence(primaryAttempt.finalUrl, "content-security-policy", "The CSP header is missing from the main response."),
    }),
  );

  const frameOptions = primaryAttempt.headers["x-frame-options"]?.toUpperCase() ?? "";
  findings.push(
    buildSecurityCheck({
      checkKey: "x-frame-options",
      title: "X-Frame-Options",
      scoreWeight: 0.45,
      status: !frameOptions ? "fail" : ["DENY", "SAMEORIGIN"].includes(frameOptions) ? "pass" : "warning",
      severity: !frameOptions ? "low" : ["DENY", "SAMEORIGIN"].includes(frameOptions) ? "info" : "low",
      shortDescription: frameOptions
        ? `X-Frame-Options is set to "${frameOptions}".`
        : "X-Frame-Options is missing from the main response.",
      whyItMatters:
        "Frame embedding protections help reduce clickjacking exposure on pages that should not be framed by untrusted origins.",
      recommendation: frameOptions
        ? "Prefer `DENY` or `SAMEORIGIN` unless framing is intentionally required."
        : "Add `X-Frame-Options: DENY` or `SAMEORIGIN` where appropriate.",
      evidence: frameOptions
        ? {
            ...headerEvidence(primaryAttempt.finalUrl, "x-frame-options", "The X-Frame-Options header was read from the main response."),
            value: frameOptions,
          }
        : headerEvidence(primaryAttempt.finalUrl, "x-frame-options", "The X-Frame-Options header is missing from the main response."),
    }),
  );

  const contentTypeOptions = primaryAttempt.headers["x-content-type-options"]?.toLowerCase() ?? "";
  findings.push(
    buildSecurityCheck({
      checkKey: "x-content-type-options",
      title: "X-Content-Type-Options",
      scoreWeight: 0.4,
      status: contentTypeOptions === "nosniff" ? "pass" : "warning",
      severity: contentTypeOptions === "nosniff" ? "info" : "low",
      shortDescription: contentTypeOptions
        ? `X-Content-Type-Options is set to "${contentTypeOptions}".`
        : "X-Content-Type-Options is missing from the main response.",
      whyItMatters:
        "The `nosniff` policy helps prevent browsers from guessing a different MIME type than intended.",
      recommendation:
        contentTypeOptions === "nosniff"
          ? "Keep `X-Content-Type-Options: nosniff` enabled."
          : "Set `X-Content-Type-Options: nosniff` on the main response.",
      evidence: contentTypeOptions
        ? {
            ...headerEvidence(primaryAttempt.finalUrl, "x-content-type-options", "The MIME sniffing policy was read from the response."),
            value: contentTypeOptions,
          }
        : headerEvidence(primaryAttempt.finalUrl, "x-content-type-options", "The MIME sniffing policy header is missing."),
    }),
  );

  const referrerPolicy = primaryAttempt.headers["referrer-policy"] ?? "";
  const weakReferrer = /^(unsafe-url|no-referrer-when-downgrade|origin|origin-when-cross-origin)$/i.test(
    referrerPolicy.trim(),
  );
  findings.push(
    buildSecurityCheck({
      checkKey: "referrer-policy",
      title: "Referrer-Policy",
      scoreWeight: 0.4,
      status: !referrerPolicy ? "warning" : weakReferrer ? "warning" : "pass",
      severity: !referrerPolicy ? "low" : weakReferrer ? "low" : "info",
      shortDescription: referrerPolicy
        ? `Referrer-Policy is set to "${referrerPolicy}".`
        : "Referrer-Policy is missing from the main response.",
      whyItMatters:
        "Referrer policy controls how much URL information is leaked to downstream origins.",
      recommendation: !referrerPolicy
        ? "Add a Referrer-Policy header, typically `strict-origin-when-cross-origin`."
        : "Prefer a stricter policy if the current value leaks more URL detail than needed.",
      evidence: referrerPolicy
        ? {
            ...headerEvidence(primaryAttempt.finalUrl, "referrer-policy", "The referrer policy header was read from the main response."),
            value: referrerPolicy,
          }
        : headerEvidence(primaryAttempt.finalUrl, "referrer-policy", "The referrer policy header is missing."),
    }),
  );

  const permissionsPolicy = primaryAttempt.headers["permissions-policy"] ?? "";
  findings.push(
    buildSecurityCheck({
      checkKey: "permissions-policy",
      title: "Permissions-Policy",
      scoreWeight: 0.4,
      status: !permissionsPolicy ? "warning" : permissionsPolicy.length < 20 ? "warning" : "pass",
      severity: !permissionsPolicy ? "low" : permissionsPolicy.length < 20 ? "low" : "info",
      shortDescription: permissionsPolicy
        ? `Permissions-Policy is set to "${permissionsPolicy}".`
        : "Permissions-Policy is missing from the main response.",
      whyItMatters:
        "Permissions-Policy can reduce unnecessary browser capabilities on the page.",
      recommendation: !permissionsPolicy
        ? "Add a Permissions-Policy header that explicitly declares the browser features you want to allow."
        : "Review the policy to ensure it covers the browser features the page uses.",
      evidence: permissionsPolicy
        ? {
            ...headerEvidence(primaryAttempt.finalUrl, "permissions-policy", "The permissions policy header was read from the main response."),
            value: permissionsPolicy,
          }
        : headerEvidence(primaryAttempt.finalUrl, "permissions-policy", "The permissions policy header is missing."),
    }),
  );

  const isolationHeaders: Array<[string, string]> = [
    ["cross-origin-opener-policy", "Cross-Origin-Opener-Policy"],
    ["cross-origin-resource-policy", "Cross-Origin-Resource-Policy"],
    ["cross-origin-embedder-policy", "Cross-Origin-Embedder-Policy"],
  ];
  isolationHeaders.forEach(([headerName, title]) => {
    const value = primaryAttempt.headers[headerName] ?? "";
    findings.push(
      buildSecurityCheck({
        checkKey: headerName,
        title,
        status: value ? "pass" : "info",
        severity: "info",
        shortDescription: value
          ? `${title} is set to "${value}".`
          : `${title} is not present on the main response.`,
        whyItMatters:
          "Cross-origin isolation headers can tighten process isolation and resource loading behavior for advanced browser security models.",
        recommendation: value
          ? `Keep ${title} aligned with how the page uses cross-origin resources.`
          : `Add ${title} if the page benefits from stronger cross-origin isolation.`,
        evidence: value
          ? {
              ...headerEvidence(primaryAttempt.finalUrl, headerName, `${title} was read from the main response.`),
              value,
            }
          : headerEvidence(primaryAttempt.finalUrl, headerName, `${title} is not present on the main response.`),
      }),
    );
  });

  const frameAncestorsDirective =
    extractDirectiveValue(cspHeader, "frame-ancestors") ||
    extractDirectiveValue(cspReportOnlyHeader, "frame-ancestors");
  const hasStrongXfo = ["DENY", "SAMEORIGIN"].includes(frameOptions);
  const strongFrameAncestors = isStrongFrameAncestorsPolicy(frameAncestorsDirective);
  const clickjackingSurfaceHighRisk =
    allKnownForms.some((form) => form.hasPasswordField || form.sensitiveKinds.includes("account")) ||
    authSurfaceAttempts.length > 0;
  const clickjackingStatus = hasStrongXfo || strongFrameAncestors
    ? { status: "pass" as const, severity: "info" as const }
    : frameOptions || frameAncestorsDirective
      ? {
          status: "warning" as const,
          severity: clickjackingSurfaceHighRisk ? "medium" as const : "low" as const,
        }
      : {
          status: "warning" as const,
          severity: clickjackingSurfaceHighRisk ? "medium" as const : "low" as const,
        };
  findings.push(
    buildSecurityCheck({
      checkKey: "clickjacking-protection",
      title: "Clickjacking protection",
      scoreWeight: clickjackingSurfaceHighRisk ? 0.95 : 0.7,
      ...clickjackingStatus,
      shortDescription:
        clickjackingStatus.status === "pass"
          ? "The response exposes iframe embedding protection through X-Frame-Options or frame-ancestors."
          : frameOptions || frameAncestorsDirective
            ? "Some iframe embedding protection exists, but it is partial or weaker than recommended."
            : "The response does not expose a clear iframe embedding protection policy.",
      whyItMatters:
        "Without iframe embedding protection, attackers can overlay the site inside a malicious page and trick users into unintended clicks.",
      recommendation:
        clickjackingStatus.status === "pass"
          ? "Keep iframe embedding restricted to trusted origins only."
          : "Set `X-Frame-Options: DENY` or `SAMEORIGIN`, or enforce a CSP `frame-ancestors` policy for trusted origins.",
      evidence: {
        checkedUrl: primaryAttempt.finalUrl,
        expectedLocation: 'response.headers["x-frame-options"] and CSP frame-ancestors',
        summary:
          clickjackingStatus.status === "pass"
            ? "At least one strong iframe embedding control was detected."
            : "The sampled response is missing a strong iframe embedding control.",
        xFrameOptions: frameOptions || null,
        frameAncestors: frameAncestorsDirective || null,
        cspEnforced: Boolean(cspHeader),
        highRiskSurface: clickjackingSurfaceHighRisk,
      },
    }),
  );

  const corsProbeOrigin = "https://origin.cyberaudit.invalid";
  const corsTargets = uniqueUrls([
    primaryOrigin,
    ...apiSurfaceAttempts.map((attempt) => attempt.finalUrl),
    ...discoveredApiEndpoints,
  ]).slice(0, 3);
  const corsProbes = (
    await mapLimited(corsTargets, 3, async (url) => {
      const attempt = await loadAttempt(url, {
        timeoutMs: 8_000,
        includeBody: false,
        headers: {
          Origin: corsProbeOrigin,
        },
      });

      if (!attempt) {
        return null;
      }

      return {
        url,
        acao: attempt.headers["access-control-allow-origin"] ?? "",
        acac: attempt.headers["access-control-allow-credentials"] ?? "",
        vary: attempt.headers.vary ?? "",
        status: attempt.status,
        contentType: attempt.headers["content-type"] ?? "",
      };
    })
  ).filter(isPresent);
  const dangerousCorsProbe = corsProbes.find(
    (probe) =>
      (probe.acao === corsProbeOrigin || probe.acao === "*") &&
      /true/i.test(probe.acac),
  );
  const broadCorsProbe = corsProbes.find(
    (probe) =>
      (probe.acao === "*" ||
        probe.acao === corsProbeOrigin ||
        (!!probe.acao && probe.acao !== new URL(probe.url).origin)) &&
      !isStaticAssetUrl(probe.url) &&
      !/text\/html/i.test(probe.contentType) &&
      (apiPathPattern.test(new URL(probe.url).pathname) ||
        /application\/(?:json|graphql-response\+json)|text\/plain|application\/xml|text\/xml/i.test(
          probe.contentType,
        )),
  );
  const corsStatus = dangerousCorsProbe
    ? { status: "fail" as const, severity: "high" as const }
    : broadCorsProbe
      ? { status: "warning" as const, severity: "medium" as const }
      : { status: "pass" as const, severity: "info" as const };
  findings.push(
    buildSecurityCheck({
      checkKey: "cors-misconfiguration",
      title: "CORS misconfiguration",
      scoreWeight: 1.45,
      ...corsStatus,
      shortDescription: dangerousCorsProbe
        ? `A sampled response allowed the foreign origin ${corsProbeOrigin} together with credentialed CORS.`
        : broadCorsProbe
          ? `A sampled response exposed a broad CORS policy on ${broadCorsProbe.url}.`
          : "Sampled responses did not expose a dangerous cross-origin sharing policy.",
      whyItMatters:
        "Misconfigured CORS can let untrusted origins read sensitive responses in the browser, especially when credentials are allowed.",
      recommendation:
        corsStatus.status === "pass"
          ? "Keep cross-origin access tightly scoped to trusted origins and response types."
          : "Restrict `Access-Control-Allow-Origin` to explicit trusted origins and avoid combining broad origins with `Access-Control-Allow-Credentials: true`.",
      evidence: {
        checkedUrl: corsTargets.join(", "),
        expectedLocation:
          'response.headers["access-control-allow-origin"], ["access-control-allow-credentials"], ["vary"]',
        summary:
          corsStatus.status === "pass"
            ? "No sampled CORS response reflected the test origin in a dangerous way."
            : "At least one sampled response exposed a broad or dangerous CORS policy.",
        sentOrigin: corsProbeOrigin,
        targets: corsProbes.map((probe) => ({
          url: probe.url,
          status: probe.status,
          accessControlAllowOrigin: probe.acao || null,
          accessControlAllowCredentials: probe.acac || null,
          vary: probe.vary || null,
          contentType: probe.contentType || null,
        })),
      },
    }),
  );

  const cookies = primaryAttempt.setCookies.map((cookie) => ({
    name: cookieName(cookie),
    raw: cookie,
    infrastructure: isInfrastructureCookie(cookieName(cookie)),
    sensitive:
      isSensitiveCookie(cookieName(cookie)) &&
      !isInfrastructureCookie(cookieName(cookie)),
    ...parseCookieFlags(cookie),
  }));
  const applicationCookies = cookies.filter((cookie) => !cookie.infrastructure);
  const cookieHints = collectCookieHints(primaryAttempt.setCookies);
  const missingSecure = applicationCookies.filter((cookie) => !cookie.secure);
  const missingHttpOnly = applicationCookies.filter((cookie) => !cookie.httpOnly && !isCsrfCookie(cookie.name));
  const missingSameSite = applicationCookies.filter((cookie) => !cookie.sameSite);
  const cookieChecks: Array<{
    checkKey: string;
    title: string;
    items: typeof applicationCookies;
    missing: typeof missingSecure;
    flag: "Secure" | "HttpOnly" | "SameSite";
    whyItMatters: string;
    recommendation: string;
  }> = [
    {
      checkKey: "secure-cookies",
      title: "Secure cookies",
      items: applicationCookies,
      missing: missingSecure,
      flag: "Secure",
      whyItMatters:
        "Sensitive cookies should only be sent over HTTPS to avoid exposure on plaintext channels.",
      recommendation: "Mark sensitive cookies with the Secure attribute.",
    },
    {
      checkKey: "httponly-cookies",
      title: "HttpOnly cookies",
      items: applicationCookies,
      missing: missingHttpOnly,
      flag: "HttpOnly",
      whyItMatters:
        "HttpOnly prevents client-side scripts from reading sensitive cookies.",
      recommendation: "Mark authentication and session cookies as HttpOnly.",
    },
    {
      checkKey: "samesite-cookies",
      title: "SameSite cookies",
      items: applicationCookies,
      missing: missingSameSite,
      flag: "SameSite",
      whyItMatters:
        "SameSite reduces cross-site request forgery and cross-site session leakage risk.",
      recommendation: "Set SameSite=Lax or Strict where the application permits it.",
    },
  ];
  cookieChecks.forEach((check) => {
    const sensitiveMissing = check.missing.filter((cookie) => cookie.sensitive);
    const status =
      check.items.length === 0
        ? "pass"
        : sensitiveMissing.length > 0
          ? "fail"
          : check.missing.length > 0
            ? "warning"
            : "pass";
    const severity: Severity =
      status === "fail" ? "medium" : status === "warning" ? "low" : "info";

    findings.push(
      buildSecurityCheck({
        checkKey: check.checkKey,
        title: check.title,
        scoreWeight:
          sensitiveMissing.length > 0
            ? 1.15
            : check.missing.length > 0
              ? 0.7
              : 0.4,
        status,
        severity,
        shortDescription:
          applicationCookies.length === 0 && cookies.length > 0
            ? "Only infrastructure cookies were observed on the sampled response."
            : check.items.length === 0
              ? "No response cookies were set on the primary document."
            : check.missing.length === 0
              ? `All ${check.items.length} sampled response cookies include ${check.flag}.`
              : `${check.missing.length} of ${check.items.length} sampled response cookies are missing ${check.flag}.`,
        whyItMatters: check.whyItMatters,
        recommendation:
          applicationCookies.length === 0 && cookies.length > 0
            ? "No application cookies were observed on this response, so this check is informational."
            : check.items.length === 0
              ? "No change is required unless your application sets cookies on other routes."
            : check.recommendation,
        evidence: {
          checkedUrl: primaryAttempt.finalUrl,
          expectedLocation: 'response.headers["set-cookie"]',
          summary:
            applicationCookies.length === 0 && cookies.length > 0
              ? "Only infrastructure or edge-network cookies were set on the sampled response."
            : check.items.length === 0
              ? "The primary document response did not set cookies."
              : `${check.missing.length} sampled cookies are missing ${check.flag}.`,
          cookieCount: check.items.length,
          missingCount: check.missing.length,
          locations: check.missing.slice(0, 8).map((cookie) =>
            createResponseLocation({
              label: `Cookie ${cookie.name}`,
              url: primaryAttempt.finalUrl,
              path: 'response.headers["set-cookie"]',
              value: cookie.raw,
              note: `Missing ${check.flag}.`,
            }),
          ),
        },
      }),
    );
  });

  const sensitiveForms = allKnownForms.filter(
    (form) =>
      form.method !== "GET" &&
      form.sensitiveKinds.some((kind) => ["login", "password-reset", "account"].includes(kind)),
  );
  const clearlyProtectedForms = sensitiveForms.filter(
    (form) =>
      form.csrfFieldNames.length > 0 ||
      metaCsrfTokenPresent ||
      cookieHints.sensitiveCookies.some((cookie) => cookie.sameSite),
  );
  const unprotectedSensitiveForms = sensitiveForms.filter((form) => !clearlyProtectedForms.includes(form));
  const unprotectedAccountLikeForms = unprotectedSensitiveForms.filter(
    (form) =>
      form.sensitiveKinds.includes("account") ||
      form.hasFileUpload,
  );
  const unprotectedAuthLikeForms = unprotectedSensitiveForms.filter(
    (form) =>
      form.hasPasswordField ||
      form.sensitiveKinds.some((kind) => ["login", "password-reset"].includes(kind)) ||
      thirdPartyAuthMethodPattern.test(form.url),
  );
  const csrfStatus =
    sensitiveForms.length === 0
      ? { status: "info" as const, severity: "info" as const }
      : clearlyProtectedForms.length === sensitiveForms.length
        ? { status: "pass" as const, severity: "info" as const }
        : unprotectedAccountLikeForms.length > 0
          ? { status: "fail" as const, severity: "high" as const }
          : unprotectedAuthLikeForms.length > 0
            ? { status: "warning" as const, severity: "medium" as const }
            : { status: "warning" as const, severity: "low" as const };
  findings.push(
    buildSecurityCheck({
      checkKey: "csrf-protection-sensitive-forms",
      title: "CSRF protection on sensitive forms",
      scoreWeight: unprotectedAccountLikeForms.length > 0 ? 1.1 : 0.75,
      ...csrfStatus,
      shortDescription:
        sensitiveForms.length === 0
          ? "No sensitive forms were detected on the sampled pages."
          : clearlyProtectedForms.length === sensitiveForms.length
            ? "Each sampled sensitive form exposed a visible CSRF protection signal."
            : `${unprotectedSensitiveForms.length} of ${sensitiveForms.length} sampled sensitive forms did not expose a clear CSRF protection signal.`,
      whyItMatters:
        "Without CSRF protection, another site can sometimes trigger authenticated actions on behalf of a logged-in user.",
      recommendation:
        sensitiveForms.length === 0
          ? "No immediate change is required unless sensitive forms exist on unscanned routes."
          : "Use per-request CSRF tokens or equivalent framework protections on sensitive forms, and pair them with SameSite cookies where appropriate. For framework-managed login flows, verify the protection even if it is not visible in the HTML.",
      evidence: {
        checkedUrl: allKnownFormUrls.join(", "),
        expectedLocation: "Sensitive forms should expose CSRF token signals or equivalent framework protection",
        summary:
          csrfStatus.status === "pass"
            ? "Sampled sensitive forms exposed CSRF protection indicators."
            : "Some sampled sensitive forms did not expose a clear CSRF protection indicator in the sampled HTML.",
        metaCsrfTokenPresent,
        sensitiveFormCount: sensitiveForms.length,
        protectedFormCount: clearlyProtectedForms.length,
        locations: unprotectedSensitiveForms
          .slice(0, 8)
          .map((form, index) => ({
            ...form.location,
            label: `Sensitive form ${index + 1}`,
            note: `${form.method} ${form.url}`,
          })),
      },
    }),
  );

  const sessionReviewStatus =
    cookieHints.sensitiveCookies.length === 0
      ? { status: "info" as const, severity: "info" as const }
      : cookieHints.sensitiveMissingSecure.length > 0 || cookieHints.sensitiveMissingHttpOnly.length > 0
        ? { status: "fail" as const, severity: "high" as const }
        : cookieHints.sensitiveMissingSameSite.length > 0
          ? { status: "warning" as const, severity: "medium" as const }
          : { status: "pass" as const, severity: "info" as const };
  findings.push(
    buildSecurityCheck({
      checkKey: "session-handling-review",
      title: "Session handling review",
      scoreWeight: 1.4,
      ...sessionReviewStatus,
      shortDescription:
        cookieHints.sensitiveCookies.length === 0
          ? "No obvious session or auth cookies were detected in the sampled response."
          : sessionReviewStatus.status === "pass"
            ? "Sampled session-like cookies expose Secure, HttpOnly, and SameSite protections."
            : "Some sampled session-like cookies are missing one or more baseline protections.",
      whyItMatters:
        "Weak session cookie controls can enable session theft, cross-site reuse, or accidental exposure through weaker transport and browser contexts.",
      recommendation:
        sessionReviewStatus.status === "pass"
          ? "Keep session cookie scope and security flags tight."
          : "Ensure sensitive session cookies use Secure, HttpOnly, and a deliberate SameSite policy, and avoid over-broad domain or path scope.",
      evidence: {
        checkedUrl: primaryAttempt.finalUrl,
        expectedLocation: 'response.headers["set-cookie"] for auth/session cookies',
        summary:
          sessionReviewStatus.status === "pass"
            ? "Sensitive cookies were protected with the expected flags."
            : "At least one sensitive cookie was missing a baseline protection flag.",
        sensitiveCookies: cookieHints.sensitiveCookies.map((cookie) => cookie.name),
        missingSecure: cookieHints.sensitiveMissingSecure.map((cookie) => cookie.name),
        missingHttpOnly: cookieHints.sensitiveMissingHttpOnly.map((cookie) => cookie.name),
        missingSameSite: cookieHints.sensitiveMissingSameSite.map((cookie) => cookie.name),
      },
    }),
  );

  const inputProbeTargets = uniqueUrls([
    primaryPage.url,
    ...primaryPage.links
      .filter((link) => link.internal && (new URL(link.url).search.length > 0 || sensitivePathPattern.test(new URL(link.url).pathname)))
      .map((link) => link.url),
    ...discoveredApiEndpoints.filter((url) => {
      try {
        const parsed = new URL(url);
        return parsed.search.length > 0 || apiPathPattern.test(parsed.pathname);
      } catch {
        return false;
      }
    }),
    ...allKnownForms
      .filter((form) => form.method === "GET" || form.sensitiveKinds.includes("search"))
      .map((form) => form.url),
  ]);
  const inputProbeConfigs = uniqueUrls(
    [
      ...primaryPage.links
        .filter((link) => link.internal)
        .flatMap((link) =>
          [...new URL(link.url).searchParams.keys()]
            .filter((param) => riskyInputParamPattern.test(param))
            .map((param) => `${link.url}::${param}`),
        ),
      ...discoveredApiEndpoints.flatMap((url) =>
        [...new URL(url).searchParams.keys()]
          .filter((param) => riskyInputParamPattern.test(param))
          .map((param) => `${url}::${param}`),
      ),
      ...allKnownForms.flatMap((form) =>
        form.fieldNames
          .filter((name) => riskyInputParamPattern.test(name))
          .map((name) => `${form.url}::${name}`),
      ),
      ...["/search", "/api/search", "/api/products", "/rest/products/search"].map(
        (path) => `${primaryOrigin}${path}::q`,
      ),
      ...inputProbeTargets.slice(0, 2).map((url) => `${url}::q`),
    ].slice(0, 14),
  ).map((entry) => {
    const [url, parameter] = entry.split("::");
    return { url, parameter };
  });
  const reflectionToken = `cyberauditreflect${Date.now().toString(36)}`;
  const reflectionResults = (
    await mapLimited(inputProbeConfigs, 3, async (config) => {
      const url = new URL(config.url);
      url.searchParams.set(config.parameter, reflectionToken);
      const attempt = await loadAttempt(url.toString(), {
        timeoutMs: 8_000,
        followRedirects: false,
        headers: authHeadersFor(url.toString()),
      });
      if (!attempt || attempt.status >= 500 || !attempt.bodyText.includes(reflectionToken)) {
        return null;
      }

      const context = classifyReflectionContext(attempt.bodyText, reflectionToken);
      if (!context) {
        return null;
      }

      return {
        url: attempt.finalUrl,
        parameter: config.parameter,
        context,
        reflectedValue: reflectionToken,
      } satisfies ReflectionResult;
    })
  ).filter(isPresent);
  const reflectedInputStatus =
    reflectionResults.length === 0
      ? { status: "pass" as const, severity: "info" as const }
      : reflectionResults.some((result) => result.context === "script")
        ? { status: "fail" as const, severity: "high" as const }
        : reflectionResults.some((result) => result.context === "html" || result.context === "attribute")
          ? { status: "warning" as const, severity: "medium" as const }
          : { status: "info" as const, severity: "info" as const };
  findings.push(
    buildSecurityCheck({
      checkKey: "reflected-input-exposure",
      title: "Reflected input exposure",
      scoreWeight: 1.15,
      ...reflectedInputStatus,
      shortDescription:
        reflectionResults.length === 0
          ? "No sampled input token was reflected back in the tested responses."
          : `${reflectionResults.length} sampled input reflections were detected in the tested responses.`,
      whyItMatters:
        "Reflected input is not always exploitable by itself, but it is a strong indicator for XSS and output-encoding mistakes.",
      recommendation:
        reflectionResults.length === 0
          ? "Keep untrusted input encoded according to the output context."
          : "Review how reflected parameters are encoded in HTML, attribute, and script contexts before rendering them back to users.",
      evidence: {
        checkedUrl: inputProbeConfigs.map((config) => config.url).join(", "),
        expectedLocation: "Reflected query or form parameters in HTML responses",
        summary:
          reflectionResults.length === 0
            ? "No sampled reflection was detected."
            : "One or more sampled parameters were reflected back in the response.",
        reflectedParameters: reflectionResults.map((result) => ({
          url: result.url,
          parameter: result.parameter,
          context: result.context,
        })),
      },
    }),
  );

  const activeXssPayload = `"><svg data-fixnx-xss="1">`;
  const activeXssResults = (
    await mapLimited(inputProbeConfigs.slice(0, 8), 3, async (config) => {
      const url = new URL(config.url);
      url.searchParams.set(config.parameter, activeXssPayload);
      const attempt = await loadAttempt(url.toString(), {
        timeoutMs: 8_000,
        followRedirects: false,
        headers: authHeadersFor(url.toString()),
      });
      if (!attempt || attempt.status >= 500) {
        return null;
      }

      const rawPayloadReflected = attempt.bodyText.includes(activeXssPayload);
      if (!rawPayloadReflected) {
        return null;
      }

      return {
        url: attempt.finalUrl,
        parameter: config.parameter,
        status: attempt.status,
        rawPayloadReflected,
        context: classifyReflectionContext(attempt.bodyText, activeXssPayload),
      } satisfies ActiveXssProbeResult;
    })
  ).filter(isPresent);
  const activeXssFailure = activeXssResults.find(
    (result) => result.context && ["html", "attribute", "url-attribute", "script"].includes(result.context),
  );
  const browserXssExecutionResults = await runBrowserXssExecutionProbes(
    inputProbeConfigs.slice(0, 4),
    configuredAuthCookie,
  );
  const confirmedBrowserXss = browserXssExecutionResults.find((result) => result.executed);
  findings.push(
    buildSecurityCheck({
      checkKey: "active-xss-payload-reflection",
      title: "Active XSS exploit probe",
      scoreWeight: 1.4,
      status: confirmedBrowserXss || activeXssFailure ? "fail" : activeXssResults.length > 0 ? "warning" : "pass",
      severity: confirmedBrowserXss ? "critical" : activeXssFailure ? "high" : activeXssResults.length > 0 ? "medium" : "info",
      shortDescription: confirmedBrowserXss
        ? `A sampled XSS payload executed in a real browser on ${confirmedBrowserXss.url}.`
        : activeXssFailure
        ? `A sampled parameter reflected an HTML payload without clear output encoding on ${activeXssFailure.url}.`
        : activeXssResults.length > 0
          ? "A sampled XSS payload was reflected and should be reviewed for output encoding."
          : "Sampled XSS payloads were not reflected raw in tested responses.",
      whyItMatters:
        "A raw HTML payload reflected into markup, attributes, URLs, or script context is a concrete signal that XSS may be exploitable.",
      recommendation:
        activeXssResults.length === 0
          ? "Keep context-aware output encoding in place for all user-controlled input."
          : "Encode reflected values by output context, validate rich-text paths strictly, and add regression tests for the affected parameters.",
      evidence: {
        checkedUrl: inputProbeConfigs.slice(0, 8).map((config) => config.url).join(", "),
        expectedLocation: "Injected HTML payload should be encoded before rendering",
        summary: confirmedBrowserXss
            ? "The browser-side execution marker was set by the injected payload."
          : activeXssFailure
            ? "A raw HTML payload came back in an executable-capable context."
          : activeXssResults.length > 0
            ? "The payload was reflected raw, but the context needs manual confirmation."
            : "No raw active XSS payload reflection was detected.",
        probePayload: redactValue(activeXssPayload),
        browserExecution: browserXssExecutionResults.map((result) => ({
          url: result.url,
          parameter: result.parameter,
          status: result.status,
          executed: result.executed,
          payload: redactValue(result.payload),
        })),
        results: activeXssResults.map((result) => ({
          url: result.url,
          parameter: result.parameter,
          status: result.status,
          context: result.context,
        })),
      },
    }),
  );

  const dangerousDomSinks = [
    ...primaryPage.inlineScripts.flatMap((script) => detectDangerousDomSinks(script.content).map((sink) => ({
      source: primaryPage.url,
      sink,
      location: script.location,
    }))),
    ...firstPartyScriptSamples.flatMap((sample) => detectDangerousDomSinks(sample.bodyText).map((sink) => ({
      source: sample.url,
      sink,
      location: sample.location,
    }))),
  ];
  const hasAnyCspPolicy = Boolean(cspHeader || cspReportOnlyHeader);
  const dangerousReflectionDetected = reflectionResults.some((result) => result.context === "script");
  const elevatedReflectionDetected = reflectionResults.some(
    (result) => result.context === "html" || result.context === "attribute",
  );
  const activeXssDetected = Boolean(activeXssFailure || confirmedBrowserXss);
  const xssStatus =
    confirmedBrowserXss
      ? { status: "fail" as const, severity: "critical" as const }
    : activeXssDetected
      ? { status: "fail" as const, severity: "high" as const }
    : dangerousReflectionDetected && !hasAnyCspPolicy
      ? { status: "fail" as const, severity: "high" as const }
      : dangerousReflectionDetected || elevatedReflectionDetected || dangerousDomSinks.length > 0
        ? { status: "warning" as const, severity: "medium" as const }
        : { status: "pass" as const, severity: "info" as const };
  findings.push(
    buildSecurityCheck({
      checkKey: "xss-risk-indicators",
      title: "XSS evidence review",
      scoreWeight: 1.45,
      ...xssStatus,
      shortDescription:
        xssStatus.status === "pass"
          ? "The sampled HTML and JavaScript did not expose strong XSS indicators."
          : "The sampled HTML and JavaScript exposed reflection or DOM patterns that increase XSS risk.",
      whyItMatters:
        "XSS can enable session theft, UI tampering, data access, and user action forgery inside the victim's browser.",
      recommendation:
        xssStatus.status === "pass"
          ? "Keep using contextual output encoding and avoid unnecessary DOM injection APIs."
          : "Encode untrusted input by output context, avoid dangerous DOM injection sinks, and enforce a strong CSP where feasible.",
      evidence: {
        checkedUrl: primaryPage.url,
        expectedLocation: "Reflected input contexts, inline scripts, and sampled first-party JavaScript",
        summary:
          xssStatus.status === "pass"
            ? "No strong XSS indicators were detected in the sampled content."
            : "Reflection or dangerous DOM sinks were detected in sampled content.",
        cspEnforced: Boolean(cspHeader),
        cspReportOnly: Boolean(cspReportOnlyHeader),
        reflections: reflectionResults.map((result) => ({
          url: result.url,
          parameter: result.parameter,
          context: result.context,
        })),
        activePayloadReflections: activeXssResults.map((result) => ({
          url: result.url,
          parameter: result.parameter,
          context: result.context,
        })),
        browserExecutions: browserXssExecutionResults.map((result) => ({
          url: result.url,
          parameter: result.parameter,
          status: result.status,
          executed: result.executed,
        })),
        dangerousDomSinks: dangerousDomSinks.slice(0, 8).map((entry) => ({
          source: entry.source,
          sink: entry.sink,
          location: entry.location.path ?? entry.location.selector ?? null,
        })),
      },
    }),
  );

  const sqlProbeToken = "cyberaudit-sql-baseline";
  const sqlProbePayloads = ["'", "' OR '1'='1'--", "')) OR 1=1--", "' OR SLEEP(2)--"];
  const sqlProbeConfigs = inputProbeConfigs
    .filter((config) => riskyInputParamPattern.test(config.parameter))
    .slice(0, 6);
  const sqlProbeResults = (
    await mapLimited(sqlProbeConfigs, 2, async (config, configIndex) => {
      const baselineUrl = new URL(config.url);
      baselineUrl.searchParams.set(config.parameter, sqlProbeToken);
      const baselineAttempt = await loadAttempt(baselineUrl.toString(), {
        timeoutMs: 8_000,
        followRedirects: false,
        headers: authHeadersFor(baselineUrl.toString()),
      });
      const baselineRecordCount = baselineAttempt ? countStructuredRecords(baselineAttempt.bodyText) : null;

      return (
        await mapLimited(
          configIndex < 2
            ? sqlProbePayloads
            : sqlProbePayloads.filter((payload) => !/sleep/i.test(payload)),
          1,
          async (payload) => {
          const url = new URL(config.url);
          url.searchParams.set(config.parameter, payload);
          const attempt = await loadAttempt(url.toString(), {
            timeoutMs: 8_000,
            followRedirects: false,
            headers: authHeadersFor(url.toString()),
          });
          if (!attempt) {
            return null;
          }

          const probeRecordCount = countStructuredRecords(attempt.bodyText);
          const baselineDurationMs = baselineAttempt?.totalDurationMs ?? baselineAttempt?.durationMs ?? null;
          const probeDurationMs = attempt.totalDurationMs ?? attempt.durationMs ?? null;
          const recordExpansion =
            baselineRecordCount !== null &&
            probeRecordCount !== null &&
            probeRecordCount > baselineRecordCount &&
            probeRecordCount >= Math.max(3, baselineRecordCount + 3);
          const timeDelay =
            /sleep|benchmark|pg_sleep|waitfor/i.test(payload) &&
            baselineDurationMs !== null &&
            probeDurationMs !== null &&
            probeDurationMs - baselineDurationMs >= 1_600 &&
            probeDurationMs >= 1_900;

          return {
            url: attempt.finalUrl,
            parameter: config.parameter,
            payload,
            status: attempt.status,
            baselineStatus: baselineAttempt?.status ?? null,
            baselineDurationMs,
            probeDurationMs,
            sqlError: looksLikeSqlError(attempt.bodyText),
            serverError: attempt.status >= 500 && (baselineAttempt?.status ?? 200) < 500,
            baselineRecordCount,
            probeRecordCount,
            recordExpansion,
            timeDelay,
          } satisfies ActiveSqlProbeResult;
          },
        )
      ).filter(isPresent);
    })
  ).flat();
  const sqlErrorResult = sqlProbeResults.find((result) => result.sqlError || result.recordExpansion);
  const anomalousSqlResult = sqlProbeResults.find((result) => result.serverError);
  const timeBasedSqlResult = sqlProbeResults.find((result) => result.timeDelay);
  const sqlStatus = sqlErrorResult
    ? { status: "fail" as const, severity: "critical" as const }
    : timeBasedSqlResult
      ? { status: "warning" as const, severity: "high" as const }
    : anomalousSqlResult
      ? { status: "warning" as const, severity: "high" as const }
      : { status: "pass" as const, severity: "info" as const };
  findings.push(
    buildSecurityCheck({
      checkKey: "sql-injection-risk-indicators",
      title: "SQL injection active probe",
      scoreWeight: 1.6,
      ...sqlStatus,
      shortDescription: sqlErrorResult
        ? sqlErrorResult.sqlError
          ? `A sampled parameter on ${sqlErrorResult.url} triggered a database-like error response.`
          : `A SQL-style payload on ${sqlErrorResult.url} expanded the structured response from ${sqlErrorResult.baselineRecordCount ?? 0} to ${sqlErrorResult.probeRecordCount ?? 0} records.`
        : timeBasedSqlResult
          ? `A time-delay payload on ${timeBasedSqlResult.url} responded ${Math.max(0, (timeBasedSqlResult.probeDurationMs ?? 0) - (timeBasedSqlResult.baselineDurationMs ?? 0))} ms slower than baseline.`
        : anomalousSqlResult
          ? `A sampled parameter on ${anomalousSqlResult.url} triggered an unexpected server error.`
          : "Sampled input probes did not expose SQL injection indicators.",
      whyItMatters:
        "SQL injection can expose or modify backend data, bypass access controls, and compromise the application database.",
      recommendation:
        sqlStatus.status === "pass"
          ? "Keep query construction parameterized and avoid concatenating untrusted input into database queries."
          : "Review how search, filter, and ID parameters reach the backend, and ensure database access always uses parameterized queries with safe error handling.",
      evidence: {
        checkedUrl: sqlProbeConfigs.map((config) => config.url).join(", "),
        expectedLocation: "Search, filter, ID, and query parameters should not trigger SQL-like error behavior",
        summary:
          sqlStatus.status === "pass"
            ? "No SQL-like error patterns were detected in the sampled responses."
            : "At least one sampled response behaved like a SQL or backend query handling issue.",
        probePayloads: sqlProbePayloads.map((payload) => redactValue(payload)),
        results: sqlProbeResults.map((result) => ({
          url: result.url,
          parameter: result.parameter,
          payload: redactValue(result.payload),
          status: result.status,
          baselineStatus: result.baselineStatus,
          baselineDurationMs: result.baselineDurationMs,
          probeDurationMs: result.probeDurationMs,
          sqlError: result.sqlError,
          serverError: result.serverError,
          baselineRecordCount: result.baselineRecordCount,
          probeRecordCount: result.probeRecordCount,
          recordExpansion: result.recordExpansion,
          timeDelay: result.timeDelay,
        })),
        confidence: sqlErrorResult
          ? sqlErrorResult.recordExpansion
            ? "confirmed-response-difference"
            : "confirmed-error-based"
          : timeBasedSqlResult
            ? "suspected-time-based"
            : anomalousSqlResult
              ? "suspected-server-error"
              : "not-detected",
      },
    }),
  );

  const dbDisclosureResult = sqlProbeResults.find((result) => result.sqlError);
  const dbDisclosureStatus = dbDisclosureResult
    ? { status: "fail" as const, severity: "high" as const }
    : { status: "pass" as const, severity: "info" as const };
  findings.push(
    buildSecurityCheck({
      checkKey: "database-error-disclosure",
      title: "Database error disclosure",
      scoreWeight: 1.35,
      ...dbDisclosureStatus,
      shortDescription: dbDisclosureResult
        ? "A sampled response exposed a SQL or database-style error message."
        : "Sampled responses did not expose SQL or database error details.",
      whyItMatters:
        "Database and ORM error messages can reveal backend technologies, query structure, and internal implementation details that help an attacker refine exploitation attempts.",
      recommendation:
        dbDisclosureStatus.status === "pass"
          ? "Keep backend errors generic and avoid exposing stack traces or query details to the browser."
          : "Replace detailed database error responses with generic user-safe errors, and log the technical details only on the server.",
      evidence: {
        checkedUrl: dbDisclosureResult?.url ?? inputProbeConfigs.map((config) => config.url).join(", "),
        expectedLocation: "Browser responses should not expose SQL, ORM, or database exception details",
        summary:
          dbDisclosureStatus.status === "pass"
            ? "No sampled database error strings were exposed."
            : "A sampled response contained a database or SQL-style error indicator.",
      },
    }),
  );

  const authBypassPayloads = ["' OR '1'='1'--", "admin'--"];
  const authBypassTargets = uniqueUrls([
    ...authSurfaceAttempts.map((attempt) => attempt.finalUrl),
    ...discoveredApiEndpoints.filter((url) => /(login|signin|auth|session|user)/i.test(new URL(url).pathname)),
    `${primaryOrigin}/rest/user/login`,
    `${primaryOrigin}/api/login`,
    `${primaryOrigin}/login`,
  ]).slice(0, 4);
  const authBypassProbeResults = (
    await mapLimited(authBypassTargets, 2, async (targetUrl) => {
      return (
        await mapLimited(authBypassPayloads, 1, async (payload) => {
          const parsed = new URL(targetUrl);
          const apiLike = apiPathPattern.test(parsed.pathname) || /\/rest\//i.test(parsed.pathname);
          const body = apiLike
            ? JSON.stringify({
                email: payload,
                username: payload,
                password: "fixnx-auth-probe",
              })
            : new URLSearchParams({
                email: payload,
                username: payload,
                password: "fixnx-auth-probe",
              }).toString();
          const attempt = await loadAttempt(targetUrl, {
            method: "POST",
            timeoutMs: 8_000,
            followRedirects: false,
            headers: {
              "content-type": apiLike ? "application/json" : "application/x-www-form-urlencoded",
            },
            body,
          });
          if (!attempt) {
            return null;
          }

          const authSuccess = looksLikeAuthSuccessResponse(attempt);
          return {
            url: attempt.finalUrl,
            payload,
            status: attempt.status,
            ...authSuccess,
          } satisfies AuthBypassProbeResult;
        })
      ).filter(isPresent);
    })
  ).flat();
  const successfulAuthBypass = authBypassProbeResults.find((result) => result.authSuccess);
  const authBypassReachable = authBypassProbeResults.some((result) => result.status !== 404 && result.status < 500);
  findings.push(
    buildSecurityCheck({
      checkKey: "authentication-bypass-active-probe",
      title: "Authentication bypass active probe",
      scoreWeight: 1.55,
      status: successfulAuthBypass ? "fail" : authBypassReachable ? "pass" : "info",
      severity: successfulAuthBypass ? "critical" : "info",
      shortDescription: successfulAuthBypass
        ? `A sampled login endpoint returned an authentication success signal for a SQL-style bypass payload.`
        : authBypassReachable
          ? "Sampled login endpoints did not return token or session success signals for bypass payloads."
          : "No login endpoint was available for a cautious authentication bypass probe.",
      whyItMatters:
        "Authentication bypass lets an attacker access accounts without knowing a valid password and is usually a critical application flaw.",
      recommendation: successfulAuthBypass
        ? "Treat the affected login path as compromised: parameterize authentication queries, normalize credential handling, and add regression tests for SQL-style bypass payloads."
        : "Keep login handlers parameterized, rate-limited, and covered by negative tests for authentication bypass payloads.",
      evidence: {
        checkedUrl: authBypassTargets.join(", "),
        expectedLocation: "Login endpoints should reject SQL-style username/email bypass payloads",
        summary: successfulAuthBypass
          ? "A login probe returned a token-like body or session cookie after a bypass payload."
          : authBypassReachable
            ? "No sampled login endpoint returned an authentication success signal."
            : "No login endpoint candidate was found.",
        probePayloads: authBypassPayloads.map((payload) => redactValue(payload)),
        results: authBypassProbeResults.map((result) => ({
          url: result.url,
          payload: redactValue(result.payload),
          status: result.status,
          authSuccess: result.authSuccess,
          tokenLikeResponse: result.tokenLikeResponse,
          sessionCookie: result.sessionCookie,
        })),
      },
    }),
  );

  const idorCandidates = uniqueUrls(
    [
      ...primaryPage.links
        .filter((link) => link.internal)
        .map((link) => link.url),
      ...artifacts.crawledPages.flatMap((page) =>
        page.links.filter((link) => link.internal).map((link) => link.url),
      ),
      ...primaryPage.resources
        .filter((resource) => resource.internal && resource.kind === "fetch")
        .map((resource) => resource.url),
      ...discoveredApiEndpoints,
    ],
  )
    .map((url) => {
      const parsed = new URL(url);
      const hasSensitivePath = /(user|users|account|profile|invoice|order|download|file|document|report)/i.test(
        parsed.pathname,
      );
      const hasPredictableId =
        /\/(?:\d+|[0-9a-f]{8,}|[0-9a-f-]{16,})(?:\/|$)/i.test(parsed.pathname) ||
        [...parsed.searchParams.keys()].some((key) => /(id|userId|accountId|invoiceId|orderId|downloadId)/i.test(key));

      return {
        url,
        hasSensitivePath,
        hasPredictableId,
      };
    })
    .filter((candidate) => candidate.hasPredictableId)
    .slice(0, 8);
  const idorProbeResults = (
    await mapLimited(idorCandidates.slice(0, 4), 2, async (candidate) => {
      const mutatedUrl = mutationWithNextIdentifier(candidate.url);
      if (!mutatedUrl || mutatedUrl === candidate.url) {
        return null;
      }

      const [originalAttempt, mutatedAttempt, secondaryAttempt] = await Promise.all([
        loadAttempt(candidate.url, {
          timeoutMs: 8_000,
          followRedirects: false,
          headers: authHeadersFor(candidate.url),
        }),
        loadAttempt(mutatedUrl, {
          timeoutMs: 8_000,
          followRedirects: false,
          headers: authHeadersFor(mutatedUrl),
        }),
        secondaryAuthHeadersFor(candidate.url)
          ? loadAttempt(candidate.url, {
              timeoutMs: 8_000,
              followRedirects: false,
              headers: secondaryAuthHeadersFor(candidate.url),
            })
          : Promise.resolve(null),
      ]);
      if (!mutatedAttempt) {
        return null;
      }

      const originalContentType = originalAttempt?.headers["content-type"] ?? "";
      const mutatedContentType = mutatedAttempt.headers["content-type"] ?? "";
      const secondaryContentType = secondaryAttempt?.headers["content-type"] ?? "";
      const comparableResponse =
        mutatedAttempt.status >= 200 &&
        mutatedAttempt.status < 300 &&
        !isLikelyEdgeInterstitial(mutatedAttempt) &&
        (originalAttempt === null ||
          originalAttempt.status === mutatedAttempt.status ||
          (originalAttempt.status >= 200 && originalAttempt.status < 300)) &&
        (!originalContentType ||
          !mutatedContentType ||
          originalContentType.split(";")[0] === mutatedContentType.split(";")[0]);
      const crossUserAccess = Boolean(
        originalAttempt &&
          secondaryAttempt &&
          originalAttempt.status >= 200 &&
          originalAttempt.status < 300 &&
          secondaryAttempt.status >= 200 &&
          secondaryAttempt.status < 300 &&
          (!originalContentType ||
            !secondaryContentType ||
            originalContentType.split(";")[0] === secondaryContentType.split(";")[0]) &&
          !isLikelyEdgeInterstitial(secondaryAttempt),
      );

      return {
        originalUrl: candidate.url,
        mutatedUrl: mutatedAttempt.finalUrl,
        status: mutatedAttempt.status,
        originalStatus: originalAttempt?.status ?? null,
        secondaryStatus: secondaryAttempt?.status ?? null,
        contentType: mutatedAttempt.headers["content-type"] ?? null,
        comparableResponse,
        crossUserAccess,
      } satisfies IdorProbeResult;
    })
  ).filter(isPresent);
  const exposedIdorProbe = idorProbeResults.find((result) => result.comparableResponse || result.crossUserAccess);
  const confirmedIdorProbe = idorProbeResults.find((result) => result.crossUserAccess);
  const idorStatus =
    confirmedIdorProbe
      ? { status: "fail" as const, severity: "critical" as const }
    : exposedIdorProbe
      ? { status: "warning" as const, severity: "high" as const }
    : idorCandidates.length === 0
      ? { status: "pass" as const, severity: "info" as const }
      : idorCandidates.some((candidate) => candidate.hasSensitivePath)
        ? { status: "warning" as const, severity: "medium" as const }
        : { status: "info" as const, severity: "info" as const };
  findings.push(
    buildSecurityCheck({
      checkKey: "idor-risk-indicators",
      title: "IDOR authorization probe",
      scoreWeight: 1.3,
      ...idorStatus,
      shortDescription:
        confirmedIdorProbe
          ? `A secondary authenticated session could access ${confirmedIdorProbe.originalUrl}.`
        : exposedIdorProbe
          ? `Changing an object identifier returned a comparable successful response on ${exposedIdorProbe.mutatedUrl}.`
        : idorCandidates.length === 0
          ? "No obvious object-ID style URLs were detected in the sampled internal surface."
          : `${idorCandidates.length} sampled internal URLs look object-ID driven and may deserve an authorization review.`,
      whyItMatters:
        "IDOR issues happen when predictable object identifiers can be swapped to access other users' data without a proper authorization check.",
      recommendation:
        idorCandidates.length === 0
          ? "Keep enforcing object-level authorization on every user-scoped resource."
          : "Review object-level authorization on sampled ID-based routes such as users, invoices, orders, downloads, and reports.",
      evidence: {
        checkedUrl: idorCandidates.map((candidate) => candidate.url).join(", "),
        expectedLocation: "ID-based internal URLs should enforce object-level authorization",
        summary:
          confirmedIdorProbe
            ? "A cross-user authorization probe returned a successful comparable response."
          : exposedIdorProbe
            ? "A sampled object identifier could be changed and still returned a comparable successful response."
          : idorCandidates.length === 0
            ? "No strong IDOR-style URL patterns were found in the sampled links."
            : "ID-based internal URLs were found and should be reviewed for object-level access control.",
        candidates: idorCandidates,
        activeProbes: idorProbeResults,
        confidence: confirmedIdorProbe ? "confirmed-cross-user" : exposedIdorProbe ? "suspected-id-mutation" : "not-detected",
        secondarySessionProvided: Boolean(configuredSecondaryAuthCookie),
      },
    }),
  );

  const openRedirectProbeValue = "https://redirect.cyberaudit.invalid/landing";
  const openRedirectConfigs = uniqueUrls([
    ...primaryPage.links
      .filter((link) => link.internal && [...new URL(link.url).searchParams.keys()].some((param) => openRedirectParamPattern.test(param)))
      .map((link) => link.url),
    ...authSurfaceAttempts.map((attempt) => attempt.finalUrl),
  ])
    .slice(0, 4)
    .flatMap((url) => {
      const parsed = new URL(url);
      const knownParams = [...parsed.searchParams.keys()].filter((param) => openRedirectParamPattern.test(param));
      if (knownParams.length > 0) {
        return knownParams.map((parameter) => ({ url, parameter }));
      }

      return authSurfaceAttempts.some((attempt) => attempt.finalUrl === url)
        ? [{ url, parameter: "next" }]
        : [];
    });
  const openRedirectResults = (
    await mapLimited(openRedirectConfigs, 3, async (config) => {
      const url = new URL(config.url);
      url.searchParams.set(config.parameter, openRedirectProbeValue);
      const attempt = await loadAttempt(url.toString(), {
        timeoutMs: 8_000,
        followRedirects: false,
      });
      if (!attempt) {
        return null;
      }

      return {
        url: attempt.requestUrl,
        parameter: config.parameter,
        status: attempt.status,
        location: attempt.headers.location ?? "",
        resolvedLocation: resolveHttpUrl(attempt.headers.location, attempt.requestUrl),
        reflected: attempt.bodyText.includes(openRedirectProbeValue),
      };
    })
  ).filter(isPresent);
  const failingOpenRedirect = openRedirectResults.find((result) =>
    result.resolvedLocation?.startsWith(openRedirectProbeValue),
  );
  const externalRedirectProbe = openRedirectResults.find(
    (result) =>
      result.resolvedLocation &&
      !result.resolvedLocation.startsWith(primaryOrigin) &&
      !result.resolvedLocation.startsWith(openRedirectProbeValue),
  );
  const reflectedRedirectProbe = openRedirectResults.find((result) => result.reflected);
  const openRedirectStatus = failingOpenRedirect
    ? { status: "fail" as const, severity: "high" as const }
    : externalRedirectProbe
      ? { status: "warning" as const, severity: "medium" as const }
      : reflectedRedirectProbe
        ? { status: "info" as const, severity: "info" as const }
        : { status: "pass" as const, severity: "info" as const };
  findings.push(
    buildSecurityCheck({
      checkKey: "open-redirect-indicators",
      title: "Open redirect indicators",
      scoreWeight: 1.25,
      ...openRedirectStatus,
      shortDescription: failingOpenRedirect
        ? `A sampled redirect-style parameter on ${failingOpenRedirect.url} redirected to an external destination.`
        : externalRedirectProbe
          ? "A sampled redirect-style parameter influenced a redirect that leaves the scanned origin."
          : reflectedRedirectProbe
            ? "A sampled redirect-style parameter was reflected, but it did not produce an external redirect."
            : "Sampled redirect-style parameters did not produce an open redirect signal.",
      whyItMatters:
        "Open redirects help attackers build more convincing phishing flows and can sometimes be chained into broader authentication and access-control abuse.",
      recommendation:
        openRedirectStatus.status === "pass"
          ? "Keep redirect destinations validated against trusted internal paths or allowlists."
          : "Validate redirect targets strictly and reject untrusted external destinations, even when they arrive through familiar query parameters.",
      evidence: {
        checkedUrl: openRedirectConfigs.map((config) => config.url).join(", "),
        expectedLocation: "Redirect-style parameters should not send users to arbitrary external destinations",
        summary:
          openRedirectStatus.status === "pass"
            ? "No sampled open redirect signal was detected."
            : "At least one sampled redirect-style parameter influenced the response or redirect flow.",
        probeDestination: openRedirectProbeValue,
        results: openRedirectResults,
      },
    }),
  );

  const exposedSensitiveEndpoint = notableSensitiveEndpointAttempts.find((attempt) => {
    const pathname = new URL(attempt.url).pathname;
    return (
      isReachableSensitiveEndpoint(attempt) &&
      (/(debug|metrics|status)/i.test(pathname) ||
        (attempt.status >= 200 &&
          attempt.status < 300 &&
          /(admin|dashboard|export)/i.test(pathname)) ||
        (apiPathPattern.test(pathname) &&
          attempt.status >= 200 &&
          attempt.status < 300 &&
          !isHtmlLikeResponse(attempt.headers, attempt.bodyText) &&
          looksLikeStructuredApiPayload(attempt)))
    );
  });
  const visibleSensitiveEndpoint = notableSensitiveEndpointAttempts.find(
    (attempt) =>
      isReachableSensitiveEndpoint(attempt) &&
      attempt.status >= 200 &&
      attempt.status < 300 &&
      !/(login|signin|register|signup|password|reset|forgot|auth|account|accounts|session|identifier)/i.test(
        new URL(attempt.url).pathname,
      ) &&
      !looksLikePrimaryHtmlShell(primaryAttempt, attempt),
  );
  const protectedSensitiveEndpoint = notableSensitiveEndpointAttempts.find(
    (attempt) => [401, 403, 405].includes(attempt.status) || isProtectedSensitiveRedirect(attempt),
  );
  const sensitiveEndpointStatus =
    notableSensitiveEndpointAttempts.length === 0
      ? { status: "pass" as const, severity: "info" as const }
      : exposedSensitiveEndpoint
        ? { status: "fail" as const, severity: "high" as const }
        : visibleSensitiveEndpoint
          ? { status: "warning" as const, severity: "medium" as const }
          : protectedSensitiveEndpoint
            ? { status: "info" as const, severity: "info" as const }
            : { status: "pass" as const, severity: "info" as const };
  findings.push(
    buildSecurityCheck({
      checkKey: "sensitive-endpoint-discovery",
      title: "Sensitive endpoint discovery",
      scoreWeight: exposedSensitiveEndpoint ? 1.0 : 0.65,
      ...sensitiveEndpointStatus,
      shortDescription:
        notableSensitiveEndpointAttempts.length === 0
          ? "No sampled sensitive endpoint candidates returned a useful response."
          : exposedSensitiveEndpoint
            ? "A sampled high-risk endpoint returned a direct response and should be reviewed immediately."
            : visibleSensitiveEndpoint
              ? `${notableSensitiveEndpointAttempts.length} sampled non-auth sensitive endpoint candidates returned a reachable response worth reviewing.`
              : "Sensitive endpoint candidates were found, but the sampled behavior looked protected rather than openly exposed.",
      whyItMatters:
        "Admin panels, debug routes, exports, internal APIs, and account flows increase attack surface when they are publicly exposed or leak too much information.",
      recommendation:
        notableSensitiveEndpointAttempts.length === 0
          ? "Keep sensitive routes protected and hard to enumerate."
          : "Review sampled sensitive endpoints to ensure they require the intended authentication and do not expose unnecessary operational details.",
      evidence: {
        checkedUrl: sensitiveEndpointCandidates.map((candidate) => candidate.url).join(", "),
        expectedLocation: "Common auth, admin, API, debug, export, and status routes",
        summary:
          notableSensitiveEndpointAttempts.length === 0
            ? "No sensitive endpoint candidate returned a notable response."
            : "Some sensitive endpoint candidates were reachable or explicitly protected.",
        endpoints: notableSensitiveEndpointAttempts.map((attempt) => ({
          url: attempt.finalUrl,
          status: attempt.status,
          location: attempt.locationHeader || null,
          cacheControl: attempt.headers["cache-control"] ?? null,
          contentType: attempt.headers["content-type"] ?? null,
        })),
      },
    }),
  );

  const authForms = allKnownForms.filter(
    (form) => form.hasPasswordField || form.sensitiveKinds.some((kind) => ["login", "password-reset"].includes(kind)),
  );
  const authRouteMapSignals = [
    ...artifacts.browserInspection.routeMap.forms
      .filter((form) => form.sensitiveKinds.some((kind) => ["login", "password-reset", "account"].includes(kind)))
      .map((form) => form.url),
    ...artifacts.browserInspection.routeMap.buttons
      .filter((button) => button.sensitiveKinds.some((kind) => ["login", "password-reset", "account"].includes(kind)))
      .map((button) => `${button.sourceUrl}#${button.text}`),
    ...artifacts.browserInspection.routeMap.inputs
      .filter((input) =>
        input.sensitiveKinds.some((kind) => ["login", "password-reset", "account"].includes(kind)) ||
        /password|email|username|otp|token/i.test(`${input.name} ${input.type}`),
      )
      .map((input) => `${input.sourceUrl}#${input.name}`),
  ];
  const authSurfaceDetected =
    authForms.length > 0 ||
    authSurfaceAttempts.length > 0 ||
    Boolean(successfulAuthBypass) ||
    authRouteMapSignals.length > 0;
  const authReviewStatus =
    successfulAuthBypass
      ? { status: "fail" as const, severity: "critical" as const }
    : !authSurfaceDetected
      ? { status: "info" as const, severity: "info" as const }
      : authForms.some((form) => !form.secure)
        ? { status: "fail" as const, severity: "high" as const }
        : cookieHints.sensitiveMissingSecure.length > 0 || cookieHints.sensitiveMissingHttpOnly.length > 0
          ? { status: "warning" as const, severity: "medium" as const }
          : clickjackingStatus.status !== "pass" || unprotectedAuthLikeForms.length > 0
            ? { status: "warning" as const, severity: "medium" as const }
          : { status: "pass" as const, severity: "info" as const };
  findings.push(
    buildSecurityCheck({
      checkKey: "authentication-surface-review",
      title: "Authentication surface review",
      scoreWeight: authReviewStatus.status === "fail" ? 1.0 : 0.75,
      ...authReviewStatus,
      shortDescription:
        successfulAuthBypass
          ? "Authentication surface was detected and one active bypass probe returned an authentication success signal."
        : !authSurfaceDetected
          ? "No authentication forms or routes were detected in the sampled surface."
          : authReviewStatus.status === "pass"
            ? "Sampled authentication surfaces look protected by HTTPS and baseline browser controls."
            : "Sampled authentication surfaces expose one or more baseline weaknesses.",
      whyItMatters:
        "Login, reset, and account-recovery surfaces are frequent attack targets and need stronger-than-average hardening.",
      recommendation:
        authReviewStatus.status === "pass"
          ? "Keep authentication flows protected by HTTPS, strong session cookies, and iframe restrictions."
          : "Harden authentication routes with HTTPS-only delivery, secure session cookies, anti-clickjacking controls, and explicit CSRF protection where applicable.",
      evidence: {
        checkedUrl: uniqueUrls([
          ...authSurfaceAttempts.map((attempt) => attempt.finalUrl),
          ...authForms.map((form) => form.url),
          ...authRouteMapSignals,
          ...authBypassTargets,
        ]).join(", "),
        expectedLocation: "Login, reset, and account-recovery routes and forms",
        summary:
          successfulAuthBypass
            ? "An active authentication bypass result confirms that authentication routes exist and require urgent review."
          : authReviewStatus.status === "pass"
            ? "Sampled auth surfaces looked reasonably hardened."
            : "At least one sampled auth surface lacked a baseline control.",
        authRouteCount: authSurfaceAttempts.length,
        passwordFormCount: authForms.length,
        routeMapSignals: authRouteMapSignals.slice(0, 12),
        authBypassProbeStatus: successfulAuthBypass ? "confirmed" : authBypassReachable ? "tested" : "not-tested",
        clickjackingStatus: clickjackingStatus.status,
      },
    }),
  );

  const passwordForms = authForms.filter((form) => form.hasPasswordField);
  const passwordFieldStatus =
    passwordForms.length === 0
      ? { status: "info" as const, severity: "info" as const }
      : passwordForms.some((form) => !form.secure)
        ? { status: "fail" as const, severity: "high" as const }
        : clickjackingStatus.status !== "pass"
          ? { status: "warning" as const, severity: "medium" as const }
        : passwordForms.some(
              (form) =>
                !form.autocompleteHints.some((hint) =>
                  /current-password|new-password|one-time-code/i.test(hint),
                ),
            )
          ? { status: "warning" as const, severity: "low" as const }
          : { status: "pass" as const, severity: "info" as const };
  findings.push(
    buildSecurityCheck({
      checkKey: "password-field-security",
      title: "Password field security",
      scoreWeight: passwordFieldStatus.status === "fail" ? 1.0 : 0.7,
      ...passwordFieldStatus,
      shortDescription:
        passwordForms.length === 0
          ? "No password fields were detected on the sampled pages."
          : passwordFieldStatus.status === "pass"
            ? "Sampled password forms are delivered over HTTPS and expose baseline embedding protections."
            : "Sampled password forms expose missing or weaker-than-expected baseline protections.",
      whyItMatters:
        "Password entry points must be protected against insecure transport, hostile framing, and weak browser form handling.",
      recommendation:
        passwordFieldStatus.status === "pass"
          ? "Keep password forms on HTTPS-only pages with tight embedding controls."
          : "Ensure password fields load only over HTTPS, submit to secure same-origin actions, and are protected from framing and weak form behavior.",
      evidence: {
        checkedUrl: passwordForms.map((form) => form.url).join(", "),
        expectedLocation: "Forms containing password inputs",
        summary:
          passwordForms.length === 0
            ? "No password inputs were found."
            : "Password forms were evaluated for HTTPS, action security, and baseline browser controls.",
        passwordForms: passwordForms.map((form) => ({
          url: form.url,
          method: form.method,
          secure: form.secure,
          autocompleteHints: form.autocompleteHints,
        })),
      },
    }),
  );

  const uploadForms = allKnownForms.filter((form) => form.hasFileUpload || form.sensitiveKinds.includes("upload"));
  const uploadStatus =
    uploadForms.length === 0 && uploadSurfaceAttempts.length === 0
      ? { status: "info" as const, severity: "info" as const }
      : uploadForms.some((form) => !form.secure)
        ? { status: "fail" as const, severity: "high" as const }
        : uploadForms.some((form) => form.csrfFieldNames.length === 0 && !metaCsrfTokenPresent)
          ? { status: "warning" as const, severity: "medium" as const }
          : { status: "info" as const, severity: "info" as const };
  findings.push(
    buildSecurityCheck({
      checkKey: "file-upload-risk-indicators",
      title: "File upload risk indicators",
      scoreWeight: 1.2,
      ...uploadStatus,
      shortDescription:
        uploadForms.length === 0 && uploadSurfaceAttempts.length === 0
          ? "No file upload surface was detected in the sampled pages."
          : `${uploadForms.length} upload form signals and ${uploadSurfaceAttempts.length} upload routes were detected.`,
      whyItMatters:
        "Upload flows can become a high-risk surface when they allow unsafe file handling, weak validation, or insufficient request protections.",
      recommendation:
        uploadStatus.status === "info"
          ? "If upload flows exist elsewhere, keep validating files server-side and protect upload requests like any other sensitive action."
          : "Protect upload forms with same-origin HTTPS actions, explicit request protections, and strong server-side file validation.",
      evidence: {
        checkedUrl: [...uploadForms.map((form) => form.url), ...uploadSurfaceAttempts.map((attempt) => attempt.finalUrl)].join(", "),
        expectedLocation: "multipart forms and upload-oriented endpoints",
        summary:
          uploadForms.length === 0 && uploadSurfaceAttempts.length === 0
            ? "No upload-oriented form or route was detected."
            : "Upload-oriented surfaces were detected and reviewed for basic protection hints.",
      },
    }),
  );

  const apiExposureSignals = apiSurfaceAttempts
    .filter(
      (attempt) =>
        attempt.status < 400 &&
        !isLikelyEdgeInterstitial(attempt) &&
        !isHtmlLikeResponse(attempt.headers, attempt.bodyText) &&
        looksLikeStructuredApiPayload(attempt),
    )
    .map((attempt) => ({
      url: attempt.finalUrl,
      sensitiveResponse: looksLikeSensitiveApiPayload(attempt.bodyText),
      contentType: attempt.headers["content-type"] ?? "",
    }));
  const apiExposureStatus =
    apiExposureSignals.some((signal) => signal.sensitiveResponse)
      ? { status: "fail" as const, severity: "high" as const }
      : apiExposureSignals.length > 0
        ? { status: "warning" as const, severity: "medium" as const }
        : discoveredApiEndpoints.length > 0
          ? { status: "info" as const, severity: "info" as const }
          : { status: "pass" as const, severity: "info" as const };
  findings.push(
    buildSecurityCheck({
      checkKey: "api-exposure-review",
      title: "API exposure review",
      scoreWeight: 1.3,
      ...apiExposureStatus,
      shortDescription:
        apiExposureSignals.some((signal) => signal.sensitiveResponse)
          ? "A sampled API-like endpoint returned data patterns that look sensitive."
          : apiExposureSignals.length > 0
            ? `${apiExposureSignals.length} sampled API-like endpoints were reachable and should be reviewed.`
            : discoveredApiEndpoints.length > 0
              ? "API-like endpoints were discovered in the frontend surface."
              : "No strong API exposure signal was detected in the sampled surface.",
      whyItMatters:
        "Exposed APIs can leak sensitive data, widen the public attack surface, or make authorization mistakes easier to find.",
      recommendation:
        apiExposureStatus.status === "pass"
          ? "Keep public APIs scoped to the data and methods that are intentionally exposed."
          : "Review reachable API endpoints for authentication, authorization, and response data minimization.",
      evidence: {
        checkedUrl: uniqueUrls([...discoveredApiEndpoints, ...apiSurfaceAttempts.map((attempt) => attempt.finalUrl)]).join(", "),
        expectedLocation: "Frontend-discovered API, GraphQL, AJAX, RPC, and REST endpoints",
        summary:
          apiExposureStatus.status === "pass"
            ? "No reachable API surface with suspicious response data was detected."
            : "Some API-like endpoints were discovered or reachable and should be reviewed.",
        endpoints: apiExposureSignals,
      },
    }),
  );

  const graphqlTarget =
    uniqueUrls([
      ...apiSurfaceAttempts
        .filter((attempt) => /graphql/i.test(new URL(attempt.url).pathname))
        .map((attempt) => attempt.finalUrl),
      `${primaryOrigin}/graphql`,
    ])[0] ?? null;
  let graphqlProbe:
    | {
        status: number;
        bodyText: string;
        introspectionOpen: boolean;
        reachable: boolean;
        protected: boolean;
      }
    | null = null;
  if (graphqlTarget) {
    const baseProbe = await loadAttempt(graphqlTarget, {
      method: "POST",
      timeoutMs: 8_000,
      headers: {
        "content-type": "application/json",
      },
        body: JSON.stringify({
          query: "query { __typename }",
        }),
      });
    if (baseProbe) {
      const introspectionProbe = await loadAttempt(graphqlTarget, {
        method: "POST",
        timeoutMs: 8_000,
        headers: {
          "content-type": "application/json",
        },
        body: JSON.stringify({
          query: "query IntrospectionQuery { __schema { queryType { name } } }",
        }),
      });
      graphqlProbe = {
        status: introspectionProbe?.status ?? baseProbe.status,
        bodyText: (introspectionProbe?.bodyText || baseProbe.bodyText || "").slice(0, 4_000),
        introspectionOpen: Boolean(introspectionProbe?.bodyText.includes("__schema")),
        reachable:
          baseProbe.status !== 404 &&
          baseProbe.status < 500 &&
          !isLikelyEdgeInterstitial(baseProbe) &&
          (baseProbe.status === 405 ||
            (!isHtmlLikeResponse(baseProbe.headers, baseProbe.bodyText) && looksLikeStructuredApiPayload(baseProbe))),
        protected:
          isLikelyEdgeInterstitial(baseProbe) ||
          [401, 403].includes(baseProbe.status) ||
          baseProbe.status === 405,
      };
    }
  }
  const graphqlStatus =
    !graphqlTarget || !graphqlProbe?.reachable
      ? { status: "pass" as const, severity: "info" as const }
    : graphqlProbe?.introspectionOpen
        ? { status: "fail" as const, severity: "high" as const }
        : graphqlProbe.protected
          ? { status: "info" as const, severity: "info" as const }
        : graphqlProbe.status < 500
          ? { status: "warning" as const, severity: "medium" as const }
          : { status: "pass" as const, severity: "info" as const };
  findings.push(
    buildSecurityCheck({
      checkKey: "graphql-exposure",
      title: "GraphQL exposure",
      scoreWeight: 1.2,
      ...graphqlStatus,
      shortDescription:
        !graphqlTarget || !graphqlProbe?.reachable
          ? "No GraphQL endpoint was detected in the sampled surface."
        : graphqlProbe?.introspectionOpen
            ? "The sampled GraphQL endpoint appears to expose introspection without a visible protection layer."
            : graphqlProbe.protected
              ? "A GraphQL-like endpoint was present, but the sampled response looked intentionally protected."
            : graphqlProbe
              ? "A GraphQL-like endpoint was reachable and should be reviewed."
              : "The sampled GraphQL endpoint was not reachable.",
      whyItMatters:
        "Public GraphQL endpoints can expose internal schema details and expand the application's query surface if left too open.",
      recommendation:
        !graphqlTarget || graphqlStatus.status === "pass"
          ? "Keep GraphQL protected behind the intended authentication and schema exposure rules."
          : "Review GraphQL authentication and consider disabling or restricting introspection on production endpoints that should not disclose schema details.",
      evidence: {
        checkedUrl: graphqlTarget ?? primaryOrigin,
        expectedLocation: "/graphql and GraphQL-like frontend-discovered endpoints",
        summary:
          !graphqlTarget || !graphqlProbe?.reachable
            ? "No GraphQL endpoint was found."
          : graphqlProbe?.introspectionOpen
              ? "The sampled GraphQL endpoint appeared to disclose introspection data."
              : graphqlProbe.protected
                ? "A GraphQL endpoint was detected, but access looked intentionally restricted."
              : "A GraphQL endpoint was detected or probed.",
        introspectionOpen: graphqlProbe?.introspectionOpen ?? false,
        statusCode: graphqlProbe?.status ?? null,
      },
    }),
  );

  const highRiskRateLimitTarget = authSurfaceAttempts.find(isReachableSensitiveEndpoint)?.finalUrl ?? apiSurfaceAttempts[0]?.finalUrl ?? null;
  const searchRateLimitTarget = primaryPage.links.find((link) => link.internal && /search|query|q=/i.test(link.url))?.url ?? null;
  const rateLimitTarget = highRiskRateLimitTarget ?? searchRateLimitTarget;
  const rateLimitProbeScope = highRiskRateLimitTarget ? "sensitive" : searchRateLimitTarget ? "search" : "none";
  const rateLimitAttempts = rateLimitTarget
    ? await mapLimited([1, 2, 3], 1, async (iteration) => {
        const url = new URL(rateLimitTarget);
        url.searchParams.set("cyberaudit_rate_probe", String(iteration));
        const attempt = await loadAttempt(url.toString(), {
          timeoutMs: 8_000,
          followRedirects: false,
        });
        return attempt;
      })
    : [];
  const rateLimitSignals = rateLimitAttempts.flatMap((attempt) => {
    if (!attempt) {
      return [];
    }

    const headers = Object.fromEntries(
      Object.entries(attempt.headers).filter(([name]) => /ratelimit|retry-after|x-ratelimit/i.test(name)),
    );
    return Object.keys(headers).length > 0 || attempt.status === 429
      ? [{ status: attempt.status, headers }]
      : [];
  });
  const rateLimitStatus =
    !rateLimitTarget
      ? { status: "info" as const, severity: "info" as const }
      : rateLimitSignals.length > 0
        ? { status: "pass" as const, severity: "info" as const }
        : { status: "info" as const, severity: "info" as const };
  findings.push(
    buildSecurityCheck({
      checkKey: "rate-limiting-indicators",
      title: "Rate limiting indicators",
      scoreWeight: 0.4,
      ...rateLimitStatus,
      shortDescription:
        !rateLimitTarget
          ? "No obvious auth, API, or search endpoint was available for a cautious rate-limit probe."
        : rateLimitSignals.length > 0
          ? "The sampled sensitive endpoint exposed headers or responses that suggest rate limiting."
          : rateLimitProbeScope === "sensitive"
            ? "The sampled sensitive endpoint did not expose a clear rate-limiting signal during a cautious probe."
            : "Only a generic search-style endpoint was available, so no strong rate-limit conclusion was made.",
      whyItMatters:
        "Rate limiting helps reduce brute-force, spam, and high-frequency abuse on login, reset, search, and API endpoints.",
      recommendation:
        !rateLimitTarget || rateLimitSignals.length > 0
          ? "Keep rate limiting and abuse detection visible on sensitive routes."
          : "Add visible rate-limit controls, headers, or abuse protections on sensitive routes such as login, reset, search, and API endpoints.",
      evidence: {
        checkedUrl: rateLimitTarget ?? primaryOrigin,
        expectedLocation: "RateLimit, Retry-After, or x-ratelimit response headers on sensitive endpoints",
        summary:
          !rateLimitTarget
            ? "No suitable endpoint was found for a cautious rate-limit check."
          : rateLimitSignals.length > 0
            ? "A sampled endpoint exposed rate-limit signals."
            : rateLimitProbeScope === "sensitive"
              ? "No visible rate-limit signal was detected during the cautious probe."
              : "No high-risk endpoint was available for a meaningful rate-limit assessment.",
        probeScope: rateLimitProbeScope,
        signals: rateLimitSignals,
      },
    }),
  );

  const missingRouteAttempt = await loadAttempt(`${primaryOrigin}/cyberaudit-not-found-${Date.now().toString(36)}`, {
    timeoutMs: 8_000,
    followRedirects: false,
  });
  const invalidInputAttempt = await loadAttempt(`${primaryPage.url}${primaryPage.url.includes("?") ? "&" : "?"}cyberaudit_invalid=%27%22%3C%3E`, {
    timeoutMs: 8_000,
    followRedirects: false,
  });
  const verboseErrorAttempt = [missingRouteAttempt, invalidInputAttempt].find(
    (attempt) =>
      attempt &&
      (looksLikeSqlError(attempt.bodyText) ||
        strongVerboseErrorPatterns.some((pattern) => pattern.test(attempt.bodyText)) ||
        (attempt.status >= 500 && looksLikeVerboseError(attempt.bodyText))),
  );
  const errorHandlingStatus = verboseErrorAttempt
    ? { status: "fail" as const, severity: "high" as const }
    : [missingRouteAttempt, invalidInputAttempt].some((attempt) => attempt && attempt.status >= 500)
      ? { status: "warning" as const, severity: "medium" as const }
      : { status: "pass" as const, severity: "info" as const };
  findings.push(
    buildSecurityCheck({
      checkKey: "error-handling-hardening",
      title: "Error handling hardening",
      scoreWeight: 1.2,
      ...errorHandlingStatus,
      shortDescription: verboseErrorAttempt
        ? "A sampled error path exposed verbose backend details."
        : "Sampled invalid paths and inputs returned generic or low-detail error behavior.",
      whyItMatters:
        "Verbose errors reveal framework, package, path, and backend implementation details that help attackers refine later attacks.",
      recommendation:
        errorHandlingStatus.status === "pass"
          ? "Keep error responses generic in production and log technical details only server-side."
          : "Remove stack traces, framework paths, and backend error details from browser responses, and return generic production-safe messages instead.",
      evidence: {
        checkedUrl: [missingRouteAttempt?.finalUrl, invalidInputAttempt?.finalUrl].filter(Boolean).join(", "),
        expectedLocation: "Invalid routes and malformed inputs should not expose stack traces or internal backend errors",
        summary:
          errorHandlingStatus.status === "pass"
            ? "Sampled error responses stayed generic."
            : "At least one sampled error response exposed too much detail.",
        verboseErrorDetected: Boolean(verboseErrorAttempt),
      },
    }),
  );

  const cacheSensitiveAttempts = notableSensitiveEndpointAttempts.filter(
    (attempt) =>
      isReachableSensitiveEndpoint(attempt) &&
      /(account|profile|dashboard|invoice|billing|payment|admin|export)/i.test(new URL(attempt.url).pathname),
  );
  const dangerouslyCachedAttempt = cacheSensitiveAttempts.find((attempt) =>
    /\bpublic\b|\bmax-age=\d{2,}\b/i.test(attempt.headers["cache-control"] ?? ""),
  );
  const unclearCachedAttempt = cacheSensitiveAttempts.find(
    (attempt) => !(attempt.headers["cache-control"] ?? "").match(/no-store|no-cache|private|max-age=0/i),
  );
  const cacheSensitiveStatus =
    cacheSensitiveAttempts.length === 0
      ? { status: "info" as const, severity: "info" as const }
      : dangerouslyCachedAttempt
        ? { status: "fail" as const, severity: "high" as const }
        : unclearCachedAttempt
          ? { status: "warning" as const, severity: "medium" as const }
          : { status: "pass" as const, severity: "info" as const };
  findings.push(
    buildSecurityCheck({
      checkKey: "cache-control-sensitive-pages",
      title: "Cache-Control on sensitive pages",
      scoreWeight: 1.25,
      ...cacheSensitiveStatus,
      shortDescription:
        cacheSensitiveAttempts.length === 0
          ? "No sensitive page was detected for cache header review."
          : cacheSensitiveStatus.status === "pass"
            ? "Sampled sensitive pages expose conservative cache controls."
            : "At least one sampled sensitive page exposes unclear or risky cache behavior.",
      whyItMatters:
        "Sensitive pages should not be cached in a way that leaks account, billing, or dashboard data to other users or intermediaries.",
      recommendation:
        cacheSensitiveAttempts.length === 0 || cacheSensitiveStatus.status === "pass"
          ? "Keep sensitive responses private and non-cacheable unless a stronger model is explicitly intended."
          : "Use `Cache-Control: no-store` or equivalent conservative directives on sensitive account, admin, export, billing, and dashboard pages.",
      evidence: {
        checkedUrl: cacheSensitiveAttempts.map((attempt) => attempt.finalUrl).join(", "),
        expectedLocation: 'response.headers["cache-control"], ["pragma"], ["expires"] on sensitive pages',
        summary:
          cacheSensitiveAttempts.length === 0
            ? "No sensitive page was available for cache review."
            : "Sensitive page cache headers were reviewed.",
        pages: cacheSensitiveAttempts.map((attempt) => ({
          url: attempt.finalUrl,
          status: attempt.status,
          cacheControl: attempt.headers["cache-control"] ?? null,
          pragma: attempt.headers.pragma ?? null,
          expires: attempt.headers.expires ?? null,
        })),
      },
    }),
  );

  const optionsAttempt = await loadAttempt(primaryOrigin, {
    method: "OPTIONS",
    includeBody: false,
    timeoutMs: 8_000,
    followRedirects: false,
  });
  const allowedMethods = (optionsAttempt?.headers.allow || optionsAttempt?.headers["access-control-allow-methods"] || "")
    .split(",")
    .map((method) => method.trim().toUpperCase())
    .filter(Boolean);
  const dangerousMethods = allowedMethods.filter((method) => ["PUT", "DELETE", "PATCH", "TRACE"].includes(method));
  const methodsStatus =
    dangerousMethods.includes("TRACE")
      ? { status: "fail" as const, severity: "medium" as const }
      : dangerousMethods.length > 0
        ? { status: "warning" as const, severity: "medium" as const }
        : { status: "pass" as const, severity: "info" as const };
  findings.push(
    buildSecurityCheck({
      checkKey: "dangerous-methods-exposure",
      title: "Dangerous methods exposure",
      scoreWeight: 1.0,
      ...methodsStatus,
      shortDescription:
        allowedMethods.length === 0
          ? "No unusual HTTP methods were advertised on the sampled origin."
          : `${allowedMethods.join(", ")} were advertised on the sampled origin.`,
      whyItMatters:
        "Exposing unnecessary HTTP methods can widen the attack surface and make method-specific weaknesses easier to exploit.",
      recommendation:
        dangerousMethods.length === 0
          ? "Keep only the HTTP methods the application actually needs."
          : "Disable or tightly scope unnecessary methods such as PUT, DELETE, PATCH, and TRACE on public routes.",
      evidence: {
        checkedUrl: primaryOrigin,
        expectedLocation: 'response.headers["allow"] or ["access-control-allow-methods"]',
        summary:
          allowedMethods.length === 0
            ? "No method advertisement was found on the sampled origin."
            : "The sampled origin advertised one or more HTTP methods.",
        allow: allowedMethods,
      },
    }),
  );

  const traceAttempt = await loadAttempt(primaryOrigin, {
    method: "TRACE",
    timeoutMs: 8_000,
    followRedirects: false,
  });
  const traceStatus =
    traceAttempt && traceAttempt.status < 400
      ? { status: "fail" as const, severity: "medium" as const }
      : { status: "pass" as const, severity: "info" as const };
  findings.push(
    buildSecurityCheck({
      checkKey: "trace-method-enabled",
      title: "TRACE method enabled",
      scoreWeight: 1.0,
      ...traceStatus,
      shortDescription:
        traceAttempt && traceAttempt.status < 400
          ? `TRACE returned status ${traceAttempt.status} on the sampled origin.`
          : "TRACE did not appear to be enabled on the sampled origin.",
      whyItMatters:
        "TRACE is usually unnecessary on public applications and can contribute to method abuse or proxy misconfigurations.",
      recommendation:
        traceAttempt && traceAttempt.status < 400
          ? "Disable TRACE on the public origin unless there is a very specific operational need for it."
          : "Keep TRACE disabled on public routes.",
      evidence: {
        checkedUrl: primaryOrigin,
        expectedLocation: "TRACE should be blocked or disabled on the public origin",
        summary:
          traceAttempt && traceAttempt.status < 400
            ? "The origin responded successfully to TRACE."
            : "TRACE did not return a successful response.",
        statusCode: traceAttempt?.status ?? null,
      },
    }),
  );

  const hostTrustProbeHost = "attacker.cyberaudit.invalid";
  const hostTrustAttempt = await loadAttempt(primaryOrigin, {
    timeoutMs: 8_000,
    followRedirects: false,
    headers: {
      Origin: `https://${hostTrustProbeHost}`,
      "X-Forwarded-Host": hostTrustProbeHost,
      Forwarded: `host=${hostTrustProbeHost};proto=https`,
    },
  });
  const hostReflectionDetected = Boolean(
    hostTrustAttempt &&
      ((hostTrustAttempt.headers.location ?? "").includes(hostTrustProbeHost) ||
        hostTrustAttempt.bodyText.includes(hostTrustProbeHost)),
  );
  const hostTrustStatus = hostReflectionDetected
    ? { status: "fail" as const, severity: "high" as const }
    : { status: "pass" as const, severity: "info" as const };
  findings.push(
    buildSecurityCheck({
      checkKey: "host-origin-trust-indicators",
      title: "Host header / origin trust indicators",
      scoreWeight: 1.2,
      ...hostTrustStatus,
      shortDescription: hostReflectionDetected
        ? "A sampled response reflected an attacker-controlled host hint."
        : "Sampled responses did not reflect attacker-controlled host or origin hints.",
      whyItMatters:
        "Over-trusting Host or forwarded origin headers can enable password-reset poisoning, unsafe absolute URL generation, and redirect confusion.",
      recommendation:
        hostTrustStatus.status === "pass"
          ? "Keep host and forwarded-origin handling tied to trusted proxy settings only."
          : "Ignore or strictly validate forwarded host and origin headers, and generate absolute URLs from trusted server-side configuration only.",
      evidence: {
        checkedUrl: primaryOrigin,
        expectedLocation: "Location headers and absolute URLs should not trust unvalidated forwarded host or origin headers",
        summary:
          hostTrustStatus.status === "pass"
            ? "No unsafe host reflection was detected."
            : "An attacker-controlled host value appeared to influence the response.",
        reflectedHost: hostReflectionDetected ? hostTrustProbeHost : null,
      },
    }),
  );

  const sensitiveContentFindings = [
    ...detectSensitiveDataExposure(primaryAttempt.bodyText, "primary HTML"),
    ...firstPartyScriptSamples.flatMap((sample) =>
      detectSensitiveDataExposure(sample.bodyText, sample.url),
    ),
  ];
  const sensitiveDataStatus =
    sensitiveContentFindings.some((match) => match.severity === "critical" || match.severity === "high")
      ? { status: "fail" as const, severity: "high" as const }
      : sensitiveContentFindings.length > 0
        ? { status: "warning" as const, severity: "medium" as const }
        : { status: "pass" as const, severity: "info" as const };
  findings.push(
    buildSecurityCheck({
      checkKey: "sensitive-data-exposure-html-js",
      title: "Sensitive data exposure in HTML / JS",
      scoreWeight: 1.45,
      ...sensitiveDataStatus,
      shortDescription:
        sensitiveContentFindings.length === 0
          ? "No obvious sensitive data exposure was detected in sampled HTML and first-party JavaScript."
          : `${sensitiveContentFindings.length} sampled sensitive-data exposure signals were detected in HTML or JavaScript.`,
      whyItMatters:
        "Secrets, internal URLs, debug data, and token-like values in client-visible content can leak implementation details or credentials to any visitor.",
      recommendation:
        sensitiveContentFindings.length === 0
          ? "Keep secrets and internal configuration out of client-visible HTML and JavaScript."
          : "Remove secrets from client-visible code, redact internal-only configuration, and move sensitive values behind authenticated server-side boundaries.",
      evidence: {
        checkedUrl: [primaryPage.url, ...firstPartyScriptSamples.map((sample) => sample.url)].join(", "),
        expectedLocation: "Client-visible HTML and first-party JavaScript should not expose secrets or internal-only configuration",
        summary:
          sensitiveContentFindings.length === 0
            ? "No obvious sensitive client-side exposure was detected."
            : "One or more client-visible content blocks exposed potentially sensitive information.",
        matches: sensitiveContentFindings.slice(0, 8),
      },
    }),
  );

  const insecureResources = primaryPage.resources.filter((resource) => !resource.secure);
  const activeMixedContent = insecureResources.filter((resource) =>
    ["script", "stylesheet", "iframe", "form"].includes(resource.kind),
  );
  findings.push(
    buildSecurityCheck({
      checkKey: "mixed-content",
      title: "Mixed content",
      status: insecureResources.length === 0 ? "pass" : activeMixedContent.length > 0 ? "fail" : "warning",
      severity: insecureResources.length === 0 ? "info" : activeMixedContent.length > 0 ? "medium" : "low",
      shortDescription:
        insecureResources.length === 0
          ? "No HTTP resources were referenced from the HTTPS page."
          : `${insecureResources.length} HTTP resources were referenced from the HTTPS page.`,
      whyItMatters:
        "Mixed content weakens the HTTPS trust boundary and can trigger blocking or downgrade behavior in browsers.",
      recommendation:
        insecureResources.length === 0
          ? "Keep all referenced resources on HTTPS."
          : "Serve all scripts, styles, images, iframes, and forms from HTTPS URLs only.",
      evidence: {
        checkedUrl: primaryPage.url,
        expectedLocation: 'src/href/action values should start with "https://"',
        summary:
          insecureResources.length === 0
            ? "No insecure resources were found on the primary page."
            : "Some referenced resources still use HTTP on an HTTPS page.",
        insecureResources: insecureResources.length,
        activeMixedContent: activeMixedContent.length,
        locations: exposedResourceLocations(
          insecureResources,
          "This resource is referenced over HTTP from an HTTPS page.",
        ),
      },
    }),
  );

  const insecureInternalLinks = [...primaryPage.links, ...artifacts.crawledPages.flatMap((page) => page.links)]
    .filter((link) => link.internal && !link.secure);
  findings.push(
    buildSecurityCheck({
      checkKey: "insecure-internal-links",
      title: "Insecure internal links",
      status:
        insecureInternalLinks.length === 0
          ? "pass"
          : insecureInternalLinks.length <= 3
            ? "warning"
            : "fail",
      severity:
        insecureInternalLinks.length === 0
          ? "info"
          : insecureInternalLinks.length <= 3
            ? "low"
            : "medium",
      shortDescription:
        insecureInternalLinks.length === 0
          ? "No HTTP internal links were found in the limited crawl."
          : `${insecureInternalLinks.length} HTTP internal links were found in the limited crawl.`,
      whyItMatters:
        "Internal links that still point to HTTP can route users and crawlers through insecure entrypoints.",
      recommendation:
        insecureInternalLinks.length === 0
          ? "Keep internal linking on HTTPS."
          : "Update internal links so they always reference HTTPS URLs.",
      evidence: {
        checkedUrl: primaryPage.url,
        expectedLocation: 'Internal <a href> values should start with "https://"',
        summary:
          insecureInternalLinks.length === 0
            ? "No insecure internal links were discovered."
            : "Some internal links still point to HTTP URLs.",
        insecureInternalLinks: insecureInternalLinks.length,
        locations: insecureInternalLinks.slice(0, 8).map((link, index) => ({
          ...link.location,
          label: `Internal link ${index + 1}`,
          note: `This internal link points to ${link.url}.`,
        })),
      },
    }),
  );

  const insecureExternalResources = primaryPage.resources.filter(
    (resource) => !resource.internal && !resource.secure,
  );
  const criticalExternalResources = insecureExternalResources.filter((resource) =>
    ["script", "stylesheet", "iframe"].includes(resource.kind),
  );
  findings.push(
    buildSecurityCheck({
      checkKey: "insecure-external-resources",
      title: "Insecure external resources",
      status:
        insecureExternalResources.length === 0
          ? "pass"
          : criticalExternalResources.length > 0
            ? "fail"
            : "warning",
      severity:
        insecureExternalResources.length === 0
          ? "info"
          : criticalExternalResources.length > 0
            ? "medium"
            : "low",
      shortDescription:
        insecureExternalResources.length === 0
          ? "No external HTTP resources were referenced from the primary page."
          : `${insecureExternalResources.length} external HTTP resources were referenced from the primary page.`,
      whyItMatters:
        "External HTTP resources break the secure transport guarantee and enlarge supply-chain exposure.",
      recommendation:
        insecureExternalResources.length === 0
          ? "Keep all external resources on HTTPS."
          : "Replace insecure external resources with HTTPS equivalents or remove them.",
      evidence: {
        checkedUrl: primaryPage.url,
        expectedLocation: 'External script/style/image/iframe URLs should start with "https://"',
        summary:
          insecureExternalResources.length === 0
            ? "No insecure external resources were found."
            : "Some external resources still use HTTP.",
        insecureExternalResources: insecureExternalResources.length,
        criticalExternalResources: criticalExternalResources.length,
        locations: exposedResourceLocations(
          insecureExternalResources,
          "This external resource is loaded over HTTP.",
        ),
      },
    }),
  );

  const insecureForms = primaryPage.forms.filter((form) => !form.secure);
  findings.push(
    buildSecurityCheck({
      checkKey: "insecure-form-submission",
      title: "Insecure form submission",
      status: insecureForms.length === 0 ? "pass" : "fail",
      severity: insecureForms.length === 0 ? "info" : "high",
      shortDescription:
        insecureForms.length === 0
          ? "All sampled form actions resolve to HTTPS."
          : `${insecureForms.length} form actions resolve to HTTP.`,
      whyItMatters:
        "Submitting forms to HTTP can expose credentials and user input in transit.",
      recommendation:
        insecureForms.length === 0
          ? "Keep form submissions on HTTPS."
          : "Change every form action to an HTTPS endpoint.",
      evidence: {
        checkedUrl: primaryPage.url,
        expectedLocation: 'form[action] values should resolve to "https://"',
        summary:
          insecureForms.length === 0
            ? "All sampled forms submit to HTTPS URLs."
            : "Some sampled forms submit to HTTP URLs.",
        insecureForms: insecureForms.length,
        locations: exposedResourceLocations(insecureForms, "This form action resolves to HTTP."),
      },
    }),
  );

  const thirdPartyScriptsWithoutSri = primaryPage.resources.filter(
    (resource) => resource.kind === "script" && !resource.internal && !resource.integrity,
  );
  findings.push(
    buildSecurityCheck({
      checkKey: "third-party-scripts-without-sri",
      title: "Third-party scripts without SRI",
      status: thirdPartyScriptsWithoutSri.length === 0 ? "pass" : "warning",
      severity: thirdPartyScriptsWithoutSri.length === 0 ? "info" : "low",
      shortDescription:
        thirdPartyScriptsWithoutSri.length === 0
          ? "All sampled third-party scripts expose integrity metadata."
          : `${thirdPartyScriptsWithoutSri.length} third-party scripts are missing integrity metadata.`,
      whyItMatters:
        "Subresource Integrity helps detect unexpected content changes in third-party scripts.",
      recommendation:
        thirdPartyScriptsWithoutSri.length === 0
          ? "Keep integrity metadata updated as third-party script versions change."
          : "Add `integrity` and `crossorigin` attributes to stable third-party scripts when feasible.",
      evidence: {
        checkedUrl: primaryPage.url,
        expectedLocation: "script[src][integrity] for third-party scripts",
        summary:
          thirdPartyScriptsWithoutSri.length === 0
            ? "No missing SRI attributes were found on sampled third-party scripts."
            : "Some sampled third-party scripts are missing SRI attributes.",
        scriptsWithoutSri: thirdPartyScriptsWithoutSri.length,
        locations: exposedResourceLocations(
          thirdPartyScriptsWithoutSri,
          "This third-party script is missing an integrity attribute.",
        ),
      },
    }),
  );

  const sourceMapCandidates = uniqueUrls(
    firstPartyScriptSamples
      .flatMap((sample) => {
        const sourceMapUrl = resolveSourceMapUrl(sample.url, sample.bodyText);
        return sourceMapUrl ? [sourceMapUrl] : [];
      })
      .slice(0, 8),
  );
  const sourceMapAttempts = (
    await mapLimited(sourceMapCandidates.slice(0, 6), 3, async (url) => {
      const attempt = await loadAttempt(url, {
        timeoutMs: 8_000,
        followRedirects: false,
      });
      if (!attempt) {
        return null;
      }

      return {
        url: attempt.finalUrl,
        status: attempt.status,
        sourceMapLike:
          attempt.status < 400 &&
          /"version"\s*:\s*3|"sources"\s*:\s*\[|"sourcesContent"\s*:\s*\[/i.test(attempt.bodyText),
        includesSourcesContent: /"sourcesContent"\s*:\s*\[/i.test(attempt.bodyText),
      };
    })
  ).filter(isPresent);
  const exposedSourceMaps = sourceMapAttempts.filter((attempt) => attempt.sourceMapLike);
  findings.push(
    buildSecurityCheck({
      checkKey: "exposed-source-maps",
      title: "Exposed source maps",
      scoreWeight: 0.95,
      status: exposedSourceMaps.some((attempt) => attempt.includesSourcesContent)
        ? "fail"
        : exposedSourceMaps.length > 0
          ? "warning"
          : "pass",
      severity: exposedSourceMaps.some((attempt) => attempt.includesSourcesContent)
        ? "high"
        : exposedSourceMaps.length > 0
          ? "medium"
          : "info",
      shortDescription:
        exposedSourceMaps.length === 0
          ? "No public first-party JavaScript source maps were detected in the sampled scripts."
          : `${exposedSourceMaps.length} public source map file(s) were reachable from sampled first-party JavaScript.`,
      whyItMatters:
        "Source maps can expose original source paths, comments, internal route names, and sometimes secrets that were not meant for production users.",
      recommendation:
        exposedSourceMaps.length === 0
          ? "Keep production source maps private unless they are intentionally published."
          : "Remove public source maps from production or serve them only to trusted error-reporting infrastructure.",
      evidence: {
        checkedUrl: sourceMapCandidates.join(", "),
        expectedLocation: "First-party JavaScript sourceMappingURL comments and .map files",
        summary:
          exposedSourceMaps.length === 0
            ? "No sampled source map endpoint returned source-map-like content."
            : "At least one sampled source map endpoint returned source map content.",
        sourceMaps: sourceMapAttempts,
      },
    }),
  );

  const gitHead = await loadAttempt(`${primaryOrigin}/.git/HEAD`, {
    timeoutMs: 8_000,
    followRedirects: false,
  });
  const gitExposed = Boolean(gitHead && gitHead.status < 400 && /refs\/heads/i.test(gitHead.bodyText));
  findings.push(
    buildSecurityCheck({
      checkKey: "exposed-git",
      title: "Exposed .git",
      status: gitExposed ? "fail" : "pass",
      severity: gitExposed ? "critical" : "info",
      shortDescription: gitExposed
        ? "The /.git/HEAD path appears to be publicly accessible."
        : "The /.git/HEAD path was not exposed.",
      whyItMatters:
        "Public Git metadata can leak repository history, internal paths, and sometimes secrets.",
      recommendation: gitExposed
        ? "Block all `.git` paths at the web server and remove exposed repository content from the public root."
        : "Keep `.git` paths blocked from public access.",
      evidence: {
        checkedUrl: `${primaryOrigin}/.git/HEAD`,
        expectedLocation: "/.git/HEAD should not be publicly reachable",
        summary: gitExposed
          ? "The response looked like Git metadata."
          : "The `.git/HEAD` path did not expose Git metadata.",
        statusCode: gitHead?.status ?? null,
      },
    }),
  );

  const envFile = await loadAttempt(`${primaryOrigin}/.env`, {
    timeoutMs: 8_000,
    followRedirects: false,
  });
  const envExposed = Boolean(envFile && looksLikeEnvFile(envFile));
  findings.push(
    buildSecurityCheck({
      checkKey: "exposed-env",
      title: "Exposed .env",
      status: envExposed ? "fail" : "pass",
      severity: envExposed ? "critical" : "info",
      shortDescription: envExposed
        ? "The /.env path appears to return environment-style data."
        : "The /.env path was not exposed.",
      whyItMatters:
        "Exposed environment files often contain credentials, secrets, and infrastructure details.",
      recommendation: envExposed
        ? "Remove the file from the public root and block direct access to environment artifacts."
        : "Keep environment artifacts out of the public document root.",
      evidence: {
        checkedUrl: `${primaryOrigin}/.env`,
        expectedLocation: "/.env should not be publicly reachable",
        summary: envExposed
          ? "The response resembled key-value environment content."
          : "The `.env` path did not expose environment-style content.",
        statusCode: envFile?.status ?? null,
      },
    }),
  );

  const backupPaths = ["/.env.bak", "/backup.zip", "/config.php~", "/index.php.bak"];
  const backupAttempts = await Promise.all(
    backupPaths.map((path) =>
      loadAttempt(`${primaryOrigin}${path}`, {
        timeoutMs: 8_000,
        followRedirects: false,
      }),
    ),
  );
  const exposedBackups = backupAttempts
    .flatMap((attempt, index) =>
      attempt && looksLikeExposedBackupArtifact(attempt, backupPaths[index])
        ? [{ attempt, path: backupPaths[index] }]
        : [],
    );
  findings.push(
    buildSecurityCheck({
      checkKey: "exposed-backup-files",
      title: "Exposed backup files",
      status: exposedBackups.length === 0 ? "pass" : exposedBackups.some(({ path }) => /env|config|zip/i.test(path)) ? "fail" : "warning",
      severity: exposedBackups.length === 0 ? "info" : exposedBackups.some(({ path }) => /env|config|zip/i.test(path)) ? "high" : "medium",
      shortDescription:
        exposedBackups.length === 0
          ? "No sampled backup-style files were publicly accessible."
          : `${exposedBackups.length} sampled backup-style files were publicly accessible.`,
      whyItMatters:
        "Public backup artifacts can expose source code, credentials, or stale copies of sensitive data.",
      recommendation:
        exposedBackups.length === 0
          ? "Keep backup artifacts outside the public web root."
          : "Remove publicly accessible backup files and block direct access to backup-style paths.",
      evidence: {
        checkedUrl: backupPaths.map((path) => `${primaryOrigin}${path}`).join(", "),
        expectedLocation: "Common backup file paths should not be publicly reachable",
        summary:
          exposedBackups.length === 0
            ? "No sampled backup-style paths returned a successful response."
            : "Some sampled backup-style paths returned successful responses.",
        locations: exposedBackups.map(({ attempt, path }) =>
          createResponseLocation({
            label: path,
            url: `${primaryOrigin}${path}`,
            path,
            note: `Returned status ${attempt.status}.`,
          }),
        ),
      },
    }),
  );

  const directoryPaths = ["/wp-content/uploads/", "/assets/", "/images/", "/backup/"];
  const directoryAttempts = await Promise.all(
    directoryPaths.map((path) =>
      loadAttempt(`${primaryOrigin}${path}`, {
        timeoutMs: 8_000,
        followRedirects: false,
      }),
    ),
  );
  const exposedListings = directoryAttempts
    .flatMap((attempt, index) =>
      attempt && attempt.status < 400 && directoryListingDetected(attempt.bodyText)
        ? [{ attempt, path: directoryPaths[index] }]
        : [],
    );
  findings.push(
    buildSecurityCheck({
      checkKey: "directory-listing",
      title: "Directory listing",
      status: exposedListings.length === 0 ? "pass" : exposedListings.length > 1 ? "fail" : "warning",
      severity: exposedListings.length === 0 ? "info" : exposedListings.length > 1 ? "medium" : "low",
      shortDescription:
        exposedListings.length === 0
          ? "No sampled directory listing pages were exposed."
          : `${exposedListings.length} sampled directory paths returned directory listings.`,
      whyItMatters:
        "Directory listings can leak internal file names, deployment artifacts, and crawlable paths.",
      recommendation:
        exposedListings.length === 0
          ? "Keep directory listing disabled on public paths."
          : "Disable directory indexing on public directories and restrict direct browsing of asset folders.",
      evidence: {
        checkedUrl: directoryPaths.map((path) => `${primaryOrigin}${path}`).join(", "),
        expectedLocation: "Public directory paths should not expose server-generated index listings",
        summary:
          exposedListings.length === 0
            ? "No sampled directory listing patterns were detected."
            : "Some sampled paths exposed directory listings.",
        locations: exposedListings.map(({ path }) =>
          createResponseLocation({
            label: path,
            url: `${primaryOrigin}${path}`,
            path,
            note: "Directory listing pattern detected in the response body.",
          }),
        ),
      },
    }),
  );

  const serverHeader = primaryAttempt.headers.server ?? "";
  findings.push(
    buildSecurityCheck({
      checkKey: "server-header-disclosure",
      title: "Server header disclosure",
      status: !serverHeader ? "pass" : /\d/.test(serverHeader) ? "warning" : "pass",
      severity: !serverHeader ? "info" : /\d/.test(serverHeader) ? "low" : "info",
      shortDescription: serverHeader
        ? `Server is set to "${serverHeader}".`
        : "The response does not expose a Server header.",
      whyItMatters:
        "Detailed server banners can make stack fingerprinting and version-targeted reconnaissance easier.",
      recommendation: serverHeader
        ? "Minimize version detail in the Server header where your hosting stack allows it."
        : "Keep server banner disclosure minimized.",
      evidence: serverHeader
        ? {
            ...headerEvidence(primaryAttempt.finalUrl, "server", "The Server header was read from the response."),
            value: serverHeader,
          }
        : headerEvidence(primaryAttempt.finalUrl, "server", "The response did not expose a Server header."),
    }),
  );

  const poweredByHeader = primaryAttempt.headers["x-powered-by"] ?? "";
  findings.push(
    buildSecurityCheck({
      checkKey: "x-powered-by-disclosure",
      title: "X-Powered-By disclosure",
      status: poweredByHeader ? "warning" : "pass",
      severity: poweredByHeader ? "low" : "info",
      shortDescription: poweredByHeader
        ? `X-Powered-By is set to "${poweredByHeader}".`
        : "The response does not expose X-Powered-By.",
      whyItMatters:
        "Framework disclosure can help attackers fingerprint the stack and prioritize exploit attempts.",
      recommendation: poweredByHeader
        ? "Disable or overwrite X-Powered-By in production."
        : "Keep framework disclosure disabled.",
      evidence: poweredByHeader
        ? {
            ...headerEvidence(primaryAttempt.finalUrl, "x-powered-by", "The X-Powered-By header was read from the response."),
            value: poweredByHeader,
          }
        : headerEvidence(primaryAttempt.finalUrl, "x-powered-by", "The response did not expose X-Powered-By."),
    }),
  );

  const wellKnownSecurityTxt = await loadAttempt(`${primaryOrigin}/.well-known/security.txt`, {
    timeoutMs: 8_000,
    includeBody: false,
  });
  const rootSecurityTxt = await loadAttempt(`${primaryOrigin}/security.txt`, {
    timeoutMs: 8_000,
    includeBody: false,
  });
  const securityTxtAttempt =
    wellKnownSecurityTxt && wellKnownSecurityTxt.status < 400
      ? wellKnownSecurityTxt
      : rootSecurityTxt && rootSecurityTxt.status < 400
        ? rootSecurityTxt
        : null;
  findings.push(
    buildSecurityCheck({
      checkKey: "security-txt",
      title: "security.txt",
      status: securityTxtAttempt ? "pass" : "info",
      severity: "info",
      shortDescription: securityTxtAttempt
        ? `security.txt is reachable at ${securityTxtAttempt.finalUrl}.`
        : "security.txt was not found at the standard locations.",
      whyItMatters:
        "security.txt gives researchers a standard place to find disclosure and contact instructions.",
      recommendation: securityTxtAttempt
        ? "Keep contact and policy information current."
        : "Publish `/.well-known/security.txt` with disclosure instructions and a monitored contact address.",
      evidence: {
        checkedUrl: `${primaryOrigin}/.well-known/security.txt, ${primaryOrigin}/security.txt`,
        expectedLocation: "/.well-known/security.txt or /security.txt",
        summary: securityTxtAttempt
          ? "A security.txt file was found."
          : "No security.txt file was found at the tested locations.",
      },
    }),
  );

  const robotsTxt = await loadAttempt(`${primaryOrigin}/robots.txt`, {
    timeoutMs: 8_000,
    includeBody: false,
  });
  findings.push(
    buildSecurityCheck({
      checkKey: "robots-txt-presence",
      title: "robots.txt presence",
      status: robotsTxt && robotsTxt.status < 400 ? "pass" : "info",
      severity: "info",
      shortDescription:
        robotsTxt && robotsTxt.status < 400
          ? "robots.txt is reachable on the primary origin."
          : "robots.txt is not reachable on the primary origin.",
      whyItMatters:
        "robots.txt is not a direct security control, but its presence often reflects baseline operational hygiene.",
      recommendation:
        robotsTxt && robotsTxt.status < 400
          ? "Keep robots.txt aligned with the intended crawl policy."
          : "Publish robots.txt if you want explicit crawler guidance on the primary origin.",
      evidence: {
        checkedUrl: `${primaryOrigin}/robots.txt`,
        expectedLocation: "/robots.txt",
        summary:
          robotsTxt && robotsTxt.status < 400
            ? "robots.txt returned a successful response."
            : "robots.txt did not return a successful response.",
      },
    }),
  );

  findings.push(
    buildSecurityCheck({
      checkKey: "technology-fingerprinting",
      title: "Technology fingerprinting",
      status: "info",
      severity: "info",
      shortDescription:
        artifacts.technologyHints.length > 0
          ? `Detected likely technologies: ${artifacts.technologyHints.join(", ")}.`
          : "No strong technology signatures were detected from the sampled response.",
      whyItMatters:
        "Technology fingerprinting is informational, but it helps teams understand what their public stack reveals.",
      recommendation:
        artifacts.technologyHints.length > 0
          ? "Review whether publicly exposed stack signatures are acceptable for your threat model."
          : "No immediate action is required unless you want to reduce passive fingerprinting further.",
      evidence: {
        checkedUrl: primaryAttempt.finalUrl,
        expectedLocation: "Response headers, meta tags, and asset naming patterns",
        summary:
          artifacts.technologyHints.length > 0
            ? "Technology signatures were inferred from public response evidence."
            : "No strong technology signatures were inferred from the sampled response.",
        technologies: artifacts.technologyHints,
      },
      premiumOnly: true,
    }),
  );

  findings.push(
    buildSecurityCheck({
      checkKey: "basic-waf-cdn-detection",
      title: "Basic WAF / CDN detection",
      status: "info",
      severity: "info",
      shortDescription:
        artifacts.wafHints.length > 0
          ? `Detected possible edge providers: ${artifacts.wafHints.join(", ")}.`
          : "No strong CDN or WAF signatures were detected from the sampled response.",
      whyItMatters:
        "Edge infrastructure detection is informational, but it helps explain response headers, caching, and security controls seen in production.",
      recommendation:
        artifacts.wafHints.length > 0
          ? "Verify that the detected edge providers are configured with the caching and security posture you expect."
          : "No action is required unless you expected a CDN or WAF in front of the site.",
      evidence: {
        checkedUrl: primaryAttempt.finalUrl,
        expectedLocation: "Response headers and edge-specific response patterns",
        summary:
          artifacts.wafHints.length > 0
            ? "Edge-provider hints were inferred from public response headers."
            : "No strong WAF/CDN signatures were inferred from the sampled response.",
        providers: artifacts.wafHints,
      },
      premiumOnly: true,
    }),
  );

  const gated = applyPremiumGating(findings, 10);
  return {
    score: computeScore(findings),
    findings: gated,
  };
}
