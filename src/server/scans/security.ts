import { load as loadHtml } from "cheerio";
import { type FindingConfidence, type FindingStatus, type ScanFinding, type Severity } from "@/lib/types";
import { applyPremiumGating, deriveFindingStatus } from "@/lib/utils";
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
import { type CategoryScanResult, type HttpAttempt, type NormalizedTarget, type ScanRunOptions } from "@/server/scans/types";
import { authContextFromSession, AuthContextStore } from "@/security/auth/authContextStore";
import { analyzeSessionContext } from "@/security/auth/sessionContextAnalyzer";
import { buildAttackPaths } from "@/security/analysis/attackPathBuilder";
import { buildReportSummary } from "@/security/reportSummary";
import { getRecommendationLabel } from "@/security/analysis/riskPrioritizer";
import {
  controlledXssPayloads,
  createXssMarker,
  verifyXssExecution,
} from "@/security/probes/xssExecutionVerifier";
import { verifyIdorOwnership } from "@/security/probes/idorOwnershipVerifier";
import { buildRoleBasedAccessMatrix } from "@/security/probes/roleBasedAccessTester";
import { runBlindSqlInjectionProbe } from "@/security/probes/blindSqlInjectionProbe";
import {
  buildSqlResponseSignature,
  classifyParameter,
  findStrictDbErrorSignature,
  highDynamicResponseSignal,
  responseDiffDimensions,
  type DbErrorFamily,
  type EvidenceStrength,
  type ParameterContext,
} from "@/security/probes/sqlEvidence";

function buildSecurityCheck(input: {
  checkKey: string;
  title: string;
  status: FindingStatus;
  severity: Severity;
  confidence?: FindingConfidence;
  scoreWeight?: number;
  shortDescription: string;
  whyItMatters: string;
  recommendation: string;
  evidence?: Record<string, unknown>;
  premiumOnly?: boolean;
}) {
  return createFinding({
    ...input,
    id: `security-${input.checkKey}`,
    category: "security",
  });
}

function resolveSecurityScanMode(target: NormalizedTarget) {
  if (target.scanMode) {
    return target.scanMode;
  }
  if (process.env.FIXNX_SCAN_MODE?.trim().toLowerCase() === "deep") {
    return "Deep";
  }
  if (target.authCookieHeader || target.authUsername) {
    return "Authenticated";
  }
  return "Fast";
}

function securityBudgetMs(scanMode: ReturnType<typeof resolveSecurityScanMode>) {
  switch (scanMode) {
    case "Deep":
      return 90_000;
    case "Authenticated":
      return 55_000;
    case "Fast":
    default:
      return 32_000;
  }
}

function createSecurityPhaseLogger(target: NormalizedTarget, scanMode: ReturnType<typeof resolveSecurityScanMode>) {
  const startedAt = Date.now();
  let lastAt = startedAt;
  return (phase: string, metadata: Record<string, unknown> = {}) => {
    const now = Date.now();
    const elapsedMs = now - startedAt;
    const phaseMs = now - lastAt;
    lastAt = now;
    console.info(
      `[fixnx][security][${target.targetHostname}][${scanMode}] ${phase} elapsed=${elapsedMs}ms phase=${phaseMs}ms`,
      metadata,
    );
  };
}

function originFromAttempt(attempt: HttpAttempt | null, fallbackUrl: string) {
  try {
    return new URL(attempt?.finalUrl ?? fallbackUrl).origin;
  } catch {
    return fallbackUrl;
  }
}

function preliminaryScore(findings: ScanFinding[]) {
  let score = 100;
  for (const finding of findings) {
    const status = deriveFindingStatus(finding);
    if (status === "fail") {
      score -= finding.severity === "high" || finding.severity === "critical" ? 16 : 8;
    } else if (status === "warning") {
      score -= finding.severity === "medium" ? 8 : 4;
    }
  }
  return Math.max(20, Math.min(100, Math.round(score)));
}

async function runFastBaselinePhase(target: NormalizedTarget, scanMode: ReturnType<typeof resolveSecurityScanMode>) {
  const startedAt = Date.now();
  const timeoutMs = scanMode === "Fast" ? 6_000 : 8_000;
  const [httpsAttempt, httpAttempt] = await Promise.all([
    loadAttempt(target.httpsUrl, { timeoutMs, followRedirects: true }),
    loadAttempt(target.httpUrl, { timeoutMs, includeBody: false, followRedirects: false }),
  ]);
  const primaryAttempt = httpsAttempt ?? httpAttempt;
  const primaryOrigin = originFromAttempt(primaryAttempt, target.httpsUrl);
  const [robotsTxt, sitemapXml, wellKnownSecurityTxt, rootSecurityTxt] = await Promise.all([
    loadAttempt(`${primaryOrigin}/robots.txt`, { timeoutMs }),
    loadAttempt(`${primaryOrigin}/sitemap.xml`, { timeoutMs, includeBody: false }),
    loadAttempt(`${primaryOrigin}/.well-known/security.txt`, { timeoutMs, includeBody: false }),
    loadAttempt(`${primaryOrigin}/security.txt`, { timeoutMs, includeBody: false }),
  ]);

  if (!primaryAttempt) {
    const findings = [
      buildSecurityCheck({
        checkKey: "fast-baseline-coverage",
        title: "Fast baseline coverage",
        status: "fail",
        severity: "high",
        confidence: "confirmed",
        shortDescription: "The scanner could not fetch the target during the fast baseline phase.",
        whyItMatters: "Without a baseline response the scanner cannot produce early header, platform, or form evidence.",
        recommendation: "Verify that the target is reachable from the scanner and rerun the scan.",
        evidence: {
          checkedUrl: `${target.httpsUrl}, ${target.httpUrl}`,
          summary: "No primary HTTP response was available during fast baseline.",
          preliminary: true,
        },
      }),
    ];

    return {
      findings,
      score: preliminaryScore(findings),
      urlsChecked: 6,
      durationMs: Date.now() - startedAt,
    };
  }

  const headers = primaryAttempt.headers;
  const bodyText = primaryAttempt.bodyText ?? "";
  const $ = loadHtml(bodyText);
  const forms = $("form").toArray();
  const passwordFields = $('input[type="password"]').length;
  const scripts = $("script[src]").length;
  const links = $("a[href]").length;
  const generator = $('meta[name="generator"]').attr("content")?.trim() ?? "";
  const poweredBy = headers["x-powered-by"] ?? "";
  const serverHeader = headers.server ?? "";
  const cspHeader = headers["content-security-policy"] ?? "";
  const cspDirectives = cspHeader
    .split(";")
    .map((directive) => directive.trim().toLowerCase())
    .filter(Boolean);
  const cspOnlyUpgradeInsecureRequests =
    cspDirectives.length > 0 &&
    cspDirectives.every((directive) => directive === "upgrade-insecure-requests");
  const cspWeak =
    !cspHeader ||
    cspOnlyUpgradeInsecureRequests ||
    /unsafe-inline|unsafe-eval/i.test(cspHeader) ||
    !/(^|;)\s*(script-src|default-src)\b/i.test(cspHeader);
  const frameOptions = headers["x-frame-options"]?.toUpperCase() ?? "";
  const contentTypeOptions = headers["x-content-type-options"]?.toLowerCase() ?? "";
  const referrerPolicy = headers["referrer-policy"] ?? "";
  const hsts = headers["strict-transport-security"] ?? "";
  const securityTxtFound = Boolean(
    (wellKnownSecurityTxt && wellKnownSecurityTxt.status < 400) ||
      (rootSecurityTxt && rootSecurityTxt.status < 400),
  );
  const wordpressDetected =
    /wordpress|wp-content|wp-includes|wp-json/i.test(`${bodyText} ${generator}`) ||
    /wp-/i.test(generator);

  const findings = [
    buildSecurityCheck({
      checkKey: "fast-baseline-coverage",
      title: "Fast baseline coverage",
      status: "info",
      severity: "info",
      confidence: "info",
      shortDescription:
        `Initial results are ready from ${primaryAttempt.finalUrl}. Browser rendering and active probes are still running.`,
      whyItMatters:
        "Fast baseline findings give immediate visibility into high-signal headers, platform hints, and first-page attack surface while deeper checks continue.",
      recommendation:
        "Use these preliminary results for early triage, then review the final report after browser and active checks complete.",
      evidence: {
        checkedUrl: primaryAttempt.finalUrl,
        expectedLocation: "Main response, headers, first-page HTML, robots, sitemap, and security.txt",
        summary: "Fast baseline completed. Deeper checks are still running.",
        preliminary: true,
        durationMs: Date.now() - startedAt,
      },
    }),
    buildSecurityCheck({
      checkKey: "https-enabled",
      title: "HTTPS enabled",
      status: httpsAttempt && httpsAttempt.status < 500 ? "pass" : "fail",
      severity: httpsAttempt && httpsAttempt.status < 500 ? "info" : "high",
      shortDescription:
        httpsAttempt && httpsAttempt.status < 500
          ? "The target returned an HTTPS response during fast baseline."
          : "The target did not return a usable HTTPS response during fast baseline.",
      whyItMatters: "HTTPS is the baseline transport control for protecting users and scan evidence.",
      recommendation:
        httpsAttempt && httpsAttempt.status < 500
          ? "Keep HTTPS enabled for all public pages."
          : "Enable HTTPS and redirect all HTTP traffic to HTTPS.",
      evidence: {
        checkedUrl: target.httpsUrl,
        summary: httpsAttempt ? `HTTPS returned status ${httpsAttempt.status}.` : "HTTPS request failed.",
        preliminary: true,
      },
    }),
    buildSecurityCheck({
      checkKey: "http-to-https-redirect",
      title: "HTTP to HTTPS redirect",
      status:
        httpAttempt && [301, 302, 307, 308].includes(httpAttempt.status) && /https:\/\//i.test(httpAttempt.headers.location ?? "")
          ? "pass"
          : "warning",
      severity:
        httpAttempt && [301, 302, 307, 308].includes(httpAttempt.status) && /https:\/\//i.test(httpAttempt.headers.location ?? "")
          ? "info"
          : "medium",
      confidence: "likely",
      shortDescription:
        httpAttempt && [301, 302, 307, 308].includes(httpAttempt.status) && /https:\/\//i.test(httpAttempt.headers.location ?? "")
          ? "HTTP redirects to HTTPS."
          : "HTTP did not clearly redirect to HTTPS in the fast baseline sample.",
      whyItMatters: "Clear HTTPS redirects reduce downgrade and duplicate-content exposure.",
      recommendation: "Redirect HTTP requests to the canonical HTTPS origin.",
      evidence: {
        checkedUrl: target.httpUrl,
        summary: httpAttempt ? `HTTP returned ${httpAttempt.status}.` : "HTTP request failed.",
        location: httpAttempt?.headers.location ?? null,
        preliminary: true,
      },
    }),
    buildSecurityCheck({
      checkKey: "hsts-header",
      title: "HSTS header",
      status: hsts ? "pass" : "warning",
      severity: hsts ? "info" : "low",
      confidence: hsts ? "info" : "likely",
      shortDescription: hsts ? `Strict-Transport-Security is set to "${hsts}".` : "Strict-Transport-Security is missing from the HTTPS response.",
      whyItMatters: "HSTS helps browsers avoid insecure protocol downgrades after the first secure visit.",
      recommendation: hsts ? "Keep HSTS configured with a suitable max-age." : "Add a Strict-Transport-Security header on HTTPS responses.",
      evidence: {
        checkedUrl: primaryAttempt.finalUrl,
        value: hsts || null,
        preliminary: true,
      },
    }),
    buildSecurityCheck({
      checkKey: "content-security-policy",
      title: cspWeak ? "Weak Content-Security-Policy" : "Content-Security-Policy",
      status: cspWeak ? "warning" : "pass",
      severity: cspWeak ? "low" : "info",
      confidence: cspWeak ? "likely" : "info",
      shortDescription: cspHeader
        ? cspWeak
          ? `Content-Security-Policy is set, but it is weak: "${cspHeader}".`
          : `Content-Security-Policy is set to "${cspHeader}".`
        : "Content-Security-Policy is missing from the main response.",
      whyItMatters: "A strong CSP reduces XSS impact and limits script, frame, and object loading.",
      recommendation: cspWeak
        ? "Add a stronger CSP with script-src, object-src, base-uri, frame-ancestors, and default-src directives where feasible."
        : "Keep CSP aligned with the application script and framing model.",
      evidence: {
        checkedUrl: primaryAttempt.finalUrl,
        value: cspHeader || null,
        weakPolicy: cspWeak,
        onlyUpgradeInsecureRequests: cspOnlyUpgradeInsecureRequests,
        preliminary: true,
      },
    }),
    buildSecurityCheck({
      checkKey: "clickjacking-protection",
      title: "Clickjacking protection",
      status: frameOptions === "DENY" || frameOptions === "SAMEORIGIN" || /frame-ancestors/i.test(cspHeader) ? "pass" : "warning",
      severity: passwordFields > 0 && !frameOptions ? "medium" : frameOptions ? "info" : "low",
      confidence: frameOptions ? "info" : "likely",
      shortDescription:
        frameOptions || /frame-ancestors/i.test(cspHeader)
          ? "A frame embedding control was detected in the fast baseline."
          : "No clear frame embedding protection was detected in the fast baseline.",
      whyItMatters: "Login and form pages need anti-framing protection to reduce clickjacking risk.",
      recommendation: "Set X-Frame-Options or CSP frame-ancestors for pages that should not be framed.",
      evidence: {
        checkedUrl: primaryAttempt.finalUrl,
        xFrameOptions: frameOptions || null,
        cspFrameAncestors: /frame-ancestors/i.test(cspHeader),
        passwordFields,
        preliminary: true,
      },
    }),
    buildSecurityCheck({
      checkKey: "x-content-type-options",
      title: "X-Content-Type-Options",
      status: contentTypeOptions === "nosniff" ? "pass" : "warning",
      severity: contentTypeOptions === "nosniff" ? "info" : "low",
      confidence: contentTypeOptions === "nosniff" ? "info" : "likely",
      shortDescription: contentTypeOptions === "nosniff" ? "X-Content-Type-Options is set to nosniff." : "X-Content-Type-Options is missing from the main response.",
      whyItMatters: "The nosniff policy helps prevent MIME confusion in browsers.",
      recommendation: "Set X-Content-Type-Options: nosniff on the main response.",
      evidence: {
        checkedUrl: primaryAttempt.finalUrl,
        value: contentTypeOptions || null,
        preliminary: true,
      },
    }),
    buildSecurityCheck({
      checkKey: "referrer-policy",
      title: "Referrer-Policy",
      status: referrerPolicy ? "pass" : "warning",
      severity: referrerPolicy ? "info" : "low",
      confidence: referrerPolicy ? "info" : "likely",
      shortDescription: referrerPolicy ? `Referrer-Policy is set to "${referrerPolicy}".` : "Referrer-Policy is missing from the main response.",
      whyItMatters: "Referrer policy controls how much URL information is sent to other sites.",
      recommendation: "Add Referrer-Policy, typically strict-origin-when-cross-origin.",
      evidence: {
        checkedUrl: primaryAttempt.finalUrl,
        value: referrerPolicy || null,
        preliminary: true,
      },
    }),
    buildSecurityCheck({
      checkKey: "authentication-surface-review",
      title: "Authentication surface review",
      status: passwordFields > 0 || /login|signin|wp-login|password/i.test(bodyText) ? "warning" : "info",
      severity: passwordFields > 0 ? "medium" : "info",
      confidence: passwordFields > 0 ? "likely" : "info",
      shortDescription:
        passwordFields > 0
          ? `Fast baseline detected ${passwordFields} password field(s) on the first page.`
          : "No password field was captured in the first-page fast baseline.",
      whyItMatters: "Authentication surfaces are high-value targets and should be visible early in the scan.",
      recommendation: "Review login and password routes with anti-framing, CSRF, secure cookies, and authenticated scan coverage.",
      evidence: {
        checkedUrl: primaryAttempt.finalUrl,
        passwordFormCount: passwordFields,
        authSurfaceDetected: passwordFields > 0,
        preliminary: true,
      },
    }),
    buildSecurityCheck({
      checkKey: "fast-html-surface",
      title: "First-page HTML surface",
      status: "info",
      severity: "info",
      confidence: "info",
      shortDescription: `Fast baseline found ${forms.length} form(s), ${links} link(s), and ${scripts} script tag(s) on the first page.`,
      whyItMatters: "Forms, links, and scripts define the first attack surface the scanner can prioritize.",
      recommendation: "Use browser-rendered and active checks for deeper validation of dynamic routes and form behavior.",
      evidence: {
        checkedUrl: primaryAttempt.finalUrl,
        forms: forms.length,
        passwordFields,
        links,
        scripts,
        preliminary: true,
      },
    }),
    buildSecurityCheck({
      checkKey: "technology-fingerprinting",
      title: "Technology fingerprinting",
      status: generator || poweredBy || serverHeader || wordpressDetected ? "warning" : "info",
      severity: generator || poweredBy ? "low" : "info",
      confidence: generator || poweredBy || serverHeader || wordpressDetected ? "likely" : "info",
      shortDescription:
        generator || poweredBy || serverHeader || wordpressDetected
          ? `Fast baseline detected technology hints: ${[generator, poweredBy && `X-Powered-By: ${poweredBy}`, serverHeader && `Server: ${serverHeader}`, wordpressDetected && "WordPress"].filter(Boolean).join(", ")}.`
          : "No strong technology hints were detected in the fast baseline.",
      whyItMatters: "Public platform and version hints help prioritize follow-up checks.",
      recommendation: "Reduce exact public version disclosure where feasible and verify patch posture for detected platforms.",
      evidence: {
        checkedUrl: primaryAttempt.finalUrl,
        generator: generator || null,
        poweredBy: poweredBy || null,
        server: serverHeader || null,
        wordpressDetected,
        preliminary: true,
      },
      premiumOnly: true,
    }),
    buildSecurityCheck({
      checkKey: "security-txt",
      title: "security.txt",
      status: securityTxtFound ? "pass" : "info",
      severity: "info",
      confidence: "info",
      shortDescription: securityTxtFound ? "security.txt is reachable." : "security.txt was not found at standard locations.",
      whyItMatters: "security.txt gives researchers a standard place to find disclosure and contact instructions.",
      recommendation: securityTxtFound ? "Keep security.txt current." : "Publish /.well-known/security.txt with disclosure instructions.",
      evidence: {
        checkedUrl: `${primaryOrigin}/.well-known/security.txt, ${primaryOrigin}/security.txt`,
        found: securityTxtFound,
        preliminary: true,
      },
    }),
    buildSecurityCheck({
      checkKey: "fast-discovery-files",
      title: "Discovery files",
      status: "info",
      severity: "info",
      confidence: "info",
      shortDescription:
        `Fast baseline checked robots.txt (${robotsTxt?.status ?? "failed"}) and sitemap.xml (${sitemapXml?.status ?? "failed"}).`,
      whyItMatters: "robots.txt and sitemap.xml can quickly reveal crawl scope and sensitive-looking paths.",
      recommendation: "Ensure discovery files do not reference unprotected sensitive paths.",
      evidence: {
        checkedUrl: `${primaryOrigin}/robots.txt, ${primaryOrigin}/sitemap.xml`,
        robotsStatus: robotsTxt?.status ?? null,
        sitemapStatus: sitemapXml?.status ?? null,
        preliminary: true,
      },
    }),
  ];

  return {
    findings,
    score: preliminaryScore(findings),
    urlsChecked: 6,
    durationMs: Date.now() - startedAt,
  };
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

type CookieSensitivity =
  | "auth"
  | "session"
  | "csrf"
  | "tracking"
  | "preference"
  | "analytics"
  | "unknown";

function isCsrfCookie(name: string) {
  return /(csrf|xsrf)/i.test(name);
}

function isHostedAuthProviderSignal(value: string) {
  const text = value.toLowerCase();
  let hostname = "";
  try {
    hostname = new URL(value.split("#")[0] || value).hostname.toLowerCase();
  } catch {
    hostname = "";
  }

  return (
    /(?:^|\.)accounts\./.test(hostname) ||
    /(?:^|\.)auth0\.com$|(?:^|\.)okta\.com$|login\.microsoftonline\.com$|(?:^|\.)cognito-idp\./.test(hostname) ||
    /servicelogin|weblitesignin|oauth2?|openid|saml|identity-provider|idp/.test(text)
  );
}

function isSensitiveCookie(name: string) {
  return ["auth", "session", "csrf"].includes(classifyCookieSensitivity(name));
}

function classifyCookieSensitivity(name: string): CookieSensitivity {
  const lower = name.toLowerCase();

  if (/(csrf|xsrf)/i.test(name)) {
    return "csrf";
  }
  if (
    /^(?:phpsessid|jsessionid|sessionid|connect\.sid)$/i.test(name) ||
    /(?:^|[_.-])(?:session|sess|sid)(?:$|[_.-])/i.test(lower)
  ) {
    return "session";
  }
  if (/(?:auth(?:entication)?|access|refresh|id)[_.-]?token|jwt|login/i.test(lower)) {
    return "auth";
  }
  if (/^(?:_ga|_gid|_gat|_gcl|nid|1p_jar|ogpc|aec|ide|fr|fbp)$/i.test(name)) {
    return "analytics";
  }
  if (/^(?:consent|socs|preferences?|prefs?|lang|locale|theme)$/i.test(name)) {
    return "preference";
  }
  if (/(?:track|analytics|visitor|utm|campaign|ga|gid)/i.test(lower)) {
    return "tracking";
  }

  return "unknown";
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
  payload: string;
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
  marker?: string;
  signals?: Array<{ type: string; value: string; timestamp?: string }>;
  domState?: Record<string, unknown> | null;
};

type ActiveSqlProbeResult = {
  url: string;
  parameter: string;
  parameterContext: ParameterContext;
  payload: string;
  status: number;
  baselineStatus: number | null;
  baselineDurationMs: number | null;
  probeDurationMs: number | null;
  sqlError: boolean;
  dbErrorSignature: string | null;
  dbErrorFamily: DbErrorFamily | null;
  dbErrorExcerpt: string | null;
  serverError: boolean;
  baselineRecordCount: number | null;
  probeRecordCount: number | null;
  recordExpansion: boolean;
  timeDelay: boolean;
  evidenceStrength: EvidenceStrength;
  falsePositiveRisk: "low" | "medium" | "high";
};

type BooleanSqlProbeResult = {
  url: string;
  parameter: string;
  parameterContext: ParameterContext;
  truePayload: string;
  falsePayload: string;
  baselineStatus: number | null;
  trueStatus: number | null;
  falseStatus: number | null;
  baselineRecordCount: number | null;
  trueRecordCount: number | null;
  falseRecordCount: number | null;
  trueBodyLength: number | null;
  falseBodyLength: number | null;
  responseDifference: boolean;
  diffDimensions: string[];
  highDynamic: boolean;
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
  sessionBased?: boolean;
  ownershipConfirmed?: boolean;
  ownerContext?: string | null;
  attackerContext?: string | null;
  leakedFields?: string[];
  leakedMarkers?: string[];
  ownershipResponseDiff?: string | null;
};

type AuthBypassProbeResult = {
  url: string;
  payload: string;
  status: number;
  authSuccess: boolean;
  tokenLikeResponse: boolean;
  sessionCookie: boolean;
  token: string | null;
  userId: string | number | null;
  basketId: string | number | null;
  userEmail: string | null;
  roles: string[];
  setCookies: string[];
};

type AuthSessionProof = {
  source: "provided-cookie" | "provided-credentials" | "active-bypass";
  headers: HeadersInit;
  token: string | null;
  cookieHeader: string | null;
  userId: string | number | null;
  basketId: string | number | null;
  userEmail: string | null;
  roles: string[];
  roleLabel: string | null;
};

type AuthenticatedEndpointProbe = {
  url: string;
  status: number;
  contentType: string;
  sensitiveResponse: boolean;
  adminLike: boolean;
  bodyLength: number;
};

type StoredXssProbeResult = {
  url: string;
  method: string;
  status: number;
  accepted: boolean;
  retrievable: boolean;
  executed: boolean;
  payload: string;
  marker: string;
  signals?: Array<{ type: string; value: string; timestamp?: string }>;
  renderedUrl?: string;
};

const csrfTokenNamePattern = /(csrf|xsrf|authenticity|requestverification|form[_-]?token|nonce)/i;
const sensitivePathPattern =
  /(login|signin|auth|register|signup|password|reset|forgot|admin|dashboard|account|profile|settings|billing|payment|invoice|export|download|upload|graphql|api|debug|status|metrics)/i;
const apiPathPattern = /(?:^|\/)(?:api(?:\/v\d+)?|graphql|rest(?:\/v\d+)?|rpc|ajax)(?:\/|$)/i;
const openRedirectParamPattern = /^(redirect|next|return|returnurl|continue|url|target|dest)$/i;
const riskyInputParamPattern = /^(q|query|search|keyword|term|id|sort|filter|category|redirect|next|returnurl|continue|url)$/i;
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

type ApiEndpointClassification = {
  url: string;
  classes: string[];
  source: "frontend" | "browser-network" | "sensitive-probe";
};

type SensitiveFileProbe = {
  url: string;
  path: string;
  status: number;
  contentType: string;
  exposed: boolean;
  kind: string;
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

const fastSensitiveFilePaths = [
  "/.DS_Store",
  "/config.json",
  "/swagger.json",
  "/openapi.json",
  "/api-docs",
  "/phpinfo.php",
  "/server-status",
  "/actuator",
  "/.well-known/",
];

const missingHeaderCheckKeys = [
  "content-security-policy",
  "hsts-header",
  "x-frame-options",
  "x-content-type-options",
  "referrer-policy",
  "permissions-policy",
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

function applyProbeParameter(rawUrl: string, parameter: string, value: string) {
  const parsed = new URL(rawUrl);
  const encodedPair = `${encodeURIComponent(parameter)}=${encodeURIComponent(value)}`;

  if (parsed.hash && /^#\/?/.test(parsed.hash) && /^(q|query|search|keyword|term|filter|category)$/i.test(parameter)) {
    const hashBody = parsed.hash.slice(1);
    const [hashPath, hashQuery = ""] = hashBody.split("?");
    const hashParams = new URLSearchParams(hashQuery);
    hashParams.set(parameter, value);
    parsed.hash = `${hashPath}?${hashParams.toString()}`;
    return parsed.toString();
  }

  if (parsed.hash && parsed.hash.includes("?") && !parsed.searchParams.has(parameter)) {
    parsed.hash += parsed.hash.includes("&") ? `&${encodedPair}` : `&${encodedPair}`;
    return parsed.toString();
  }

  parsed.searchParams.set(parameter, value);
  return parsed.toString();
}

function jsonRecord(value: unknown): Record<string, unknown> | null {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : null;
}

function parseJsonBody(bodyText: string): unknown {
  try {
    return JSON.parse(bodyText) as unknown;
  } catch {
    return null;
  }
}

function findFirstJsonValue(
  value: unknown,
  keyPattern: RegExp,
): string | number | null {
  if (Array.isArray(value)) {
    for (const item of value) {
      const found = findFirstJsonValue(item, keyPattern);
      if (found !== null) {
        return found;
      }
    }
    return null;
  }

  const record = jsonRecord(value);
  if (!record) {
    return null;
  }

  for (const [key, entry] of Object.entries(record)) {
    if (keyPattern.test(key) && (typeof entry === "string" || typeof entry === "number")) {
      return entry;
    }
    const found = findFirstJsonValue(entry, keyPattern);
    if (found !== null) {
      return found;
    }
  }

  return null;
}

function findJsonStringArray(value: unknown, keyPattern: RegExp): string[] {
  const record = jsonRecord(value);
  if (!record) {
    return [];
  }

  for (const [key, entry] of Object.entries(record)) {
    if (keyPattern.test(key) && Array.isArray(entry)) {
      return entry.filter((item): item is string => typeof item === "string").slice(0, 8);
    }
    const nested: string[] = findJsonStringArray(entry, keyPattern);
    if (nested.length > 0) {
      return nested;
    }
  }

  return [];
}

function extractAuthSessionFromAttempt(
  attempt: HttpAttempt,
  source: AuthSessionProof["source"],
  roleLabel: string | null,
): AuthSessionProof | null {
  const parsedBody = parseJsonBody(attempt.bodyText);
  const tokenValue =
    findFirstJsonValue(parsedBody, /^(?:token|accessToken|access_token|id_token|jwt)$/i) ??
    attempt.bodyText.match(/\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9._-]{10,}\.[A-Za-z0-9._-]{10,}\b/)?.[0] ??
    null;
  const cookieHeader = attempt.setCookies
    .map((cookie) => cookie.split(";")[0]?.trim())
    .filter(Boolean)
    .join("; ");
  const headers: HeadersInit = {};
  if (typeof tokenValue === "string" && tokenValue.length > 10) {
    headers.authorization = `Bearer ${tokenValue}`;
  }
  if (cookieHeader) {
    headers.cookie = cookieHeader;
  }

  if (!headers.authorization && !headers.cookie) {
    return null;
  }

  return {
    source,
    headers,
    token: typeof tokenValue === "string" ? tokenValue : null,
    cookieHeader: cookieHeader || null,
    userId: findFirstJsonValue(parsedBody, /^(?:id|userId|uid)$/i),
    basketId: findFirstJsonValue(parsedBody, /^(?:bid|basketId)$/i),
    userEmail:
      String(findFirstJsonValue(parsedBody, /^(?:email|umail|username)$/i) ?? "") || null,
    roles: findJsonStringArray(parsedBody, /roles?|authorities|permissions/i),
    roleLabel,
  };
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

function maskSecret(value: string | null | undefined) {
  if (!value || value.length < 12) {
    return "[masked]";
  }

  return `${value.slice(0, 6)}...${value.slice(-4)}`;
}

function collectCookieHints(setCookies: string[]) {
  const cookies = setCookies.map((cookie) => ({
    name: cookieName(cookie),
    raw: cookie,
    sensitivity: classifyCookieSensitivity(cookieName(cookie)),
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
  return Boolean(findStrictDbErrorSignature(bodyText));
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

  const marker = createXssMarker("reflected");
  const payloads = controlledXssPayloads(marker);
  const results: BrowserXssExecutionResult[] = [];

  for (const config of configs.slice(0, 3)) {
    for (const payload of payloads.slice(0, 1)) {
      const probeUrl = applyProbeParameter(config.url, config.parameter, payload.value);
      try {
        const verification = await verifyXssExecution({
          url: probeUrl,
          marker,
          payload: payload.value,
          contextOptions: {
            extraHTTPHeaders: authCookieHeader ? { cookie: authCookieHeader } : undefined,
          },
          waitMs: 650,
        });
        results.push({
          url: probeUrl,
          parameter: config.parameter,
          status: verification.status,
          executed: verification.executed,
          payload: verification.sanitizedPayload,
          marker: verification.marker,
          signals: verification.signals,
          domState: verification.domState,
        });
        if (verification.executed) {
          break;
        }
      } catch {
        results.push({
          url: probeUrl,
          parameter: config.parameter,
          status: null,
          executed: false,
          payload: payload.value,
          marker,
          signals: [],
          domState: null,
        });
      }
    }
  }

  return results;
}

async function runCredentialLoginProbe(input: {
  primaryOrigin: string;
  loginUrl: string | null | undefined;
  username: string | null | undefined;
  password: string | null | undefined;
  roleLabel: string | null | undefined;
  targetHostname: string;
  timeoutMs?: number;
}) {
  const username = input.username?.trim();
  const password = input.password?.trim();
  if (!username || !password) {
    return null;
  }

  const loginTargets = uniqueUrls([
    input.loginUrl ? resolveHttpUrl(input.loginUrl, input.primaryOrigin) ?? "" : "",
    `${input.primaryOrigin}/rest/user/login`,
    `${input.primaryOrigin}/api/login`,
    `${input.primaryOrigin}/login`,
  ]).slice(0, 4);

  for (const targetUrl of loginTargets) {
    let parsed: URL;
    try {
      parsed = new URL(targetUrl);
    } catch {
      continue;
    }
    if (!isInternalHostMatch(parsed.hostname, input.targetHostname)) {
      continue;
    }

    const apiLike = apiPathPattern.test(parsed.pathname) || /\/rest\//i.test(parsed.pathname);
    const body = apiLike
      ? JSON.stringify({
          email: username,
          username,
          password,
        })
      : new URLSearchParams({
          email: username,
          username,
          password,
        }).toString();
    const attempt = await loadAttempt(targetUrl, {
      method: "POST",
      timeoutMs: input.timeoutMs ?? 5_000,
      followRedirects: false,
      headers: {
        "content-type": apiLike ? "application/json" : "application/x-www-form-urlencoded",
      },
      body,
    });
    if (!attempt) {
      continue;
    }

    const session = extractAuthSessionFromAttempt(attempt, "provided-credentials", input.roleLabel?.trim() || null);
    if (session) {
      return {
        url: attempt.finalUrl,
        status: attempt.status,
        session,
      };
    }
  }

  return null;
}

async function runAuthenticatedEndpointProbes(input: {
  primaryOrigin: string;
  session: AuthSessionProof | null;
  timeoutMs?: number;
  maxEndpoints?: number;
}) {
  if (!input.session) {
    return [];
  }

  const endpoints = uniqueUrls([
    `${input.primaryOrigin}/rest/user/whoami`,
    `${input.primaryOrigin}/rest/user/authentication-details`,
    input.session.userId !== null ? `${input.primaryOrigin}/api/Users/${input.session.userId}` : "",
    input.session.basketId !== null ? `${input.primaryOrigin}/rest/basket/${input.session.basketId}` : "",
    input.session.basketId !== null ? `${input.primaryOrigin}/api/BasketItems?BasketId=${input.session.basketId}` : "",
    `${input.primaryOrigin}/rest/admin/application-configuration`,
    `${input.primaryOrigin}/api/Challenges`,
  ]).slice(0, input.maxEndpoints ?? 8);

  return (
    await mapLimited(endpoints, 3, async (url) => {
      const attempt = await loadAttempt(url, {
        timeoutMs: input.timeoutMs ?? 5_000,
        followRedirects: false,
        headers: input.session?.headers,
      });
      if (!attempt) {
        return null;
      }

      const contentType = attempt.headers["content-type"] ?? "";
      return {
        url: attempt.finalUrl,
        status: attempt.status,
        contentType,
        sensitiveResponse: attempt.status < 400 && looksLikeSensitiveApiPayload(attempt.bodyText),
        adminLike: /(admin|challenge|configuration|debug)/i.test(new URL(url).pathname),
        bodyLength: attempt.bodyText.length,
      } satisfies AuthenticatedEndpointProbe;
    })
  ).filter(isPresent);
}

function statefulAttackProbesAllowed(hostname: string) {
  return (
    process.env.FIXNX_ACTIVE_STATEFUL_PROBES === "1" ||
    /(?:juice-shop|webgoat|dvwa|vulnweb|hackazon|testfire|demo)/i.test(hostname)
  );
}

async function runStoredXssStatefulProbe(input: {
  primaryOrigin: string;
  targetHostname: string;
  session: AuthSessionProof | null;
  executeBrowser: boolean;
  timeoutMs?: number;
}) {
  if (!input.session || !statefulAttackProbesAllowed(input.targetHostname)) {
    return [];
  }

  const marker = createXssMarker("stored");
  const payload = controlledXssPayloads(marker)[0].value;
  const reviewTargets = [
    {
      url: `${input.primaryOrigin}/rest/products/1/reviews`,
      method: "PUT",
      body: JSON.stringify({ message: payload }),
    },
  ];

  const results: StoredXssProbeResult[] = [];
  for (const target of reviewTargets) {
    const attempt = await loadAttempt(target.url, {
      method: target.method,
      timeoutMs: input.timeoutMs ?? 5_000,
      followRedirects: false,
      headers: {
        ...input.session.headers,
        "content-type": "application/json",
      },
      body: target.body,
    });
    if (!attempt) {
      continue;
    }

    const readback = await loadAttempt(target.url, {
      timeoutMs: input.timeoutMs ?? 5_000,
      followRedirects: false,
      headers: input.session.headers,
    });
    let executed = false;
    let signals: StoredXssProbeResult["signals"] = [];
    const renderedUrl = `${input.primaryOrigin}/#/product/1`;
    if (input.executeBrowser && attempt.status < 400 && readback?.bodyText.includes(marker) && process.env.FIXNX_BROWSER_SCAN !== "0") {
      try {
        const verification = await verifyXssExecution({
          url: renderedUrl,
          marker,
          payload,
          contextOptions: {
            extraHTTPHeaders: input.session.cookieHeader ? { cookie: input.session.cookieHeader } : undefined,
          },
          localStorage: {
            ...(input.session.token ? { token: input.session.token } : {}),
            ...(input.session.basketId !== null && input.session.basketId !== undefined
              ? { bid: String(input.session.basketId) }
              : {}),
          },
          waitMs: 900,
        });
        executed = verification.executed;
        signals = verification.signals;
      } catch {
        executed = false;
      }
    }

    results.push({
      url: attempt.finalUrl,
      method: target.method,
      status: attempt.status,
      accepted: attempt.status >= 200 && attempt.status < 400,
      retrievable: Boolean(readback?.bodyText.includes(marker)),
      executed,
      payload: redactValue(payload),
      marker: redactValue(marker, 8),
      signals,
      renderedUrl,
    });
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

function classifyApiEndpoint(url: string, source: ApiEndpointClassification["source"] = "frontend") {
  let pathname = "";
  let search = "";
  try {
    const parsed = new URL(url);
    pathname = parsed.pathname.toLowerCase();
    search = parsed.search.toLowerCase();
  } catch {
    pathname = url.toLowerCase();
  }

  const combined = `${pathname}${search}`;
  const classes = new Set<string>();
  if (/(admin|manage|moderator|backoffice|console)/i.test(combined)) {
    classes.add("admin-looking");
  }
  if (/(login|signin|auth|oauth|session|token|password|reset|register|signup)/i.test(combined)) {
    classes.add("auth-looking");
  }
  if (/(debug|config|env|status|metrics|health|actuator|swagger|openapi|api-docs|schema)/i.test(combined)) {
    classes.add("debug/config");
  }
  if (/(user|users|me|account|profile|customer|member|order|invoice|basket|cart)/i.test(combined)) {
    classes.add("user/account");
  }
  if (/(upload|file|files|media|avatar|image|import)/i.test(combined)) {
    classes.add("upload");
  }
  if (/(search|filter|query|lookup|products|catalog|items|q=|query=|filter=)/i.test(combined)) {
    classes.add("search/filter");
  }
  if (classes.size === 0) {
    classes.add("public data");
  }

  return {
    url,
    classes: [...classes],
    source,
  } satisfies ApiEndpointClassification;
}

function exposedSensitiveFileKind(path: string, attempt: HttpAttempt, primaryAttempt: HttpAttempt) {
  if (!isSuccessfulNonChallengeResponse(attempt) || isLikelyEdgeInterstitial(attempt)) {
    return null;
  }

  const probe = {
    url: attempt.finalUrl,
    status: attempt.status,
    finalUrl: attempt.finalUrl,
    locationHeader: attempt.headers.location ?? "",
    headers: attempt.headers,
    bodyText: attempt.bodyText,
  };
  if (looksLikePrimaryHtmlShell(primaryAttempt, probe)) {
    return null;
  }

  const body = attempt.bodyText.slice(0, 80_000);
  const contentType = attempt.headers["content-type"] ?? "";
  if (path === "/.DS_Store") {
    return !isHtmlLikeResponse(attempt.headers, body) && /Bud1|\x00\x05\x16\x07/.test(body)
      ? "macOS directory metadata"
      : null;
  }
  if (/(swagger|openapi|api-docs)/i.test(path)) {
    return /"openapi"\s*:|"swagger"\s*:|"paths"\s*:|Swagger UI|api-docs/i.test(body)
      ? "API schema/documentation"
      : null;
  }
  if (/config\.json/i.test(path)) {
    return /application\/json/i.test(contentType) && /"(?:api|auth|database|firebase|token|secret|endpoint|baseUrl)"/i.test(body)
      ? "client/server configuration"
      : null;
  }
  if (/phpinfo\.php/i.test(path)) {
    return /phpinfo\(\)|PHP Version|<title>phpinfo/i.test(body) ? "PHP diagnostics" : null;
  }
  if (/server-status/i.test(path)) {
    return /Apache Server Status|Server uptime|Total accesses|Scoreboard/i.test(body) ? "server status page" : null;
  }
  if (/actuator/i.test(path)) {
    return /"_links"\s*:|"health"\s*:|"beans"\s*:|"env"\s*:|"heapdump"/i.test(body)
      ? "Spring actuator surface"
      : null;
  }
  if (/\.well-known/i.test(path)) {
    return directoryListingDetected(body) || /href=["'][^"']*\.well-known/i.test(body)
      ? ".well-known directory listing"
      : null;
  }

  return null;
}

function extractSensitiveRobotsPaths(bodyText: string) {
  return bodyText
    .split(/\r?\n/)
    .map((line) => line.trim())
    .flatMap((line) => {
      const match = line.match(/^disallow:\s*(\S+)/i);
      return match?.[1] ? [match[1]] : [];
    })
    .filter((path) => sensitivePathPattern.test(path) || /\.(?:bak|zip|sql|env|log|old|config)$/i.test(path))
    .slice(0, 12);
}

function formatDuration(milliseconds: number) {
  if (milliseconds < 1_000) {
    return `${milliseconds} ms`;
  }

  return `${(milliseconds / 1_000).toFixed(milliseconds < 10_000 ? 1 : 0)} sec`;
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
    { pattern: /\bAIza[0-9A-Za-z_-]{20,}\b/, label: "Google/Firebase API key", severity: "medium" },
    {
      pattern: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9._-]{10,}\.[A-Za-z0-9._-]{10,}\b/,
      label: "JWT-like token",
      severity: "high",
    },
    {
      pattern: /firebase(?:app|config)?[^<>{}]{0,80}{[^}]{0,500}\bapiKey\s*:\s*["'][^"']{12,}["'][^}]*}/i,
      label: "Firebase client configuration",
      severity: "medium",
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
      pattern: /https?:\/\/(?:localhost|127\.0\.0\.1|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}|[^/"'\s]+(?:\.internal|\.local|\.lan|\.corp|\.staging|\.dev))[^"'\s<]*/i,
      label: "Internal URL exposure",
      severity: "low",
    },
    {
      pattern: /https?:\/\/[a-z0-9.-]+\.s3[.-][a-z0-9-]+\.amazonaws\.com\/[^"'\s<]+|s3:\/\/[a-z0-9._-]+\/[^"'\s<]+/i,
      label: "S3 bucket URL",
      severity: "low",
    },
    {
      pattern: /sourceMappingURL=([^\s"'<>]+)/i,
      label: "Source map reference",
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

export async function runSecurityScan(
  target: NormalizedTarget,
  options: ScanRunOptions = {},
): Promise<CategoryScanResult> {
  const securityStartedAt = Date.now();
  const scanMode = resolveSecurityScanMode(target);
  const budgetMs = securityBudgetMs(scanMode);
  const phase = createSecurityPhaseLogger(target, scanMode);
  const hasBudgetFor = (minimumRemainingMs: number) => Date.now() - securityStartedAt + minimumRemainingMs < budgetMs;
  phase("start", { budgetMs });
  const fastBaseline = await runFastBaselinePhase(target, scanMode);
  phase("fast-baseline:complete", {
    findings: fastBaseline.findings.length,
    score: fastBaseline.score,
    durationMs: fastBaseline.durationMs,
    urlsChecked: fastBaseline.urlsChecked,
  });
  await options.onProgress?.({
    phase: "fast-baseline",
    message: `Initial results ready. ${fastBaseline.findings.length} baseline checks are visible while deeper checks continue.`,
    percent: 24,
    findings: fastBaseline.findings,
    score: fastBaseline.score,
    urlsChecked: fastBaseline.urlsChecked,
  });
  await options.onProgress?.({
    phase: "browser-render",
    message: "Initial results are ready. Rendering the site in a browser and mapping dynamic routes now.",
    percent: 38,
  });
  const artifacts = await loadAuditArtifacts(target);
  phase("artifacts:loaded", {
    rendered: artifacts.browserInspection.rendered,
    renderedPages: artifacts.browserInspection.renderedPageCount,
    networkRequests: artifacts.browserInspection.networkRequestCount,
  });
  const primaryAttempt = artifacts.context.primary;
  const primaryPage = artifacts.primaryPage;
  const primaryOrigin = getPrimaryOrigin(artifacts.context);

  if (!primaryAttempt || !primaryPage || !primaryOrigin) {
    throw new Error("Unable to fetch the target website.");
  }

  const findings: ScanFinding[] = [];
  const authContextStore = new AuthContextStore();
  authContextStore.upsert({
    id: "anonymous",
    label: "anonymous",
    headers: {},
  });
  const configuredAuthCookie = target.authCookieHeader?.trim() || getConfiguredAuthCookieHeader();
  const configuredSecondaryAuthCookie =
    target.secondaryAuthCookieHeader?.trim() ||
    process.env.FIXNX_SCAN_SECONDARY_AUTH_COOKIE_HEADER?.trim().slice(0, 8_000) ||
    process.env.FIXNX_SCAN_SECONDARY_AUTH_COOKIES?.trim().slice(0, 8_000) ||
    "";
  phase("setup:target-loaded", {
    primaryUrl: primaryAttempt.finalUrl,
    mode: scanMode,
    hasAuth: Boolean(configuredAuthCookie || target.authUsername),
    hasSecondaryAuth: Boolean(configuredSecondaryAuthCookie || target.secondaryAuthUsername),
  });
  const fastMode = scanMode === "Fast";
  const probeTimeoutMs = fastMode ? 3_500 : scanMode === "Authenticated" ? 5_000 : 8_000;
  const lightProbeTimeoutMs = fastMode ? 2_500 : scanMode === "Authenticated" ? 4_000 : 6_000;
  const firstPartyScriptLimit = fastMode ? 3 : 5;
  const sensitiveEndpointLimit = fastMode ? 8 : 12;
  phase("setup:budgets", {
    probeTimeoutMs,
    lightProbeTimeoutMs,
    firstPartyScriptLimit,
    sensitiveEndpointLimit,
  });
  let runtimePrimarySession: AuthSessionProof | null = null;
  let runtimeSecondarySession: AuthSessionProof | null = null;
  const authHeadersFor = (url: string): HeadersInit | undefined => {
    if (!configuredAuthCookie && !runtimePrimarySession) {
      return undefined;
    }

    try {
      const parsed = new URL(url);
      return isInternalHostMatch(parsed.hostname, target.targetHostname)
        ? configuredAuthCookie
          ? { cookie: configuredAuthCookie }
          : runtimePrimarySession?.headers
        : undefined;
    } catch {
      return undefined;
    }
  };
  const secondaryAuthHeadersFor = (url: string): HeadersInit | undefined => {
    if (
      (!configuredSecondaryAuthCookie || configuredSecondaryAuthCookie.startsWith("[") || configuredSecondaryAuthCookie.startsWith("{")) &&
      !runtimeSecondarySession
    ) {
      return undefined;
    }

    try {
      const parsed = new URL(url);
      return isInternalHostMatch(parsed.hostname, target.targetHostname)
        ? runtimeSecondarySession?.headers ?? { cookie: configuredSecondaryAuthCookie }
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
    timeoutMs: lightProbeTimeoutMs,
  });
  const pageForms = primaryAttemptIsInterstitial ? [] : primaryPage.formSnapshots;
  const metaCsrfTokenPresent = /<meta[^>]+name=["'][^"']*csrf[^"']*["'][^>]+content=["'][^"']+["']/i.test(
    primaryAttempt.bodyText,
  );
  const firstPartyScriptResources = (primaryAttemptIsInterstitial ? [] : primaryPage.resources).filter(
    (resource) => resource.kind === "script" && resource.internal,
  );
  const firstPartyScriptSamples = (
    await mapLimited(firstPartyScriptResources.slice(0, firstPartyScriptLimit), 3, async (resource) => {
      const attempt = await loadAttempt(resource.url, {
        timeoutMs: probeTimeoutMs,
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
  phase("javascript:samples-complete", {
    firstPartyScriptResources: firstPartyScriptResources.length,
    sampledScripts: firstPartyScriptSamples.length,
    elapsedMs: Date.now() - securityStartedAt,
  });
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
  ]).slice(0, sensitiveEndpointLimit);
  const sensitiveEndpointAttempts = (
    await mapLimited(sensitiveEndpointCandidates, 4, async (candidate) => {
      const attempt = await loadAttempt(candidate.url, {
        timeoutMs: probeTimeoutMs,
        followRedirects: false,
        headers: authHeadersFor(candidate.url),
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
  phase("surface:sensitive-endpoints-complete", {
    candidates: sensitiveEndpointCandidates.length,
    attempts: sensitiveEndpointAttempts.length,
    notable: notableSensitiveEndpointAttempts.length,
    elapsedMs: Date.now() - securityStartedAt,
  });
  await options.onProgress?.({
    phase: "attack-surface",
    message: `Attack surface mapped. ${notableSensitiveEndpointAttempts.length} sensitive endpoint candidate(s) need review while active probes continue.`,
    percent: 52,
    urlsChecked: sensitiveEndpointAttempts.length,
  });
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
  const [credentialSessionProbe, secondaryCredentialSessionProbe] = await Promise.all([
    runCredentialLoginProbe({
      primaryOrigin,
      loginUrl: target.authLoginUrl,
      username: target.authUsername,
      password: target.authPassword,
      roleLabel: target.authRoleLabel,
      targetHostname: target.targetHostname,
      timeoutMs: lightProbeTimeoutMs,
    }),
    runCredentialLoginProbe({
      primaryOrigin,
      loginUrl: target.secondaryAuthLoginUrl,
      username: target.secondaryAuthUsername,
      password: target.secondaryAuthPassword,
      roleLabel: target.secondaryAuthRoleLabel,
      targetHostname: target.targetHostname,
      timeoutMs: lightProbeTimeoutMs,
    }),
  ]);
  phase("auth:credentials-complete", {
    primaryCredentialSession: Boolean(credentialSessionProbe?.session),
    secondaryCredentialSession: Boolean(secondaryCredentialSessionProbe?.session),
    elapsedMs: Date.now() - securityStartedAt,
  });
  runtimePrimarySession = credentialSessionProbe?.session ?? null;
  runtimeSecondarySession = secondaryCredentialSessionProbe?.session ?? null;

  const httpsProtectedOrChallenged = Boolean(
    httpsDirectAttempt &&
      ([401, 403, 405].includes(httpsDirectAttempt.status) || isLikelyEdgeInterstitial(httpsDirectAttempt)),
  );
  const internalScriptCount = primaryPage.resources.filter(
    (resource) => resource.kind === "script" && resource.internal,
  ).length;
  const appShellLikely =
    internalScriptCount >= 3 &&
    primaryPage.nodeCount <= 120 &&
    primaryPage.formSnapshots.length === 0 &&
    (
      primaryPage.resources.some((resource) =>
        resource.kind === "script" &&
        /(?:^|\/)(?:main|runtime|polyfills|app|bundle|chunk-[^/?#]+)\.[^/?#]*\.?js(?:[?#]|$)/i.test(resource.url),
      ) ||
      /<app-root\b|ng-version|data-beasties-container|rel=["']modulepreload/i.test(primaryAttempt.bodyText.slice(0, 120_000))
    );
  const knownVulnerableTrainingApp =
    /owasp juice shop|probably the most modern and sophisticated insecure web application|x-recruiting.*#\/jobs/i.test(
      `${primaryPage.title} ${primaryPage.description} ${primaryAttempt.headers["x-recruiting"] ?? ""} ${primaryAttempt.bodyText.slice(0, 8_000)}`,
    );
  const browserCoverageStatus = artifacts.browserInspection.rendered
    ? { status: "pass" as const, severity: "info" as const }
    : artifacts.browserInspection.attempted
      ? { status: "warning" as const, severity: appShellLikely ? ("high" as const) : ("low" as const) }
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
        appShellLikely,
        internalScriptCount,
        nodeCount: primaryPage.nodeCount,
        crawledPages: artifacts.crawledPages.map((page) => page.url),
      },
    }),
  );

  if (knownVulnerableTrainingApp) {
    findings.push(
      buildSecurityCheck({
        checkKey: "known-vulnerable-training-app",
        title: "Known intentionally vulnerable application",
        status: "fail",
        severity: "critical",
        confidence: "confirmed",
        scoreWeight: 1,
        shortDescription:
          "The target identifies as OWASP Juice Shop, an intentionally vulnerable security training application.",
        whyItMatters:
          "An intentionally vulnerable application exposed on a public origin should be treated as critical unless it is an isolated lab environment.",
        recommendation:
          "Do not expose intentionally vulnerable training applications on public production infrastructure. Restrict access, isolate the lab, or remove the deployment.",
        evidence: {
          checkedUrl: primaryAttempt.finalUrl,
          expectedLocation: "Application title, description, and response headers",
          summary: "The sampled response contains OWASP Juice Shop / intentionally insecure application markers.",
          title: primaryPage.title,
          description: primaryPage.description,
          xRecruiting: primaryAttempt.headers["x-recruiting"] ?? null,
        },
      }),
    );
  }

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
  const cspDirectives = effectiveCspHeader
    .split(";")
    .map((directive) => directive.trim().toLowerCase())
    .filter(Boolean);
  const cspHasScriptControl = /(^|;)\s*(script-src|default-src)\b/i.test(effectiveCspHeader);
  const cspHasNonceOrHash = /'(?:nonce-[^']+|sha(?:256|384|512)-[^']+)'/i.test(effectiveCspHeader);
  const cspHasStrictDynamic = /'strict-dynamic'/i.test(effectiveCspHeader);
  const cspUnsafeInlineIsMitigated = cspHasNonceOrHash || cspHasStrictDynamic;
  const cspOnlyUpgradeInsecureRequests =
    cspDirectives.length > 0 &&
    cspDirectives.every((directive) => directive === "upgrade-insecure-requests");
  const cspWeak = effectiveCspHeader
    ? /unsafe-eval/i.test(effectiveCspHeader) ||
      (/unsafe-inline/i.test(effectiveCspHeader) && !cspUnsafeInlineIsMitigated) ||
      cspOnlyUpgradeInsecureRequests ||
      !cspHasScriptControl
    : false;
  const cspReportOnlyLooksReviewable =
    Boolean(cspReportOnlyHeader) &&
    cspHasScriptControl &&
    !cspOnlyUpgradeInsecureRequests;
  const cspStatus = cspHeader
    ? cspWeak
      ? { status: "warning" as const, severity: "low" as const }
      : { status: "pass" as const, severity: "info" as const }
    : cspReportOnlyHeader
      ? {
          status: cspReportOnlyLooksReviewable ? ("info" as const) : ("warning" as const),
          severity: cspReportOnlyLooksReviewable ? ("info" as const) : ("low" as const),
        }
      : primaryAttemptIsInterstitial
        ? { status: "info" as const, severity: "info" as const }
        : { status: "warning" as const, severity: "low" as const };
  findings.push(
    buildSecurityCheck({
      checkKey: "content-security-policy",
      title: cspWeak ? "Weak Content-Security-Policy" : "Content-Security-Policy",
      scoreWeight: 0.7,
      ...cspStatus,
      shortDescription: cspHeader
        ? cspWeak
          ? `Content-Security-Policy is set, but it is weak: "${cspHeader}".`
          : `Content-Security-Policy is set to "${cspHeader}".`
        : cspReportOnlyHeader
          ? `Content-Security-Policy-Report-Only is set to "${cspReportOnlyHeader}".`
          : primaryAttemptIsInterstitial
            ? "The sampled response looked like an edge interstitial, so CSP enforcement on the underlying app could not be verified."
          : "Content-Security-Policy is missing from the main response.",
      whyItMatters:
        "A strong CSP reduces exposure to XSS and limits where scripts, frames, and other content can load from.",
      recommendation: cspHeader
        ? cspWeak
          ? "Add a stronger CSP with script-src, object-src, base-uri, frame-ancestors, and default-src directives where feasible."
          : "Tighten permissive directives like `unsafe-inline` or `unsafe-eval` when feasible."
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
            weakPolicy: cspWeak,
            onlyUpgradeInsecureRequests: cspOnlyUpgradeInsecureRequests,
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
        timeoutMs: lightProbeTimeoutMs,
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
    sensitivity: classifyCookieSensitivity(cookieName(cookie)),
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
    const nonSensitiveMissing = check.missing.filter((cookie) => !cookie.sensitive);
    const status =
      check.items.length === 0
        ? "pass"
        : sensitiveMissing.length > 0
          ? "warning"
          : check.missing.length > 0
            ? "info"
            : "pass";
    const severity: Severity =
      status === "warning" ? check.flag === "SameSite" ? "low" : "medium" : "info";
    const nonSensitiveOnly = sensitiveMissing.length === 0 && nonSensitiveMissing.length > 0;

    findings.push(
      buildSecurityCheck({
        checkKey: check.checkKey,
        title: nonSensitiveOnly ? `${check.flag} cookie hardening note` : check.title,
        scoreWeight:
          sensitiveMissing.length > 0
            ? 0.85
            : check.missing.length > 0
              ? 0.15
              : 0.4,
        status,
        severity,
        confidence: sensitiveMissing.length > 0 ? "likely" : "info",
        shortDescription:
          applicationCookies.length === 0 && cookies.length > 0
            ? "Only infrastructure cookies were observed on the sampled response."
            : check.items.length === 0
              ? "No response cookies were set on the primary document."
            : check.missing.length === 0
              ? `All ${check.items.length} sampled response cookies include ${check.flag}.`
              : nonSensitiveOnly
                ? `${nonSensitiveMissing.length} sampled non-sensitive cookie(s) are missing ${check.flag}; no sampled auth/session cookie was affected.`
              : `${check.missing.length} of ${check.items.length} sampled response cookies are missing ${check.flag}.`,
        whyItMatters: nonSensitiveOnly
          ? "Cookie flag gaps on tracking, analytics, preference, or unknown cookies are hardening/privacy notes unless they protect an authenticated session."
          : check.whyItMatters,
        recommendation:
          applicationCookies.length === 0 && cookies.length > 0
            ? "No application cookies were observed on this response, so this check is informational."
            : check.items.length === 0
              ? "No change is required unless your application sets cookies on other routes."
            : nonSensitiveOnly
              ? "Review whether these cookies need the flag for privacy or compatibility, but prioritize auth/session cookies first."
            : check.recommendation,
        evidence: {
          checkedUrl: primaryAttempt.finalUrl,
          expectedLocation: 'response.headers["set-cookie"]',
          summary:
            applicationCookies.length === 0 && cookies.length > 0
              ? "Only infrastructure or edge-network cookies were set on the sampled response."
            : check.items.length === 0
              ? "The primary document response did not set cookies."
            : nonSensitiveOnly
              ? `Only non-sensitive sampled cookies are missing ${check.flag}.`
              : `${check.missing.length} sampled cookies are missing ${check.flag}.`,
          cookieCount: check.items.length,
          missingCount: check.missing.length,
          sensitiveCookies: check.items.filter((cookie) => cookie.sensitive).map((cookie) => cookie.name),
          sensitiveMissing: sensitiveMissing.map((cookie) => cookie.name),
          nonSensitiveMissing: nonSensitiveMissing.map((cookie) => cookie.name),
          cookieSensitivity: check.items.map((cookie) => ({
            name: cookie.name,
            sensitivity: cookie.sensitivity,
          })),
          locations: check.missing.slice(0, 8).map((cookie) =>
            createResponseLocation({
              label: `Cookie ${cookie.name}`,
              url: primaryAttempt.finalUrl,
              path: 'response.headers["set-cookie"]',
              value: cookie.raw,
              note: `Missing ${check.flag}. Sensitivity: ${cookie.sensitivity}.`,
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
        sensitiveForms: sensitiveForms.map((form) => ({
          url: form.url,
          method: form.method,
          sensitiveKinds: form.sensitiveKinds,
          csrfFieldNames: form.csrfFieldNames,
        })),
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
          ? "No obvious session or auth cookies were detected on the primary document; token-based authentication is analyzed separately after login/bypass probes."
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
            : cookieHints.sensitiveCookies.length === 0
              ? "No session cookies were detected on the primary document. This is a cookie-only coverage statement, not proof that no session exists."
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
  const spaRouteSignals =
    artifacts.browserInspection.routeMap.pages.some((url) => /#\/?/.test(url)) ||
    artifacts.browserInspection.routeMap.inputs.some((input) => input.sensitiveKinds.includes("search")) ||
    primaryPage.resources.some((resource) => resource.kind === "script" && resource.internal);
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
      ...artifacts.browserInspection.routeMap.inputs.flatMap((input) =>
        riskyInputParamPattern.test(input.name) || input.sensitiveKinds.includes("search")
          ? [`${input.sourceUrl}::${input.name}`]
          : [],
      ),
      ...artifacts.browserInspection.routeMap.pages
        .filter((url) => /#\/?(?:search|products|catalog|login|account|admin)/i.test(url))
        .map((url) => `${url}::q`),
      ...["/search", "/api/search", "/api/products", "/rest/products/search"].map(
        (path) => `${primaryOrigin}${path}::q`,
      ),
      ...(spaRouteSignals
        ? [
            `${primaryOrigin}/#/search::q`,
            `${primaryOrigin}/#/search?query=fixnx::query`,
          ]
        : []),
      ...inputProbeTargets.slice(0, 2).map((url) => `${url}::q`),
    ].slice(0, fastMode ? 10 : 14),
  ).map((entry) => {
    const [url, parameter] = entry.split("::");
    return { url, parameter };
  });
  const reflectionToken = `cyberauditreflect${Date.now().toString(36)}`;
  const reflectionResults = (
    await mapLimited(inputProbeConfigs, 3, async (config) => {
      const probeUrl = applyProbeParameter(config.url, config.parameter, reflectionToken);
      const attempt = await loadAttempt(probeUrl, {
        timeoutMs: probeTimeoutMs,
        followRedirects: false,
        headers: authHeadersFor(probeUrl),
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
      confidence: reflectionResults.length === 0 ? "info" : "likely",
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

  const activeXssPayloads = [
    `"><svg data-fixnx-xss="1">`,
    `'><img src=x data-fixnx-xss=1>`,
    `javascript:window.__fixnxXss`,
  ];
  const activeXssProbeConfigs = inputProbeConfigs.slice(0, fastMode ? 3 : 5);
  const boundedActiveXssPayloads = fastMode ? activeXssPayloads.slice(0, 2) : activeXssPayloads;
  const activeXssResults = (
    await mapLimited(activeXssProbeConfigs, 3, async (config) => {
      return (
        await mapLimited(boundedActiveXssPayloads, 1, async (payload) => {
          const probeUrl = applyProbeParameter(config.url, config.parameter, payload);
          const attempt = await loadAttempt(probeUrl, {
            timeoutMs: probeTimeoutMs,
            followRedirects: false,
            headers: authHeadersFor(probeUrl),
          });
          if (!attempt || attempt.status >= 500) {
            return null;
          }

          const rawPayloadReflected = attempt.bodyText.includes(payload);
          if (!rawPayloadReflected) {
            return null;
          }

          return {
            url: attempt.finalUrl,
            parameter: config.parameter,
            payload,
            status: attempt.status,
            rawPayloadReflected,
            context: classifyReflectionContext(attempt.bodyText, payload),
          } satisfies ActiveXssProbeResult;
        })
      ).filter(isPresent);
    })
  ).flat();
  const activeXssFailure = activeXssResults.find(
    (result) => result.context && ["html", "attribute", "url-attribute", "script"].includes(result.context),
  );
  const shouldRunBrowserXssExecution =
    scanMode !== "Fast" &&
    hasBudgetFor(8_000) &&
    (activeXssResults.length > 0 ||
      reflectionResults.length > 0 ||
      activeXssProbeConfigs.some((config) => /#\/?/.test(config.url)) ||
      artifacts.browserInspection.routeMap.inputs.some((input) => input.sensitiveKinds.includes("search")));
  phase("xss:active-complete", {
    activeXssResults: activeXssResults.length,
    browserExecutionQueued: shouldRunBrowserXssExecution,
    elapsedMs: Date.now() - securityStartedAt,
  });
  await options.onProgress?.({
    phase: "active-probes",
    message: "Running safe active probes for XSS, SQL injection, authentication, and authorization.",
    percent: 68,
  });
  const browserXssExecutionResults = shouldRunBrowserXssExecution
    ? await runBrowserXssExecutionProbes(
        activeXssProbeConfigs.slice(0, scanMode === "Deep" ? 4 : 2),
        configuredAuthCookie,
      )
    : [];
  phase("xss:browser-execution-complete", {
    browserXssExecutionResults: browserXssExecutionResults.length,
    elapsedMs: Date.now() - securityStartedAt,
  });
  const confirmedBrowserXss = browserXssExecutionResults.find((result) => result.executed);
  findings.push(
    buildSecurityCheck({
      checkKey: "active-xss-payload-reflection",
      title: "Active XSS exploit probe",
      scoreWeight: 1.4,
      confidence: confirmedBrowserXss ? "confirmed" : activeXssFailure || activeXssResults.length > 0 ? "likely" : "info",
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
        checkedUrl: activeXssProbeConfigs.map((config) => config.url).join(", "),
        expectedLocation: "Injected HTML payload should be encoded before rendering",
        summary: confirmedBrowserXss
            ? "The browser-side execution marker was set by the injected payload."
          : activeXssFailure
            ? "A raw HTML payload came back in an executable-capable context."
          : activeXssResults.length > 0
            ? "The payload was reflected raw, but the context needs manual confirmation."
            : "No raw active XSS payload reflection was detected.",
        probePayloads: activeXssPayloads.map((payload) => redactValue(payload)),
        browserExecution: browserXssExecutionResults.map((result) => ({
          url: result.url,
          parameter: result.parameter,
          status: result.status,
          executed: result.executed,
          payload: redactValue(result.payload),
          signals: result.signals ?? [],
          domState: result.domState ?? null,
        })),
        results: activeXssResults.map((result) => ({
          url: result.url,
          parameter: result.parameter,
          payload: redactValue(result.payload),
          status: result.status,
          context: result.context,
        })),
        confidence: confirmedBrowserXss ? "confirmed-browser-execution" : activeXssFailure ? "likely-dangerous-reflection" : activeXssResults.length > 0 ? "likely-raw-reflection" : "not-detected",
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
      confidence: confirmedBrowserXss ? "confirmed" : xssStatus.status === "pass" ? "info" : "likely",
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
          signals: result.signals ?? [],
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
  const boundedSqlProbePayloads = fastMode
    ? sqlProbePayloads.filter((payload) => !/sleep/i.test(payload))
    : sqlProbePayloads;
	  const sqlProbeConfigs = inputProbeConfigs
	    .filter((config) => {
	      const context = classifyParameter(config.parameter, config.url);
	      return context === "search" || context === "id" || context === "filter" || context === "sort" || context === "pagination" || context === "unknown";
	    })
	    .slice(0, fastMode ? 4 : 6);
	  const sqlProbeResults = (
	    await mapLimited(sqlProbeConfigs, 2, async (config, configIndex) => {
	      const parameterContext = classifyParameter(config.parameter, config.url);
	      const baselineUrl = applyProbeParameter(config.url, config.parameter, sqlProbeToken);
	      const baselineAttempt = await loadAttempt(baselineUrl, {
	        timeoutMs: probeTimeoutMs,
	        followRedirects: false,
	        headers: authHeadersFor(baselineUrl),
	      });
	      const baselineRecordCount = baselineAttempt ? countStructuredRecords(baselineAttempt.bodyText) : null;

      return (
        await mapLimited(
          configIndex < 2
            ? boundedSqlProbePayloads
            : boundedSqlProbePayloads.filter((payload) => !/sleep/i.test(payload)),
          1,
          async (payload) => {
          const probeUrl = applyProbeParameter(config.url, config.parameter, payload);
          const attempt = await loadAttempt(probeUrl, {
            timeoutMs: probeTimeoutMs,
            followRedirects: false,
            headers: authHeadersFor(probeUrl),
          });
          if (!attempt) {
            return null;
          }

	          const probeRecordCount = countStructuredRecords(attempt.bodyText);
	          const baselineDurationMs = baselineAttempt?.totalDurationMs ?? baselineAttempt?.durationMs ?? null;
	          const probeDurationMs = attempt.totalDurationMs ?? attempt.durationMs ?? null;
	          const probeSignature = buildSqlResponseSignature({
	            status: attempt.status,
	            contentType: attempt.headers["content-type"] ?? "",
	            bodyText: attempt.bodyText,
	            url: attempt.finalUrl,
	          });
	          const dbErrorMatch = findStrictDbErrorSignature(attempt.bodyText);
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
	          const dynamicSignal = highDynamicResponseSignal({
	            url: attempt.finalUrl,
	            headers: attempt.headers,
	            bodyText: attempt.bodyText,
	            signature: probeSignature,
	          });
	          const weakContext =
	            parameterContext === "redirect" ||
	            parameterContext === "auth-flow" ||
	            parameterContext === "tracking" ||
	            (dynamicSignal.highDynamic && !recordExpansion && !dbErrorMatch);
	          const evidenceStrength: EvidenceStrength = recordExpansion
	            ? "exploit-proof"
	            : dbErrorMatch
	              ? "moderate"
	              : "weak";

	          return {
	            url: attempt.finalUrl,
	            parameter: config.parameter,
	            parameterContext,
	            payload,
	            status: attempt.status,
	            baselineStatus: baselineAttempt?.status ?? null,
            baselineDurationMs,
            probeDurationMs,
	            sqlError: Boolean(dbErrorMatch),
	            dbErrorSignature: dbErrorMatch?.signature ?? null,
	            dbErrorFamily: dbErrorMatch?.family ?? null,
	            dbErrorExcerpt: dbErrorMatch?.excerpt ?? null,
	            serverError: attempt.status >= 500 && (baselineAttempt?.status ?? 200) < 500,
	            baselineRecordCount,
	            probeRecordCount,
	            recordExpansion,
	            timeDelay,
	            evidenceStrength,
	            falsePositiveRisk: weakContext ? "high" : dbErrorMatch ? "medium" : "low",
	          } satisfies ActiveSqlProbeResult;
          },
        )
      ).filter(isPresent);
    })
  ).flat();
	  const booleanSqlProbeResults = (
	    await mapLimited(sqlProbeConfigs.slice(0, fastMode ? 2 : 4), 2, async (config) => {
	      const parameterContext = classifyParameter(config.parameter, config.url);
	      const baselineUrl = applyProbeParameter(config.url, config.parameter, sqlProbeToken);
	      const truePayload = "' OR 1=1--";
      const falsePayload = "' AND 1=2--";
      const trueUrl = applyProbeParameter(config.url, config.parameter, truePayload);
      const falseUrl = applyProbeParameter(config.url, config.parameter, falsePayload);
      const [baselineAttempt, trueAttempt, falseAttempt] = await Promise.all([
        loadAttempt(baselineUrl, {
          timeoutMs: probeTimeoutMs,
          followRedirects: false,
          headers: authHeadersFor(baselineUrl),
        }),
        loadAttempt(trueUrl, {
          timeoutMs: probeTimeoutMs,
          followRedirects: false,
          headers: authHeadersFor(trueUrl),
        }),
        loadAttempt(falseUrl, {
          timeoutMs: probeTimeoutMs,
          followRedirects: false,
          headers: authHeadersFor(falseUrl),
        }),
      ]);
      if (!trueAttempt || !falseAttempt) {
        return null;
      }

      const baselineRecordCount = baselineAttempt ? countStructuredRecords(baselineAttempt.bodyText) : null;
	      const trueRecordCount = countStructuredRecords(trueAttempt.bodyText);
	      const falseRecordCount = countStructuredRecords(falseAttempt.bodyText);
	      const recordDifference =
	        trueRecordCount !== null &&
	        falseRecordCount !== null &&
	        trueRecordCount >= Math.max(3, falseRecordCount + 3);
	      const trueSignature = buildSqlResponseSignature({
	        status: trueAttempt.status,
	        contentType: trueAttempt.headers["content-type"] ?? "",
	        bodyText: trueAttempt.bodyText,
	        url: trueAttempt.finalUrl,
	      });
	      const falseSignature = buildSqlResponseSignature({
	        status: falseAttempt.status,
	        contentType: falseAttempt.headers["content-type"] ?? "",
	        bodyText: falseAttempt.bodyText,
	        url: falseAttempt.finalUrl,
	      });
	      const highDynamic =
	        highDynamicResponseSignal({
	          url: trueAttempt.finalUrl,
	          headers: trueAttempt.headers,
	          bodyText: trueAttempt.bodyText,
	          signature: trueSignature,
	        }).highDynamic ||
	        highDynamicResponseSignal({
	          url: falseAttempt.finalUrl,
	          headers: falseAttempt.headers,
	          bodyText: falseAttempt.bodyText,
	          signature: falseSignature,
	        }).highDynamic;
	      const weakParameterContext =
	        parameterContext === "redirect" || parameterContext === "auth-flow" || parameterContext === "tracking";
	      const diffDimensions = responseDiffDimensions(trueSignature, falseSignature).filter((dimension) => {
	        const noisyHtml =
	          highDynamic ||
	          trueSignature.isCaptchaOrBotPage ||
	          falseSignature.isCaptchaOrBotPage ||
	          trueSignature.isLoginPage ||
	          falseSignature.isLoginPage ||
	          trueSignature.isRedirectValidationPage ||
	          falseSignature.isRedirectValidationPage;
	        return !noisyHtml || (dimension !== "stable-text" && dimension !== "length-bucket");
	      });
	      const strongDiff = diffDimensions.some((dimension) => dimension === "status" || dimension === "record-count" || dimension === "json-shape");

	      return {
	        url: trueAttempt.finalUrl,
	        parameter: config.parameter,
	        parameterContext,
	        truePayload,
	        falsePayload,
        baselineStatus: baselineAttempt?.status ?? null,
        trueStatus: trueAttempt.status,
        falseStatus: falseAttempt.status,
        baselineRecordCount,
        trueRecordCount,
	        falseRecordCount,
	        trueBodyLength: trueAttempt.bodyText.length,
	        falseBodyLength: falseAttempt.bodyText.length,
	        responseDifference: !weakParameterContext && (recordDifference || (strongDiff && diffDimensions.length >= 2)),
	        diffDimensions,
	        highDynamic,
	      } satisfies BooleanSqlProbeResult;
	    })
  ).filter(isPresent);
  phase("sql:active-complete", {
    sqlProbes: sqlProbeResults.length,
    booleanProbes: booleanSqlProbeResults.length,
    elapsedMs: Date.now() - securityStartedAt,
  });
  const blindSqlProbeResults = hasBudgetFor(fastMode ? 5_000 : 10_000)
    ? await runBlindSqlInjectionProbe({
        configs: sqlProbeConfigs,
        headersFor: authHeadersFor,
        mode: scanMode,
        maxParameters: scanMode === "Deep" ? 6 : scanMode === "Authenticated" ? 4 : 1,
        timeoutMs: scanMode === "Deep" ? 7_000 : lightProbeTimeoutMs,
      })
    : [];
  phase("sql:blind-complete", {
    blindSqlProbes: blindSqlProbeResults.length,
    skipped: blindSqlProbeResults.length === 0 && sqlProbeConfigs.length > 0,
    elapsedMs: Date.now() - securityStartedAt,
  });
	  const recordExpansionSqlResult = sqlProbeResults.find((result) => result.recordExpansion);
	  const strictDbErrorSqlResult = sqlProbeResults.find((result) => result.sqlError && result.dbErrorSignature);
	  const anomalousSqlResult = sqlProbeResults.find((result) => result.serverError);
	  const timeBasedSqlResult = sqlProbeResults.find((result) => result.timeDelay);
	  const repeatedBlindSqlResult = blindSqlProbeResults.find((result) => result.confidence === "CONFIRMED");
	  const likelyBlindSqlResult = blindSqlProbeResults.find((result) => result.confidence === "LIKELY");
	  const booleanSqlResult = booleanSqlProbeResults.find((result) => result.responseDifference);
	  const sqlEvidenceResult = recordExpansionSqlResult ?? strictDbErrorSqlResult ?? null;
	  const sqlFindingEvidenceStrength: EvidenceStrength = recordExpansionSqlResult
	    ? "exploit-proof"
	    : repeatedBlindSqlResult
	      ? "strong"
	      : strictDbErrorSqlResult || booleanSqlResult || likelyBlindSqlResult
	        ? "moderate"
	        : "weak";
	  const sqlFindingFalsePositiveRisk =
	    sqlEvidenceResult?.falsePositiveRisk ??
	    likelyBlindSqlResult?.falsePositiveRisk ??
	    (booleanSqlResult?.highDynamic ? "high" : sqlFindingEvidenceStrength === "weak" ? "high" : "medium");
	  const sqlStatus = recordExpansionSqlResult || repeatedBlindSqlResult
	    ? { status: "fail" as const, severity: "critical" as const }
	    : strictDbErrorSqlResult || booleanSqlResult || likelyBlindSqlResult
	      ? { status: "warning" as const, severity: "high" as const }
	    : timeBasedSqlResult
	      ? { status: "warning" as const, severity: "medium" as const }
	    : anomalousSqlResult
	      ? { status: "warning" as const, severity: "medium" as const }
	      : { status: "pass" as const, severity: "info" as const };
  findings.push(
    buildSecurityCheck({
      checkKey: "sql-injection-risk-indicators",
      title: "SQL injection active probe",
      scoreWeight: 1.6,
      ...sqlStatus,
	      confidence: recordExpansionSqlResult || repeatedBlindSqlResult ? "confirmed" : booleanSqlResult || likelyBlindSqlResult || strictDbErrorSqlResult || timeBasedSqlResult || anomalousSqlResult ? "likely" : "info",
	      shortDescription: recordExpansionSqlResult
	        ? `A SQL-style payload on ${recordExpansionSqlResult.url} expanded the structured response from ${recordExpansionSqlResult.baselineRecordCount ?? 0} to ${recordExpansionSqlResult.probeRecordCount ?? 0} records.`
	        : strictDbErrorSqlResult
	          ? `A sampled parameter on ${strictDbErrorSqlResult.url} exposed a strict database error signature, but exploit behavior was not proven.`
	        : repeatedBlindSqlResult
	          ? `Repeated blind SQL probes on ${repeatedBlindSqlResult.url} produced stable ${repeatedBlindSqlResult.technique} evidence.`
        : booleanSqlResult
          ? `Boolean SQL payloads on ${booleanSqlResult.url} produced a clear true/false response difference.`
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
	            ? "No SQL injection proof was observed: no record-count, boolean, timing, or strict DB-error exploit evidence was collected."
	            : recordExpansionSqlResult || repeatedBlindSqlResult
	              ? "Strong SQL injection evidence was collected."
	              : "The signal is intentionally kept likely because exploitability proof was incomplete.",
	        probePayloads: sqlProbePayloads.map((payload) => redactValue(payload)),
	        url: sqlEvidenceResult?.url ?? repeatedBlindSqlResult?.url ?? booleanSqlResult?.url ?? timeBasedSqlResult?.url ?? anomalousSqlResult?.url ?? null,
	        parameter: sqlEvidenceResult?.parameter ?? repeatedBlindSqlResult?.parameter ?? booleanSqlResult?.parameter ?? timeBasedSqlResult?.parameter ?? anomalousSqlResult?.parameter ?? null,
	        parameterContext: sqlEvidenceResult?.parameterContext ?? repeatedBlindSqlResult?.parameterContext ?? booleanSqlResult?.parameterContext ?? null,
	        payload: sqlEvidenceResult?.payload
	          ? redactValue(sqlEvidenceResult.payload)
	          : repeatedBlindSqlResult
	            ? repeatedBlindSqlResult.technique
          : booleanSqlResult?.truePayload
            ? redactValue(booleanSqlResult.truePayload)
            : timeBasedSqlResult?.payload
              ? redactValue(timeBasedSqlResult.payload)
              : anomalousSqlResult?.payload
                ? redactValue(anomalousSqlResult.payload)
                : null,
	        beforeStatus: sqlEvidenceResult?.baselineStatus ?? repeatedBlindSqlResult?.baseline[0]?.status ?? booleanSqlResult?.falseStatus ?? timeBasedSqlResult?.baselineStatus ?? anomalousSqlResult?.baselineStatus ?? null,
	        afterStatus: sqlEvidenceResult?.status ?? repeatedBlindSqlResult?.trueCondition?.[0]?.status ?? booleanSqlResult?.trueStatus ?? timeBasedSqlResult?.status ?? anomalousSqlResult?.status ?? null,
	        responseDiff: recordExpansionSqlResult
	          ? `${recordExpansionSqlResult.baselineRecordCount ?? 0} to ${recordExpansionSqlResult.probeRecordCount ?? 0} records`
	          : repeatedBlindSqlResult
	            ? repeatedBlindSqlResult.evidenceSummary
	          : booleanSqlResult
	            ? `true=${booleanSqlResult.trueRecordCount ?? booleanSqlResult.trueBodyLength}, false=${booleanSqlResult.falseRecordCount ?? booleanSqlResult.falseBodyLength}; dimensions=${booleanSqlResult.diffDimensions.join(", ") || "none"}`
	          : strictDbErrorSqlResult
	            ? `strict DB error signature: ${strictDbErrorSqlResult.dbErrorSignature}`
	          : timeBasedSqlResult
	            ? `${Math.max(0, (timeBasedSqlResult.probeDurationMs ?? 0) - (timeBasedSqlResult.baselineDurationMs ?? 0))} ms slower`
            : anomalousSqlResult?.serverError
              ? "probe caused server error while baseline did not"
              : "not detected",
        results: sqlProbeResults.map((result) => ({
          url: result.url,
          parameter: result.parameter,
          payload: redactValue(result.payload),
	          status: result.status,
	          parameterContext: result.parameterContext,
	          baselineStatus: result.baselineStatus,
          baselineDurationMs: result.baselineDurationMs,
          probeDurationMs: result.probeDurationMs,
	          sqlError: result.sqlError,
	          dbErrorSignature: result.dbErrorSignature,
	          dbErrorFamily: result.dbErrorFamily,
	          serverError: result.serverError,
          baselineRecordCount: result.baselineRecordCount,
          probeRecordCount: result.probeRecordCount,
          recordExpansion: result.recordExpansion,
	          timeDelay: result.timeDelay,
	          evidenceStrength: result.evidenceStrength,
	          falsePositiveRisk: result.falsePositiveRisk,
	        })),
        booleanResults: booleanSqlProbeResults.map((result) => ({
          url: result.url,
          parameter: result.parameter,
          truePayload: redactValue(result.truePayload),
          falsePayload: redactValue(result.falsePayload),
          trueStatus: result.trueStatus,
          falseStatus: result.falseStatus,
          trueRecordCount: result.trueRecordCount,
          falseRecordCount: result.falseRecordCount,
          trueBodyLength: result.trueBodyLength,
	          falseBodyLength: result.falseBodyLength,
	          responseDifference: result.responseDifference,
	          diffDimensions: result.diffDimensions,
	          highDynamic: result.highDynamic,
	        })),
	        blindSqlResults: blindSqlProbeResults,
	        repeatedProbeConfirmed: Boolean(repeatedBlindSqlResult),
	        evidenceStrength: sqlFindingEvidenceStrength,
	        falsePositiveRisk: sqlFindingFalsePositiveRisk,
	        dbErrorSignature: strictDbErrorSqlResult?.dbErrorSignature ?? null,
	        dbErrorFamily: strictDbErrorSqlResult?.dbErrorFamily ?? null,
	        dbErrorExcerpt: strictDbErrorSqlResult?.dbErrorExcerpt ?? null,
	        confidence: recordExpansionSqlResult
	          ? "confirmed-record-count-difference"
	          : repeatedBlindSqlResult
	            ? "confirmed-blind-repeated"
	            : strictDbErrorSqlResult
	              ? "likely-strict-db-error-without-exploit-diff"
	              : booleanSqlResult
	                ? "likely-boolean-multidimension"
	                : timeBasedSqlResult
	                  ? "suspected-time-based-single-probe"
	                  : anomalousSqlResult
	                    ? "suspected-server-error"
	                    : "not-detected",
      },
    }),
  );

  findings.push(
    buildSecurityCheck({
      checkKey: "blind-sql-injection-probe",
      title: "Blind SQL injection probe",
      scoreWeight: 1.45,
	      status: repeatedBlindSqlResult ? "fail" : likelyBlindSqlResult || booleanSqlResult || timeBasedSqlResult ? "warning" : "pass",
	      severity: repeatedBlindSqlResult ? "critical" : likelyBlindSqlResult || booleanSqlResult ? "high" : timeBasedSqlResult ? "medium" : "info",
      confidence: repeatedBlindSqlResult ? "confirmed" : likelyBlindSqlResult || booleanSqlResult || timeBasedSqlResult ? "likely" : "info",
      shortDescription: repeatedBlindSqlResult
        ? `Repeated ${repeatedBlindSqlResult.technique} blind SQL probes produced stable proof on parameter ${repeatedBlindSqlResult.parameter}.`
        : likelyBlindSqlResult
          ? `Blind SQL probes produced a strong but unconfirmed ${likelyBlindSqlResult.technique} signal on parameter ${likelyBlindSqlResult.parameter}.`
        : booleanSqlResult
          ? "Boolean true/false SQL payloads produced a measurable single-pass response difference, but repeated proof was not strong enough for confirmation."
        : timeBasedSqlResult
          ? "A time-delay SQL payload produced a measurable slowdown, but repeated timing proof was not available."
          : "No blind SQL injection behavior was confirmed in the bounded probes.",
      whyItMatters:
        "Blind SQL injection can be exploitable even when the application hides database errors; attackers compare response differences or timing to extract data.",
      recommendation:
        repeatedBlindSqlResult || likelyBlindSqlResult || booleanSqlResult || timeBasedSqlResult
          ? "Parameterize backend queries and add regression tests for boolean and time-based SQL payloads on the affected parameter."
          : "Keep testing boolean and time-based payloads on high-risk search, filter, and ID parameters.",
      evidence: {
        checkedUrl: sqlProbeConfigs.map((config) => config.url).join(", "),
        expectedLocation: "Boolean and time-based SQL payload behavior",
        summary: repeatedBlindSqlResult
          ? repeatedBlindSqlResult.evidenceSummary
          : likelyBlindSqlResult
            ? likelyBlindSqlResult.evidenceSummary
          : booleanSqlResult
            ? "A boolean-based response difference was observed once and is reported as likely, not confirmed."
          : timeBasedSqlResult
            ? "A time-based SQL signal was observed."
            : "No blind SQL injection signal was confirmed.",
        url: repeatedBlindSqlResult?.url ?? likelyBlindSqlResult?.url ?? booleanSqlResult?.url ?? timeBasedSqlResult?.url ?? null,
        parameter: repeatedBlindSqlResult?.parameter ?? likelyBlindSqlResult?.parameter ?? booleanSqlResult?.parameter ?? timeBasedSqlResult?.parameter ?? null,
        payload: repeatedBlindSqlResult?.technique ?? likelyBlindSqlResult?.technique ?? (booleanSqlResult?.truePayload
          ? redactValue(booleanSqlResult.truePayload)
          : timeBasedSqlResult?.payload
            ? redactValue(timeBasedSqlResult.payload)
            : null),
        beforeStatus: repeatedBlindSqlResult?.baseline[0]?.status ?? likelyBlindSqlResult?.baseline[0]?.status ?? booleanSqlResult?.falseStatus ?? timeBasedSqlResult?.baselineStatus ?? null,
        afterStatus: repeatedBlindSqlResult?.trueCondition?.[0]?.status ?? likelyBlindSqlResult?.trueCondition?.[0]?.status ?? booleanSqlResult?.trueStatus ?? timeBasedSqlResult?.status ?? null,
        responseDiff: repeatedBlindSqlResult
          ? repeatedBlindSqlResult.evidenceSummary
          : likelyBlindSqlResult
            ? likelyBlindSqlResult.evidenceSummary
          : booleanSqlResult
          ? `true=${booleanSqlResult.trueRecordCount ?? booleanSqlResult.trueBodyLength}, false=${booleanSqlResult.falseRecordCount ?? booleanSqlResult.falseBodyLength}`
          : timeBasedSqlResult
            ? `${Math.max(0, (timeBasedSqlResult.probeDurationMs ?? 0) - (timeBasedSqlResult.baselineDurationMs ?? 0))} ms slower`
            : "not detected",
	        results: blindSqlProbeResults,
	        repeatedProbeConfirmed: Boolean(repeatedBlindSqlResult),
	        evidenceStrength: repeatedBlindSqlResult
	          ? repeatedBlindSqlResult.evidenceStrength ?? "strong"
	          : likelyBlindSqlResult
	            ? likelyBlindSqlResult.evidenceStrength ?? "moderate"
	            : booleanSqlResult
	              ? "moderate"
	              : "weak",
	        falsePositiveRisk: repeatedBlindSqlResult
	          ? repeatedBlindSqlResult.falsePositiveRisk ?? "low"
	          : likelyBlindSqlResult
	            ? likelyBlindSqlResult.falsePositiveRisk ?? "medium"
	            : booleanSqlResult?.highDynamic
	              ? "high"
	              : timeBasedSqlResult
	                ? "medium"
	                : "low",
	        parameterContext: repeatedBlindSqlResult?.parameterContext ?? likelyBlindSqlResult?.parameterContext ?? booleanSqlResult?.parameterContext ?? null,
	        baselineMedianMs: repeatedBlindSqlResult?.baselineMedianMs ?? likelyBlindSqlResult?.baselineMedianMs ?? null,
        testMedianMs: repeatedBlindSqlResult?.testMedianMs ?? likelyBlindSqlResult?.testMedianMs ?? null,
        controlMedianMs: repeatedBlindSqlResult?.controlMedianMs ?? likelyBlindSqlResult?.controlMedianMs ?? null,
        businessImpact: repeatedBlindSqlResult
          ? "Confirmed blind SQL injection can allow data extraction even when visible database errors are suppressed."
          : "No confirmed business impact from blind SQL injection in this scan.",
        exploitabilityScore: repeatedBlindSqlResult ? 9 : likelyBlindSqlResult || booleanSqlResult || timeBasedSqlResult ? 7 : 1,
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
	      confidence: dbDisclosureResult ? "confirmed" : "info",
	      shortDescription: dbDisclosureResult
	        ? `A sampled response exposed a strict ${dbDisclosureResult.dbErrorFamily ?? "database"} error signature.`
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
	            : `Matched strict database signature: ${dbDisclosureResult?.dbErrorSignature ?? "unknown"}.`,
	        url: dbDisclosureResult?.url ?? null,
	        parameter: dbDisclosureResult?.parameter ?? null,
	        dbErrorSignature: dbDisclosureResult?.dbErrorSignature ?? null,
	        dbErrorFamily: dbDisclosureResult?.dbErrorFamily ?? null,
	        excerpt: dbDisclosureResult?.dbErrorExcerpt ?? null,
	        evidenceStrength: dbDisclosureResult ? "moderate" : "weak",
	        falsePositiveRisk: dbDisclosureResult ? "low" : "low",
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
  ]).slice(0, fastMode ? 3 : 4);
  const boundedAuthBypassPayloads = fastMode ? authBypassPayloads.slice(0, 1) : authBypassPayloads;
  const authBypassProbeResults = (
    await mapLimited(authBypassTargets, 2, async (targetUrl) => {
      return (
        await mapLimited(boundedAuthBypassPayloads, 1, async (payload) => {
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
            timeoutMs: probeTimeoutMs,
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
          const session = extractAuthSessionFromAttempt(attempt, "active-bypass", "bypass session");
          return {
            url: attempt.finalUrl,
            payload,
            status: attempt.status,
            ...authSuccess,
            token: session?.token ?? null,
            userId: session?.userId ?? null,
            basketId: session?.basketId ?? null,
            userEmail: session?.userEmail ?? null,
            roles: session?.roles ?? [],
            setCookies: attempt.setCookies.map((cookie) => cookieName(cookie)),
          } satisfies AuthBypassProbeResult;
        })
      ).filter(isPresent);
    })
  ).flat();
  phase("auth:bypass-complete", {
    authBypassProbeResults: authBypassProbeResults.length,
    elapsedMs: Date.now() - securityStartedAt,
  });
  const successfulAuthBypass = authBypassProbeResults.find((result) => result.authSuccess);
  const bypassSessionAttempt = successfulAuthBypass
    ? {
        requestUrl: successfulAuthBypass.url,
        finalUrl: successfulAuthBypass.url,
        status: successfulAuthBypass.status,
        headers: {},
        setCookies: [],
        bodyText: JSON.stringify({
          token: successfulAuthBypass.token,
          id: successfulAuthBypass.userId,
          bid: successfulAuthBypass.basketId,
          email: successfulAuthBypass.userEmail,
          roles: successfulAuthBypass.roles,
        }),
        durationMs: 0,
        totalDurationMs: 0,
        redirectChain: [],
      } satisfies HttpAttempt
    : null;
  const activeBypassSession = bypassSessionAttempt
    ? extractAuthSessionFromAttempt(bypassSessionAttempt, "active-bypass", "bypass session")
    : null;
  const primarySession: AuthSessionProof | null =
    runtimePrimarySession ??
    (configuredAuthCookie
      ? {
          source: "provided-cookie",
          headers: { cookie: configuredAuthCookie },
          token: null,
          cookieHeader: configuredAuthCookie,
          userId: null,
          basketId: null,
          userEmail: null,
          roles: [],
          roleLabel: target.authRoleLabel?.trim() || "User A",
        }
      : null) ??
    activeBypassSession;
  runtimePrimarySession = primarySession;
  const secondarySession: AuthSessionProof | null =
    runtimeSecondarySession ??
    (configuredSecondaryAuthCookie && !configuredSecondaryAuthCookie.startsWith("[") && !configuredSecondaryAuthCookie.startsWith("{")
      ? {
          source: "provided-cookie",
          headers: { cookie: configuredSecondaryAuthCookie },
          token: null,
          cookieHeader: configuredSecondaryAuthCookie,
          userId: null,
          basketId: null,
          userEmail: null,
          roles: [],
          roleLabel: target.secondaryAuthRoleLabel?.trim() || "User B",
        }
      : null);
  runtimeSecondarySession = secondarySession;
  if (primarySession) {
    authContextStore.upsert(
      authContextFromSession({
        id: "userA",
        label: primarySession.roleLabel || "userA",
        headers: primarySession.headers,
        token: primarySession.token,
        userId: primarySession.userId,
        email: primarySession.userEmail,
        role: primarySession.roles[0] ?? primarySession.roleLabel,
      }),
    );
  }
  if (secondarySession) {
    authContextStore.upsert(
      authContextFromSession({
        id: "userB",
        label: secondarySession.roleLabel || "userB",
        headers: secondarySession.headers,
        token: secondarySession.token,
        userId: secondarySession.userId,
        email: secondarySession.userEmail,
        role: secondarySession.roles[0] ?? secondarySession.roleLabel,
      }),
    );
  }
  const authenticatedEndpointProbes = await runAuthenticatedEndpointProbes({
    primaryOrigin,
    session: primarySession,
    timeoutMs: lightProbeTimeoutMs,
    maxEndpoints: fastMode ? 4 : scanMode === "Authenticated" ? 6 : 8,
  });
  phase("auth:endpoints-complete", {
    hasPrimarySession: Boolean(primarySession),
    authenticatedEndpointProbes: authenticatedEndpointProbes.length,
    elapsedMs: Date.now() - securityStartedAt,
  });
  const authBypassReachable = authBypassProbeResults.some((result) => result.status !== 404 && result.status < 500);
  const verifiedAuthBypass = Boolean(
    successfulAuthBypass &&
      primarySession?.source === "active-bypass" &&
      authenticatedEndpointProbes.some((probe) => probe.status >= 200 && probe.status < 400),
  );
  const authBypassVerificationProbe =
    authenticatedEndpointProbes.find((probe) => probe.status >= 200 && probe.status < 400) ?? null;
  const authBypassSessionArtifactType =
    successfulAuthBypass?.sessionCookie
      ? "cookie"
      : primarySession?.token && primarySession.headers && "authorization" in (primarySession.headers as Record<string, unknown>)
        ? "bearer-token"
        : successfulAuthBypass?.token
          ? "json-token"
          : "unknown";
  const authBypassAuthModel =
    successfulAuthBypass?.sessionCookie && successfulAuthBypass.token
      ? "mixed"
      : successfulAuthBypass?.sessionCookie
        ? "cookie-based"
        : successfulAuthBypass?.token || primarySession?.token
          ? "token-based"
          : "unknown";
  const authBypassEvidence = successfulAuthBypass
    ? {
        loginEndpoint: `POST ${new URL(successfulAuthBypass.url).pathname}`,
        payloadPreview: redactValue(successfulAuthBypass.payload),
        responseStatus: successfulAuthBypass.status,
        sessionArtifactType: authBypassSessionArtifactType,
        tokenPreview: successfulAuthBypass.token ? maskSecret(successfulAuthBypass.token) : undefined,
        verificationEndpoint: authBypassVerificationProbe
          ? new URL(authBypassVerificationProbe.url).pathname
          : "not-verified",
        verificationStatus: authBypassVerificationProbe?.status ?? 0,
        verificationResult: verifiedAuthBypass
          ? authBypassVerificationProbe?.sensitiveResponse
            ? "protected-data-access"
            : successfulAuthBypass.userId || successfulAuthBypass.userEmail
              ? "authenticated-identity"
              : "token-accepted"
          : "unknown",
        identitySummary: {
          userId: successfulAuthBypass.userId ? String(successfulAuthBypass.userId) : undefined,
          emailPreview: successfulAuthBypass.userEmail ? redactValue(successfulAuthBypass.userEmail, 3) : undefined,
          role: successfulAuthBypass.roles[0],
        },
        authModel: authBypassAuthModel,
      }
    : null;
  findings.push(
    buildSecurityCheck({
      checkKey: "authentication-bypass-active-probe",
      title: "Authentication bypass active probe",
      scoreWeight: 1.55,
      confidence: verifiedAuthBypass ? "confirmed" : successfulAuthBypass ? "likely" : "info",
      status: successfulAuthBypass ? "fail" : authBypassReachable ? "pass" : "info",
      severity: successfulAuthBypass ? "critical" : "info",
      shortDescription: successfulAuthBypass
        ? verifiedAuthBypass
          ? "A sampled login endpoint returned a session/token for a SQL-style bypass payload and the scanner reused it against a protected endpoint."
          : "A sampled login endpoint returned a token-like or cookie-like success signal, but reusable protected access was not verified."
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
          ? verifiedAuthBypass
            ? "A login probe returned a session artifact and protected endpoint verification succeeded."
            : "A login probe returned a token-like body or session cookie, but protected endpoint verification did not prove reuse."
          : authBypassReachable
            ? "No sampled login endpoint returned an authentication success signal."
            : "No login endpoint candidate was found.",
        probePayloads: authBypassPayloads.map((payload) => redactValue(payload)),
        url: successfulAuthBypass?.url ?? null,
        payload: successfulAuthBypass?.payload ? redactValue(successfulAuthBypass.payload) : null,
        afterStatus: successfulAuthBypass?.status ?? null,
        confidence: verifiedAuthBypass ? "confirmed-reusable-session-verified" : successfulAuthBypass ? "likely-token-or-session-signal" : "not-detected",
        authenticatedVerification: verifiedAuthBypass,
        reusableSessionVerified: verifiedAuthBypass,
        authBypassEvidence,
        loginEndpoint: authBypassEvidence?.loginEndpoint ?? null,
        payloadPreview: authBypassEvidence?.payloadPreview ?? null,
        responseStatus: authBypassEvidence?.responseStatus ?? null,
        sessionArtifactType: authBypassEvidence?.sessionArtifactType ?? "unknown",
        tokenPreview: authBypassEvidence?.tokenPreview ?? null,
        authModel: authBypassEvidence?.authModel ?? "unknown",
        verificationEndpoint: authBypassVerificationProbe?.url ?? null,
        verificationStatus: authBypassEvidence?.verificationStatus ?? null,
        verificationResult: authBypassEvidence?.verificationResult ?? "unknown",
        results: authBypassProbeResults.map((result) => ({
          url: result.url,
          payload: redactValue(result.payload),
          status: result.status,
          authSuccess: result.authSuccess,
          tokenLikeResponse: result.tokenLikeResponse,
          sessionCookie: result.sessionCookie,
          tokenCaptured: Boolean(result.token),
          userId: result.userId,
          basketId: result.basketId,
          roles: result.roles,
        })),
      },
    }),
  );

  const authenticatedSessionStatus =
    authenticatedEndpointProbes.some((probe) => probe.status < 400 && probe.sensitiveResponse)
      ? { status: "fail" as const, severity: "high" as const }
      : primarySession
        ? { status: "warning" as const, severity: "medium" as const }
        : { status: "info" as const, severity: "info" as const };
  const sessionModel = analyzeSessionContext({
    setCookies: [
      ...primaryAttempt.setCookies,
      ...(successfulAuthBypass ? [] : []),
    ],
    responseJson: bypassSessionAttempt ? parseJsonBody(bypassSessionAttempt.bodyText) : null,
    authorizationHeader:
      primarySession?.headers && !Array.isArray(primarySession.headers) && !(primarySession.headers instanceof Headers)
        ? String((primarySession.headers as Record<string, unknown>).authorization ?? "")
        : null,
    token: primarySession?.token ?? null,
    cookieHeader: primarySession?.cookieHeader ?? null,
    authenticatedContextObtained: Boolean(primarySession),
    verifiedEndpoint:
      authenticatedEndpointProbes.find((probe) => probe.status >= 200 && probe.status < 400)?.url ?? null,
  });
  findings.push(
    buildSecurityCheck({
      checkKey: "authenticated-session-context",
      title: "Authenticated session context",
      scoreWeight: 1.2,
      ...authenticatedSessionStatus,
      confidence: authenticatedEndpointProbes.some((probe) => probe.status < 400) ? "confirmed" : primarySession ? "likely" : "info",
      shortDescription:
        primarySession
          ? `The scanner obtained a ${primarySession.source.replace("-", " ")} context and reused it against ${authenticatedEndpointProbes.length} authenticated endpoint candidate(s).`
          : "No reusable authenticated context was available for session-aware checks.",
      whyItMatters:
        "Most serious authorization flaws require a real session context. Reusing cookies, login credentials, or an active bypass token lets the scanner test protected account, basket, order, and admin APIs.",
      recommendation:
        primarySession
          ? "Review any protected endpoint that returned sensitive data and provide a secondary user session for stronger cross-user authorization proof."
          : "Provide cookies or credentials for User A and User B to enable authenticated and role-based authorization checks.",
      evidence: {
        checkedUrl: authenticatedEndpointProbes.map((probe) => probe.url).join(", "),
        expectedLocation: "Authenticated account, basket, user, admin, and configuration endpoints",
        summary: primarySession
          ? "A reusable authenticated context was available and endpoint probes were executed."
          : "No authenticated context was available.",
        sessionSource: primarySession?.source ?? "none",
        roleLabel: primarySession?.roleLabel ?? null,
        userId: primarySession?.userId ?? null,
        basketId: primarySession?.basketId ?? null,
        userEmail: primarySession?.userEmail ?? null,
        roles: primarySession?.roles ?? [],
        endpoints: authenticatedEndpointProbes,
        sessionModel,
        businessImpact: authenticatedEndpointProbes.some((probe) => probe.sensitiveResponse)
          ? "Authenticated endpoint data was reachable during the scan; this can expose account, basket, order, or administrative information when authorization is weak."
          : "No sensitive authenticated endpoint response was confirmed, but authenticated depth is now explicitly tracked.",
        exploitabilityScore: authenticatedEndpointProbes.some((probe) => probe.sensitiveResponse) ? 8 : primarySession ? 5 : 1,
      },
    }),
  );
  findings.push(
    buildSecurityCheck({
      checkKey: "session-model",
      title: "Session model",
      status: sessionModel.risks.length > 0 ? "warning" : "info",
      severity: sessionModel.risks.some((risk) => /httponly|secure|jwt-without-exp|javascript/i.test(risk))
        ? "medium"
        : "info",
      confidence: sessionModel.authenticatedContextObtained ? "likely" : "info",
      shortDescription:
        sessionModel.sessionType === "token-based"
          ? "No session cookies were detected on the primary document; the application appears to use token-based authentication and a reusable context was observed."
          : sessionModel.summary,
      whyItMatters:
        "Session reporting must distinguish cookie-based sessions from token-based authentication so missing-cookie statements do not contradict successful authenticated testing.",
      recommendation:
        sessionModel.risks.length > 0
          ? "Review token storage and cookie flags. Avoid JavaScript-readable long-lived tokens where possible and set Secure, HttpOnly, and SameSite on sensitive cookies."
          : "Continue tracking session artifacts after login and avoid exposing raw tokens in client-visible storage.",
      evidence: {
        checkedUrl: authenticatedEndpointProbes.map((probe) => probe.url).join(", "),
        expectedLocation: "Set-Cookie, Authorization headers, login JSON, browser storage, and authenticated endpoint reuse",
        summary: sessionModel.summary,
        sessionType: sessionModel.sessionType,
        authenticatedContextObtained: sessionModel.authenticatedContextObtained,
        storageLocations: sessionModel.storageLocations,
        tokenExposedToJavaScript: sessionModel.tokenExposedToJavaScript,
        artifacts: sessionModel.artifacts,
        risks: sessionModel.risks,
      },
    }),
  );

  const storedXssProbeResults = await runStoredXssStatefulProbe({
    primaryOrigin,
    targetHostname: target.targetHostname,
    session: primarySession,
    executeBrowser: scanMode !== "Fast" && hasBudgetFor(8_000),
    timeoutMs: scanMode === "Deep" ? 8_000 : 4_000,
  });
  phase("xss:stored-complete", {
    storedXssProbeResults: storedXssProbeResults.length,
    browserExecutionAllowed: scanMode !== "Fast",
    elapsedMs: Date.now() - securityStartedAt,
  });
  const executedStoredXss = storedXssProbeResults.find((result) => result.executed);
  const retrievableStoredXss = storedXssProbeResults.find((result) => result.retrievable);
  findings.push(
    buildSecurityCheck({
      checkKey: "stored-xss-stateful-probe",
      title: executedStoredXss
        ? "Stored XSS execution confirmed"
        : retrievableStoredXss
          ? "Stored XSS persistence detected, execution not confirmed"
          : "Stored XSS stateful probe",
      scoreWeight: 1.45,
      status: executedStoredXss ? "fail" : retrievableStoredXss ? "warning" : "info",
      severity: executedStoredXss ? "critical" : retrievableStoredXss ? "high" : "info",
      confidence: executedStoredXss ? "confirmed" : retrievableStoredXss ? "likely" : "info",
      shortDescription: executedStoredXss
        ? "A stored XSS payload was accepted, retrieved, and executed in a browser-rendered view."
        : retrievableStoredXss
          ? "A stored XSS payload was accepted and retrievable, but browser execution was not confirmed."
          : statefulAttackProbesAllowed(target.targetHostname)
            ? "No stored XSS execution was confirmed in the bounded stateful probe."
            : "State-changing stored XSS probes were not run for this target.",
      whyItMatters:
        "Stored XSS is higher impact than reflected XSS because the payload persists and can execute for other users who load the affected object.",
      recommendation:
        executedStoredXss || retrievableStoredXss
          ? "Sanitize stored rich text server-side, encode on render, and add regression tests for stored payloads in reviews, comments, profile fields, tickets, and messages."
          : "Enable stateful probes only on owned or intentionally vulnerable targets, and continue encoding all stored user content by output context.",
      evidence: {
        checkedUrl: storedXssProbeResults.map((result) => result.url).join(", "),
        expectedLocation: "Stateful comment, review, profile, or message sinks",
        summary: executedStoredXss
          ? "The marker set by the stored payload executed in a browser."
          : retrievableStoredXss
            ? "The marker was retrievable after submission but execution was not confirmed."
            : statefulAttackProbesAllowed(target.targetHostname)
              ? "Stateful XSS probes ran but did not confirm storage or execution."
              : "Stateful probes were skipped because this is not an allowlisted lab target and FIXNX_ACTIVE_STATEFUL_PROBES is not enabled.",
        results: storedXssProbeResults.map((result) => ({
          ...result,
          payload: redactValue(result.payload),
        })),
        url: executedStoredXss?.url ?? retrievableStoredXss?.url ?? null,
        payload: executedStoredXss?.payload ? redactValue(executedStoredXss.payload) : retrievableStoredXss?.payload ? redactValue(retrievableStoredXss.payload) : null,
        afterStatus: executedStoredXss?.status ?? retrievableStoredXss?.status ?? null,
        browserSignal: executedStoredXss?.signals?.[0]?.type ?? null,
        renderedUrl: executedStoredXss?.renderedUrl ?? retrievableStoredXss?.renderedUrl ?? null,
        responseDiff: executedStoredXss
          ? "stored payload executed in browser-rendered object view"
          : retrievableStoredXss
            ? "stored payload marker was retrievable from the application"
            : "not detected",
        businessImpact: executedStoredXss
          ? "A persistent browser execution path can compromise users who view the affected object and can be chained into session theft or account actions."
          : retrievableStoredXss
            ? "Stored user-controlled HTML was retrievable and may become exploitable where it is rendered unsafely."
            : "No stored XSS business impact was confirmed.",
        exploitabilityScore: executedStoredXss ? 9 : retrievableStoredXss ? 7 : 1,
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
  const sessionIdorCandidates = uniqueUrls([
    primarySession?.basketId !== null && primarySession?.basketId !== undefined
      ? `${primaryOrigin}/rest/basket/${primarySession.basketId}`
      : "",
    primarySession?.basketId !== null && primarySession?.basketId !== undefined
      ? `${primaryOrigin}/api/BasketItems?BasketId=${primarySession.basketId}`
      : "",
    primarySession?.userId !== null && primarySession?.userId !== undefined
      ? `${primaryOrigin}/api/Users/${primarySession.userId}`
      : "",
  ])
    .map((url) => ({ url, hasSensitivePath: true, hasPredictableId: true }))
    .slice(0, 4);
  const idorProbeLimit = fastMode ? 3 : scanMode === "Authenticated" ? 5 : 6;
  const shouldRunOwnershipVerifier = scanMode !== "Fast" && Boolean(primarySession && secondarySession) && hasBudgetFor(6_000);
  const idorProbeResults = (
    await mapLimited([...sessionIdorCandidates, ...idorCandidates].slice(0, idorProbeLimit), 2, async (candidate) => {
      const mutatedUrl = mutationWithNextIdentifier(candidate.url);
      if (!mutatedUrl || mutatedUrl === candidate.url) {
        return null;
      }

      const sessionHeaders = sessionIdorCandidates.some((entry) => entry.url === candidate.url)
        ? primarySession?.headers
        : authHeadersFor(candidate.url);
      const [originalAttempt, mutatedAttempt, secondaryAttempt] = await Promise.all([
        loadAttempt(candidate.url, {
          timeoutMs: lightProbeTimeoutMs,
          followRedirects: false,
          headers: sessionHeaders,
        }),
        loadAttempt(mutatedUrl, {
          timeoutMs: lightProbeTimeoutMs,
          followRedirects: false,
          headers: sessionHeaders,
        }),
        secondarySession?.headers || secondaryAuthHeadersFor(candidate.url)
          ? loadAttempt(candidate.url, {
              timeoutMs: lightProbeTimeoutMs,
              followRedirects: false,
              headers: secondarySession?.headers ?? secondaryAuthHeadersFor(candidate.url),
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
      const ownershipVerification =
        shouldRunOwnershipVerifier && primarySession && secondarySession && sessionHeaders
          ? await verifyIdorOwnership({
              victimContext: authContextFromSession({
                id: "userA",
                label: primarySession.roleLabel || "userA",
                headers: primarySession.headers,
                token: primarySession.token,
                userId: primarySession.userId,
                email: primarySession.userEmail,
                role: primarySession.roles[0] ?? primarySession.roleLabel,
              }),
              attackerContext: authContextFromSession({
                id: "userB",
                label: secondarySession.roleLabel || "userB",
                headers: secondarySession.headers,
                token: secondarySession.token,
                userId: secondarySession.userId,
                email: secondarySession.userEmail,
                role: secondarySession.roles[0] ?? secondarySession.roleLabel,
              }),
              victimUrl: candidate.url,
              timeoutMs: lightProbeTimeoutMs,
            })
          : null;

      return {
        originalUrl: candidate.url,
        mutatedUrl: mutatedAttempt.finalUrl,
        status: mutatedAttempt.status,
        originalStatus: originalAttempt?.status ?? null,
        secondaryStatus: secondaryAttempt?.status ?? null,
        contentType: mutatedAttempt.headers["content-type"] ?? null,
        comparableResponse,
        crossUserAccess,
        ownershipConfirmed: ownershipVerification?.ownershipConfirmed ?? false,
        ownerContext: ownershipVerification?.victimContext ?? null,
        attackerContext: ownershipVerification?.attackerContext ?? null,
        leakedFields: ownershipVerification?.leakedFields ?? [],
        leakedMarkers: ownershipVerification?.leakedMarkers ?? [],
        ownershipResponseDiff: ownershipVerification?.responseDiff ?? null,
        sessionBased: Boolean(sessionHeaders),
      } satisfies IdorProbeResult & {
        ownershipConfirmed: boolean;
        ownerContext: string | null;
        attackerContext: string | null;
        leakedFields: string[];
        leakedMarkers: string[];
        ownershipResponseDiff: string | null;
      };
    })
  ).filter(isPresent);
  phase("authorization:idor-complete", {
    candidates: idorCandidates.length + sessionIdorCandidates.length,
    probes: idorProbeResults.length,
    ownershipVerifier: shouldRunOwnershipVerifier,
    elapsedMs: Date.now() - securityStartedAt,
  });
  const exposedIdorProbe = idorProbeResults.find((result) => result.comparableResponse || result.crossUserAccess);
  const confirmedIdorProbe = idorProbeResults.find((result) => "ownershipConfirmed" in result && result.ownershipConfirmed === true);
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
      confidence: confirmedIdorProbe ? "confirmed" : exposedIdorProbe ? "likely" : "info",
      shortDescription:
        confirmedIdorProbe
          ? `A secondary authenticated session accessed data with ownership markers from ${confirmedIdorProbe.originalUrl}.`
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
        checkedUrl: uniqueUrls([...sessionIdorCandidates, ...idorCandidates].map((candidate) => candidate.url)).join(", "),
        expectedLocation: "ID-based internal URLs should enforce object-level authorization",
        summary:
          confirmedIdorProbe
            ? "A cross-user authorization probe returned victim ownership markers to another user context."
          : exposedIdorProbe
            ? "A sampled object identifier could be changed and still returned a comparable successful response; ownership was not proven, so this remains likely."
          : idorCandidates.length === 0
            ? "No strong IDOR-style URL patterns were found in the sampled links."
            : "ID-based internal URLs were found and should be reviewed for object-level access control.",
        candidates: idorCandidates,
        url: confirmedIdorProbe?.originalUrl ?? exposedIdorProbe?.mutatedUrl ?? null,
        beforeStatus: confirmedIdorProbe?.originalStatus ?? exposedIdorProbe?.originalStatus ?? null,
        afterStatus: confirmedIdorProbe?.secondaryStatus ?? exposedIdorProbe?.status ?? null,
        responseDiff: confirmedIdorProbe
          ? confirmedIdorProbe.ownershipResponseDiff ?? "secondary authenticated session received victim ownership markers"
          : exposedIdorProbe
            ? "mutated object identifier returned comparable success"
            : "not detected",
        activeProbes: idorProbeResults,
        confidence: confirmedIdorProbe ? "confirmed-cross-user-ownership" : exposedIdorProbe ? "suspected-id-mutation" : "not-detected",
        ownershipConfirmed: Boolean(confirmedIdorProbe),
        attackerContext: confirmedIdorProbe?.attackerContext ?? null,
        victimContext: confirmedIdorProbe?.ownerContext ?? null,
        leakedFields: confirmedIdorProbe?.leakedFields ?? [],
        leakedMarkers: confirmedIdorProbe?.leakedMarkers ?? [],
        primarySessionSource: primarySession?.source ?? "none",
        secondarySessionProvided: Boolean(secondarySession || configuredSecondaryAuthCookie),
        businessImpact: confirmedIdorProbe
          ? "A second authenticated context could access another user's object, which can expose private account, order, basket, or invoice data."
          : exposedIdorProbe
            ? "A session-based object identifier mutation returned a comparable successful response and should be treated as an authorization risk until proven scoped."
            : "No confirmed object-level authorization exposure in this scan.",
        exploitabilityScore: confirmedIdorProbe ? 9 : exposedIdorProbe ? 7 : 1,
      },
    }),
  );

  const accessMatrixEndpointLimit = fastMode ? 4 : scanMode === "Authenticated" ? 6 : 10;
  const accessMatrix = hasBudgetFor(fastMode ? 4_000 : 8_000)
    ? await buildRoleBasedAccessMatrix({
        endpoints: uniqueUrls([
          ...authenticatedEndpointProbes.map((probe) => probe.url),
          ...discoveredApiEndpoints,
          `${primaryOrigin}/rest/admin/application-configuration`,
          `${primaryOrigin}/rest/user/whoami`,
        ]).slice(0, accessMatrixEndpointLimit + 2),
        contexts: authContextStore.all(),
        timeoutMs: lightProbeTimeoutMs,
        maxEndpoints: accessMatrixEndpointLimit,
      })
    : [];
  phase("authorization:role-matrix-complete", {
    rows: accessMatrix.length,
    maxEndpoints: accessMatrixEndpointLimit,
    elapsedMs: Date.now() - securityStartedAt,
  });
  const confirmedAccessIssue = accessMatrix.find(
    (row) =>
      row.issue === "anonymous-sensitive-access" ||
      row.issue === "user-admin-access" ||
      row.issue === "cross-user-access",
  );
  const likelyAccessIssue = accessMatrix.find((row) => row.issue !== "none" && row.issue !== "partial-coverage");
  const partialAccessCoverage = accessMatrix.some((row) => row.issue === "partial-coverage");
  findings.push(
    buildSecurityCheck({
      checkKey: "role-based-access-matrix",
      title: partialAccessCoverage ? "Partial access matrix" : "Role-based access matrix",
      scoreWeight: 1.3,
      status: confirmedAccessIssue ? "fail" : likelyAccessIssue ? "warning" : "info",
      severity: confirmedAccessIssue ? "high" : likelyAccessIssue ? "medium" : "info",
      confidence: confirmedAccessIssue ? "confirmed" : likelyAccessIssue ? "likely" : "info",
      shortDescription: confirmedAccessIssue
        ? `${confirmedAccessIssue.issue.replace(/-/g, " ")} was observed on ${confirmedAccessIssue.endpoint}.`
        : likelyAccessIssue
          ? `${likelyAccessIssue.issue.replace(/-/g, " ")} may affect ${likelyAccessIssue.endpoint}.`
          : partialAccessCoverage
            ? "Partial access behavior was recorded for anonymous and scanner-auth-context coverage; userA/userB/admin were not all available."
            : "Access behavior was recorded for available anonymous and authenticated contexts.",
      whyItMatters:
        "Broken access control often appears only when comparing anonymous, normal user, secondary user, and admin contexts against the same endpoints.",
      recommendation:
        confirmedAccessIssue || likelyAccessIssue
          ? "Apply server-side authorization per endpoint and object. Admin/configuration routes should reject anonymous and low-privileged users."
          : "Keep adding role contexts so the access matrix can prove privilege boundaries across protected APIs.",
      evidence: {
        checkedUrl: accessMatrix.map((row) => row.endpoint).join(", "),
        expectedLocation: "Protected, user-owned, and admin-like endpoints should vary access by role",
        summary: confirmedAccessIssue
          ? confirmedAccessIssue.evidenceSummary
          : likelyAccessIssue
            ? likelyAccessIssue.evidenceSummary
            : partialAccessCoverage
              ? "Partial access matrix generated. Full cross-user and admin proof requires userA, userB, and admin contexts."
              : "No role-based access issue was confirmed in the sampled matrix.",
        accessMatrix,
        matrixTitle: partialAccessCoverage ? "Partial Access Matrix" : "Role-Based Access Matrix",
        partialCoverage: partialAccessCoverage,
        coverageNote: partialAccessCoverage
          ? "Only anonymous and scanner-auth-context were available for at least one sampled endpoint. Provide userA, userB, and admin contexts for full role-based authorization proof."
          : null,
        results: accessMatrix.map((row) => ({
          url: row.endpoint,
          method: row.method,
          sensitivity: row.sensitivity,
          issue: row.issue,
          explanation: row.explanation,
          anonymous: row.anonymous,
          scannerAuthContext: row.scannerAuthContext,
          userA: row.userA,
          userB: row.userB,
          admin: row.admin,
        })),
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
      const probeUrl = applyProbeParameter(config.url, config.parameter, openRedirectProbeValue);
      const attempt = await loadAttempt(probeUrl, {
        timeoutMs: lightProbeTimeoutMs,
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
      confidence: failingOpenRedirect ? "confirmed" : externalRedirectProbe || reflectedRedirectProbe ? "likely" : "info",
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
        url: failingOpenRedirect?.url ?? externalRedirectProbe?.url ?? reflectedRedirectProbe?.url ?? null,
        parameter: failingOpenRedirect?.parameter ?? externalRedirectProbe?.parameter ?? reflectedRedirectProbe?.parameter ?? null,
        afterStatus: failingOpenRedirect?.status ?? externalRedirectProbe?.status ?? reflectedRedirectProbe?.status ?? null,
        responseDiff: failingOpenRedirect?.resolvedLocation
          ? `Location: ${failingOpenRedirect.resolvedLocation}`
          : externalRedirectProbe?.resolvedLocation
            ? `Location: ${externalRedirectProbe.resolvedLocation}`
            : reflectedRedirectProbe
              ? "payload reflected without external redirect"
              : "not detected",
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
  const confirmedSensitiveEndpointExposure = exposedSensitiveEndpoint
    ? looksLikeSensitiveApiPayload(exposedSensitiveEndpoint.bodyText) ||
      /"(?:secret|token|password|private|config|env|admin|role|email|userId)"\s*:|heapdump|phpinfo|server status/i.test(
        exposedSensitiveEndpoint.bodyText.slice(0, 80_000),
      )
    : false;
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
      confidence: confirmedSensitiveEndpointExposure ? "confirmed" : notableSensitiveEndpointAttempts.length > 0 ? "likely" : "info",
      shortDescription:
        notableSensitiveEndpointAttempts.length === 0
          ? "No sampled sensitive endpoint candidates returned a useful response."
          : confirmedSensitiveEndpointExposure
            ? "A sampled high-risk endpoint returned data with sensitive/configuration markers and should be reviewed immediately."
          : exposedSensitiveEndpoint
            ? "A sampled high-risk endpoint returned a direct response, but sensitive data exposure was not proven."
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
            : confirmedSensitiveEndpointExposure
              ? "A sensitive endpoint returned recognizable sensitive or configuration data."
              : "Some sensitive endpoint candidates were reachable or explicitly protected; reachable-only endpoints are reported as likely, not confirmed.",
        dataExposure: confirmedSensitiveEndpointExposure,
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
	  const appOwnedAuthRouteMapSignals = authRouteMapSignals.filter((signal) => !isHostedAuthProviderSignal(signal));
	  const hostedAuthProviderSignals = authRouteMapSignals.filter(isHostedAuthProviderSignal);
	  const appOwnedAuthSurfaceAttempts = authSurfaceAttempts.filter((attempt) => !isHostedAuthProviderSignal(attempt.finalUrl));
	  const authSurfaceDetected =
	    authForms.length > 0 ||
	    appOwnedAuthSurfaceAttempts.length > 0 ||
	    Boolean(successfulAuthBypass) ||
	    appOwnedAuthRouteMapSignals.length > 0;
	  const hostedProviderOnlyAuthSurface =
	    !authSurfaceDetected && hostedAuthProviderSignals.length > 0;
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
	          ? hostedProviderOnlyAuthSurface
	            ? "Only hosted authentication-provider flow signals were observed; no app-owned login form was captured."
	            : "No authentication forms or routes were detected in the sampled surface."
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
	          ...appOwnedAuthSurfaceAttempts.map((attempt) => attempt.finalUrl),
	          ...authForms.map((form) => form.url),
	          ...appOwnedAuthRouteMapSignals,
	          ...authBypassTargets,
	        ]).join(", "),
        expectedLocation: "Login, reset, and account-recovery routes and forms",
        summary:
          successfulAuthBypass
            ? "An active authentication bypass result confirms that authentication routes exist and require urgent review."
          : authReviewStatus.status === "pass"
            ? "Sampled auth surfaces looked reasonably hardened."
            : "At least one sampled auth surface lacked a baseline control.",
	        authRouteCount: appOwnedAuthSurfaceAttempts.length,
	        passwordFormCount: authForms.length,
	        routeMapSignals: appOwnedAuthRouteMapSignals.slice(0, 12),
	        hostedAuthProviderSignals: hostedAuthProviderSignals.slice(0, 8),
	        hostedProviderOnlyAuthSurface,
	        authBypassProbeStatus: successfulAuthBypass ? "confirmed" : authBypassReachable ? "tested" : "not-tested",
        clickjackingStatus: clickjackingStatus.status,
      },
    }),
  );

  const passwordForms = authForms.filter((form) => form.hasPasswordField);
  const passwordFieldStatus =
    passwordForms.length === 0 && authSurfaceDetected
      ? { status: "warning" as const, severity: "medium" as const }
      : passwordForms.length === 0
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
        passwordForms.length === 0 && authSurfaceDetected
          ? "Authentication routes or API signals were detected, but no password input was captured in the rendered DOM."
          : passwordForms.length === 0
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
          passwordForms.length === 0 && authSurfaceDetected
            ? "No password input was captured; this should be read as crawler coverage, not proof that no login form exists."
            : passwordForms.length === 0
            ? "No password inputs were found."
            : "Password forms were evaluated for HTTPS, action security, and baseline browser controls.",
	        authSurfaceDetected,
	        authRouteMapSignals: appOwnedAuthRouteMapSignals.slice(0, 8),
	        hostedAuthProviderSignals: hostedAuthProviderSignals.slice(0, 8),
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
          : { status: "warning" as const, severity: "medium" as const };
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
        uploadFormCount: uploadForms.length,
        uploadRouteCount: uploadSurfaceAttempts.length,
        uploadForms: uploadForms.map((form) => ({
          url: form.url,
          method: form.method,
          secure: form.secure,
          csrfFieldNames: form.csrfFieldNames,
        })),
        uploadRoutes: uploadSurfaceAttempts.map((attempt) => ({
          url: attempt.finalUrl,
          status: attempt.status,
        })),
      },
    }),
  );

  const apiClassifications = uniqueUrls([
    ...discoveredApiEndpoints,
    ...artifacts.browserInspection.routeMap.apiEndpoints,
    ...apiSurfaceAttempts.map((attempt) => attempt.finalUrl),
  ]).map((url) =>
    classifyApiEndpoint(
      url,
      browserDiscoveredApiEndpoints.includes(url) || artifacts.browserInspection.routeMap.apiEndpoints.includes(url)
        ? "browser-network"
        : apiSurfaceAttempts.some((attempt) => attempt.finalUrl === url)
          ? "sensitive-probe"
          : "frontend",
    ),
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
      confidence: apiExposureSignals.length > 0 ? "likely" : "info",
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
        classifications: apiClassifications.slice(0, 30),
      },
    }),
  );

  const discoveredGraphqlTargets = uniqueUrls([
    ...apiSurfaceAttempts
      .filter((attempt) => /graphql/i.test(new URL(attempt.url).pathname))
      .map((attempt) => attempt.finalUrl),
    ...apiClassifications
      .filter((classification) => /graphql/i.test(new URL(classification.url).pathname))
      .map((classification) => classification.url),
    `${primaryOrigin}/graphql`,
    `${primaryOrigin}/api/graphql`,
    `${primaryOrigin}/v1/graphql`,
    `${primaryOrigin}/query`,
    `${primaryOrigin}/graphiql`,
  ]);
  const graphqlTarget = discoveredGraphqlTargets[0] ?? `${primaryOrigin}/graphql`;
  const graphqlWasDiscovered = discoveredGraphqlTargets.length > 0;
  const graphqlProbeLimit = fastMode ? 2 : scanMode === "Authenticated" ? 3 : 5;
  let graphqlProbe:
    | {
        status: number;
        bodyText: string;
        introspectionOpen: boolean;
        reachable: boolean;
        protected: boolean;
      }
    | null = null;
  for (const candidateGraphqlTarget of discoveredGraphqlTargets.slice(0, graphqlProbeLimit)) {
    const baseProbe = await loadAttempt(candidateGraphqlTarget, {
      method: "POST",
      timeoutMs: lightProbeTimeoutMs,
      headers: {
        "content-type": "application/json",
      },
        body: JSON.stringify({
          query: "query { __typename }",
        }),
      });
    if (baseProbe) {
      const introspectionProbe = await loadAttempt(candidateGraphqlTarget, {
        method: "POST",
        timeoutMs: lightProbeTimeoutMs,
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
          ((graphqlWasDiscovered && baseProbe.status === 405) ||
            (!isHtmlLikeResponse(baseProbe.headers, baseProbe.bodyText) && looksLikeStructuredApiPayload(baseProbe))),
        protected:
          isLikelyEdgeInterstitial(baseProbe) ||
          [401, 403].includes(baseProbe.status) ||
          baseProbe.status === 405,
      };
      if (graphqlProbe.reachable || graphqlProbe.introspectionOpen) {
        break;
      }
    }
  }
  phase("graphql:complete", {
    candidates: discoveredGraphqlTargets.length,
    sampled: graphqlProbeLimit,
    reachable: Boolean(graphqlProbe?.reachable),
    introspectionOpen: Boolean(graphqlProbe?.introspectionOpen),
    elapsedMs: Date.now() - securityStartedAt,
  });
  const graphqlStatus =
    !graphqlTarget || !graphqlProbe?.reachable
      ? { status: "info" as const, severity: "info" as const }
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
          ? "No GraphQL endpoint was observed in the sampled browser/API surface."
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
          ? "If GraphQL exists behind deeper app states, include authenticated cookies or credentials so it can be discovered and probed."
          : "Review GraphQL authentication and consider disabling or restricting introspection on production endpoints that should not disclose schema details.",
      evidence: {
        checkedUrl: discoveredGraphqlTargets.slice(0, graphqlProbeLimit).join(", ") || primaryOrigin,
        expectedLocation: "/graphql and GraphQL-like frontend-discovered endpoints",
        summary:
          !graphqlTarget || !graphqlProbe?.reachable
            ? "No GraphQL endpoint was observed; this is a coverage statement, not proof that GraphQL does not exist."
          : graphqlProbe?.introspectionOpen
              ? "The sampled GraphQL endpoint appeared to disclose introspection data."
              : graphqlProbe.protected
                ? "A GraphQL endpoint was detected, but access looked intentionally restricted."
              : "A GraphQL endpoint was detected or probed.",
        introspectionOpen: graphqlProbe?.introspectionOpen ?? false,
        statusCode: graphqlProbe?.status ?? null,
        sampledApiEndpoints: apiClassifications.length,
        graphqlCandidates: discoveredGraphqlTargets.slice(0, graphqlProbeLimit),
      },
    }),
  );

  const highRiskRateLimitTarget = authSurfaceAttempts.find(isReachableSensitiveEndpoint)?.finalUrl ?? apiSurfaceAttempts[0]?.finalUrl ?? null;
  const searchRateLimitTarget = primaryPage.links.find((link) => link.internal && /search|query|q=/i.test(link.url))?.url ?? null;
  const rateLimitTarget = highRiskRateLimitTarget ?? searchRateLimitTarget;
  const rateLimitProbeScope = highRiskRateLimitTarget ? "sensitive" : searchRateLimitTarget ? "search" : "none";
  const rateLimitIterations = fastMode ? [] : [1, 2, 3];
  const rateLimitAttempts = rateLimitTarget && rateLimitIterations.length > 0
    ? await mapLimited(rateLimitIterations, 1, async (iteration) => {
        const url = new URL(rateLimitTarget);
        url.searchParams.set("cyberaudit_rate_probe", String(iteration));
        const attempt = await loadAttempt(url.toString(), {
          timeoutMs: lightProbeTimeoutMs,
          followRedirects: false,
        });
        return attempt;
      })
    : [];
  phase("rate-limit:complete", {
    target: rateLimitTarget,
    attempts: rateLimitAttempts.length,
    skippedFastMode: Boolean(rateLimitTarget && fastMode),
    elapsedMs: Date.now() - securityStartedAt,
  });
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
        : fastMode
          ? "Rate-limit probing was deferred in Fast mode to keep scan time bounded."
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
          : fastMode
            ? "A suitable endpoint was found, but active rate-limit probing was skipped in Fast mode."
          : rateLimitSignals.length > 0
            ? "A sampled endpoint exposed rate-limit signals."
            : rateLimitProbeScope === "sensitive"
              ? "No visible rate-limit signal was detected during the cautious probe."
              : "No high-risk endpoint was available for a meaningful rate-limit assessment.",
        probeScope: rateLimitProbeScope,
        signals: rateLimitSignals,
        skippedFastMode: Boolean(rateLimitTarget && fastMode),
      },
    }),
  );

  const missingRouteAttempt = await loadAttempt(`${primaryOrigin}/cyberaudit-not-found-${Date.now().toString(36)}`, {
    timeoutMs: lightProbeTimeoutMs,
    followRedirects: false,
  });
  const invalidInputAttempt = await loadAttempt(`${primaryPage.url}${primaryPage.url.includes("?") ? "&" : "?"}cyberaudit_invalid=%27%22%3C%3E`, {
    timeoutMs: lightProbeTimeoutMs,
    followRedirects: false,
  });
  phase("error-handling:complete", {
    missingRouteStatus: missingRouteAttempt?.status ?? null,
    invalidInputStatus: invalidInputAttempt?.status ?? null,
    elapsedMs: Date.now() - securityStartedAt,
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
    timeoutMs: lightProbeTimeoutMs,
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
    timeoutMs: lightProbeTimeoutMs,
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
    timeoutMs: lightProbeTimeoutMs,
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
      confidence: sensitiveContentFindings.length > 0 ? "likely" : "info",
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
    await mapLimited(sourceMapCandidates.slice(0, fastMode ? 3 : 6), 3, async (url) => {
      const attempt = await loadAttempt(url, {
        timeoutMs: lightProbeTimeoutMs,
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
      confidence: exposedSourceMaps.length > 0 ? "confirmed" : "info",
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
    timeoutMs: lightProbeTimeoutMs,
    followRedirects: false,
  });
  const gitExposed = Boolean(gitHead && gitHead.status < 400 && /refs\/heads/i.test(gitHead.bodyText));
  findings.push(
    buildSecurityCheck({
      checkKey: "exposed-git",
      title: "Exposed .git",
      status: gitExposed ? "fail" : "pass",
      severity: gitExposed ? "critical" : "info",
      confidence: gitExposed ? "confirmed" : "info",
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
    timeoutMs: lightProbeTimeoutMs,
    followRedirects: false,
  });
  const envExposed = Boolean(envFile && looksLikeEnvFile(envFile));
  findings.push(
    buildSecurityCheck({
      checkKey: "exposed-env",
      title: "Exposed .env",
      status: envExposed ? "fail" : "pass",
      severity: envExposed ? "critical" : "info",
      confidence: envExposed ? "confirmed" : "info",
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

  const sensitiveFileProbes = (
    await mapLimited(fastSensitiveFilePaths, 4, async (path) => {
      const attempt = await loadAttempt(`${primaryOrigin}${path}`, {
        timeoutMs: lightProbeTimeoutMs,
        followRedirects: false,
      });
      if (!attempt) {
        return null;
      }

      const kind = exposedSensitiveFileKind(path, attempt, primaryAttempt);
      return {
        url: attempt.finalUrl,
        path,
        status: attempt.status,
        contentType: attempt.headers["content-type"] ?? "",
        exposed: Boolean(kind),
        kind: kind ?? "not exposed",
      } satisfies SensitiveFileProbe;
    })
  ).filter(isPresent);
  phase("exposure:file-probes-complete", {
    sourceMapCandidates: sourceMapCandidates.length,
    sourceMapAttempts: sourceMapAttempts.length,
    gitStatus: gitHead?.status ?? null,
    envStatus: envFile?.status ?? null,
    sensitiveFileProbes: sensitiveFileProbes.length,
    elapsedMs: Date.now() - securityStartedAt,
  });
  const exposedSensitiveFiles = sensitiveFileProbes.filter((probe) => probe.exposed);
  findings.push(
    buildSecurityCheck({
      checkKey: "sensitive-files-diagnostics-exposure",
      title: "Sensitive files and diagnostics exposure",
      scoreWeight: 1.15,
      status: exposedSensitiveFiles.length > 0 ? "fail" : "pass",
      severity: exposedSensitiveFiles.length > 0 ? "high" : "info",
      confidence: exposedSensitiveFiles.length > 0 ? "confirmed" : "info",
      shortDescription:
        exposedSensitiveFiles.length === 0
          ? "No sampled sensitive file, schema, or diagnostics paths were publicly exposed."
          : `${exposedSensitiveFiles.length} sampled sensitive file or diagnostics path(s) returned recognizable content.`,
      whyItMatters:
        "Public diagnostics, API schemas, and configuration files can expose internal endpoints, stack details, credentials, or operational controls.",
      recommendation:
        exposedSensitiveFiles.length === 0
          ? "Keep diagnostics, schemas, and configuration artifacts intentionally scoped."
          : "Remove exposed diagnostics/configuration artifacts or protect them behind authentication and network controls.",
      evidence: {
        checkedUrl: fastSensitiveFilePaths.map((path) => `${primaryOrigin}${path}`).join(", "),
        expectedLocation: "Common sensitive files and diagnostics paths should not expose content",
        summary:
          exposedSensitiveFiles.length === 0
            ? "No sampled sensitive diagnostic path exposed recognizable content."
            : "One or more sampled sensitive diagnostic paths exposed recognizable content.",
        results: sensitiveFileProbes,
        locations: exposedSensitiveFiles.map((probe) =>
          createResponseLocation({
            label: probe.kind,
            url: probe.url,
            path: probe.path,
            note: `Returned status ${probe.status} with ${probe.contentType || "unknown content type"}.`,
          }),
        ),
        confidence: exposedSensitiveFiles.length > 0 ? "confirmed-recognizable-sensitive-path" : "not-detected",
      },
    }),
  );

  const backupPaths = ["/.env.bak", "/backup.zip", "/config.php~", "/index.php.bak"];
  const backupAttempts = await Promise.all(
    backupPaths.map((path) =>
      loadAttempt(`${primaryOrigin}${path}`, {
        timeoutMs: lightProbeTimeoutMs,
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
      confidence: exposedBackups.length > 0 ? "confirmed" : "info",
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
        timeoutMs: lightProbeTimeoutMs,
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
    timeoutMs: lightProbeTimeoutMs,
    includeBody: false,
  });
  const rootSecurityTxt = await loadAttempt(`${primaryOrigin}/security.txt`, {
    timeoutMs: lightProbeTimeoutMs,
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
    timeoutMs: lightProbeTimeoutMs,
  });
  const sensitiveRobotsPaths = robotsTxt && robotsTxt.status < 400
    ? extractSensitiveRobotsPaths(robotsTxt.bodyText)
    : [];
  const robotsPathSamples = (
    await mapLimited(sensitiveRobotsPaths.slice(0, 5), 2, async (path) => {
      const url = resolveHttpUrl(path, primaryOrigin);
      if (!url) {
        return null;
      }

      const attempt = await loadAttempt(url, {
        timeoutMs: lightProbeTimeoutMs,
        followRedirects: false,
      });
      const reachable = Boolean(attempt && [200, 401, 403].includes(attempt.status));
      const sensitiveKind =
        attempt && attempt.status >= 200 && attempt.status < 300
          ? exposedSensitiveFileKind(path, attempt, primaryAttempt)
          : null;
      const sensitiveSignals = attempt
        ? detectSensitiveDataExposure(attempt.bodyText.slice(0, 80_000), path)
        : [];
      const sensitiveDataObserved = Boolean(
        attempt &&
          reachable &&
          (sensitiveKind ||
            looksLikeSensitiveApiPayload(attempt.bodyText) ||
            sensitiveSignals.some((signal) => signal.severity !== "low")),
      );

      return {
        path,
        url,
        status: attempt?.status ?? null,
        disallowPathSampled: true,
        reachable,
        sensitiveDataObserved,
        sensitiveKind,
        sensitiveSignals: sensitiveSignals.map((signal) => signal.label),
      };
    })
  ).filter(isPresent);
  const robotsSensitiveExposure = robotsPathSamples.some((sample) => sample.sensitiveDataObserved);
  findings.push(
    buildSecurityCheck({
      checkKey: "robots-txt-presence",
      title: "robots.txt presence",
      status: robotsSensitiveExposure ? "warning" : robotsTxt && robotsTxt.status < 400 ? "pass" : "info",
      severity: robotsSensitiveExposure ? "medium" : "info",
      confidence: robotsSensitiveExposure ? "confirmed" : "info",
      shortDescription:
        robotsSensitiveExposure
          ? "robots.txt references at least one sampled sensitive-looking path that returned sensitive data indicators."
          : sensitiveRobotsPaths.length > 0
          ? `robots.txt is reachable and references ${sensitiveRobotsPaths.length} sensitive-looking path(s).`
          : robotsTxt && robotsTxt.status < 400
          ? "robots.txt is reachable on the primary origin."
          : "robots.txt is not reachable on the primary origin.",
      whyItMatters:
        "robots.txt is not a direct security control, but its presence often reflects baseline operational hygiene.",
      recommendation:
        robotsSensitiveExposure
          ? "Remove sensitive data exposure from the reachable path, then keep robots.txt aligned with crawl policy only."
          : sensitiveRobotsPaths.length > 0
          ? "Do not rely on robots.txt to hide sensitive paths; ensure every referenced sensitive route is protected server-side."
          : robotsTxt && robotsTxt.status < 400
          ? "Keep robots.txt aligned with the intended crawl policy."
          : "Publish robots.txt if you want explicit crawler guidance on the primary origin.",
      evidence: {
        checkedUrl: `${primaryOrigin}/robots.txt`,
        expectedLocation: "/robots.txt",
        summary:
          robotsSensitiveExposure
            ? "A sampled robots.txt Disallow path exposed sensitive-looking content."
            : sensitiveRobotsPaths.length > 0
            ? "robots.txt returned sensitive-looking Disallow entries."
            : robotsTxt && robotsTxt.status < 400
            ? "robots.txt returned a successful response."
            : "robots.txt did not return a successful response.",
        sensitiveDisallowPaths: sensitiveRobotsPaths,
        samples: robotsPathSamples,
      },
    }),
  );

  const technologyVersionHints = uniqueUrls([
    ...artifacts.technologyHints.filter((hint) => /\b\d+(?:\.\d+){1,3}\b/.test(hint)),
    serverHeader && /\b\d+(?:\.\d+){1,3}\b/.test(serverHeader) ? `Server: ${serverHeader}` : "",
    poweredByHeader && /\b\d+(?:\.\d+){1,3}\b/.test(poweredByHeader) ? `X-Powered-By: ${poweredByHeader}` : "",
  ]);
  findings.push(
    buildSecurityCheck({
      checkKey: "technology-fingerprinting",
      title: "Technology fingerprinting",
      status: technologyVersionHints.length > 0 ? "warning" : "info",
      severity: technologyVersionHints.length > 0 ? "low" : "info",
      confidence: technologyVersionHints.length > 0 ? "likely" : "info",
      shortDescription:
        technologyVersionHints.length > 0
          ? `Detected public technology/version hints: ${technologyVersionHints.join(", ")}.`
          : artifacts.technologyHints.length > 0
          ? `Detected likely technologies: ${artifacts.technologyHints.join(", ")}.`
          : "No strong technology signatures were detected from the sampled response.",
      whyItMatters:
        "Technology fingerprinting is informational, but it helps teams understand what their public stack reveals.",
      recommendation:
        technologyVersionHints.length > 0
          ? "Version detected, vulnerability lookup recommended. Reduce exact public version banners where feasible."
          : artifacts.technologyHints.length > 0
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
        versionHints: technologyVersionHints,
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

	  const attackPathSteps = [
	    recordExpansionSqlResult || repeatedBlindSqlResult
	      ? {
	          step: "SQL injection",
	          confidence: "confirmed",
	          evidence: recordExpansionSqlResult?.url ?? repeatedBlindSqlResult?.url,
	        }
	      : null,
    successfulAuthBypass
      ? {
          step: "Authentication bypass",
          confidence: "confirmed",
          evidence: successfulAuthBypass.url,
        }
      : null,
    primarySession && authenticatedEndpointProbes.some((probe) => probe.status < 400)
      ? {
          step: "Session reuse",
          confidence: "confirmed",
          evidence: authenticatedEndpointProbes.find((probe) => probe.status < 400)?.url,
        }
      : null,
    confirmedIdorProbe || exposedIdorProbe
      ? {
          step: confirmedIdorProbe ? "Cross-user object access" : "Object ID mutation",
          confidence: confirmedIdorProbe ? "confirmed" : "likely",
          evidence: confirmedIdorProbe?.originalUrl ?? exposedIdorProbe?.mutatedUrl,
        }
      : null,
    confirmedBrowserXss || executedStoredXss
      ? {
          step: executedStoredXss ? "Stored browser execution" : "Browser XSS execution",
          confidence: "confirmed",
          evidence: executedStoredXss?.url ?? confirmedBrowserXss?.url,
        }
      : activeXssFailure || retrievableStoredXss
        ? {
            step: retrievableStoredXss ? "Stored payload retrievable" : "XSS dangerous reflection",
            confidence: "likely",
            evidence: retrievableStoredXss?.url ?? activeXssFailure?.url,
          }
        : null,
  ].filter(isPresent);
  const attackPaths = buildAttackPaths(findings);
  const confirmedAttackPathSteps = attackPathSteps.filter((step) => step.confidence === "confirmed").length;
  const topAttackPath = attackPaths[0] ?? null;
  const topConfirmedSteps = topAttackPath?.confirmedSteps ?? topAttackPath?.steps ?? [];
  const topLikelyExtensions = topAttackPath?.likelyExtensions ?? [];
  const attackChainStatus =
    topAttackPath && topConfirmedSteps.length >= 2
      ? { status: "fail" as const, severity: "critical" as const }
      : topAttackPath || attackPathSteps.length >= 2
        ? { status: "warning" as const, severity: "high" as const }
        : attackPathSteps.length === 1
          ? { status: "warning" as const, severity: "medium" as const }
          : { status: "info" as const, severity: "info" as const };
  findings.push(
    buildSecurityCheck({
      checkKey: "attack-chain-analysis",
      title: "Attack path analysis",
      scoreWeight: 1.5,
      ...attackChainStatus,
      confidence:
        topAttackPath && topConfirmedSteps.length >= 2
          ? "confirmed"
          : topAttackPath || attackPathSteps.length > 0
            ? "likely"
            : "info",
      shortDescription:
        topAttackPath
          ? `The scan built one primary attacker path with ${topConfirmedSteps.length} confirmed step(s) and ${topLikelyExtensions.length} likely extension(s): ${topAttackPath.title}.`
        : attackPathSteps.length >= 2
          ? `The scan connected ${attackPathSteps.length} exploitable or likely-exploitable steps into a plausible attacker path.`
          : attackPathSteps.length === 1
            ? "One exploitable step was identified, but no multi-step chain was confirmed."
            : "No multi-step attack chain was built from this scan.",
      whyItMatters:
        "Attackers chain issues: SQL injection can lead to account access, a stolen session can expose IDOR, and XSS can be used to steal tokens or perform account actions.",
      recommendation:
        topAttackPath
          ? `Fix first: ${findings.find((finding) => finding.id === topAttackPath.fixFirstFindingId)?.title ?? topAttackPath.fixFirstFindingId}. ${topAttackPath.fixFirstReason}`
        : attackPathSteps.length > 0
          ? "Fix the first confirmed step in the path, then rerun the scan to verify whether the downstream chain collapses."
          : "Continue feeding the scanner authenticated sessions so it can connect impact across account, object, and browser-execution checks.",
      evidence: {
        checkedUrl: attackPathSteps.map((step) => String(step.evidence ?? "")).filter(Boolean).join(", "),
        expectedLocation: "Confirmed vulnerabilities and session-aware follow-on probes",
        summary:
          topAttackPath
            ? topAttackPath.summary
            : attackPathSteps.length >= 2
              ? "Multiple findings can be chained into a higher-impact attack path."
            : attackPathSteps.length === 1
              ? "Only one attack-path step was available."
              : "No chainable path was confirmed.",
        attackPath: attackPathSteps,
        attackPaths,
        primaryAttackPath: topAttackPath,
        numberedSteps: topConfirmedSteps,
        confirmedSteps: topConfirmedSteps,
        likelyExtensions: topLikelyExtensions,
        relatedPathsSuppressed: topAttackPath?.suppressedRelatedPathCount ?? 0,
        fixFirstFindingId: topAttackPath?.fixFirstFindingId ?? null,
        fixFirstTitle: topAttackPath?.fixFirstTitle ?? null,
        fixFirstReason: topAttackPath?.fixFirstReason ?? null,
        collapsedFindingsIfFixed: topAttackPath?.collapsedFindingsIfFixed ?? [],
        businessImpact:
          topConfirmedSteps.length >= 2 || confirmedAttackPathSteps >= 2
            ? "A practical attacker path exists from initial exploitation into authenticated or user-impacting access."
            : attackPathSteps.length >= 2
              ? "A plausible attacker path exists but needs one more confirmation step."
              : "No chained business impact was confirmed.",
        exploitabilityScore:
          topConfirmedSteps.length >= 2 || confirmedAttackPathSteps >= 2
            ? 10
            : attackPathSteps.length >= 2
              ? 8
              : attackPathSteps.length === 1
                ? 5
                : 1,
        recommendedFirstFix:
          (topAttackPath
            ? topAttackPath.fixFirstTitle || findings.find((finding) => finding.id === topAttackPath.fixFirstFindingId)?.title
            : null) ??
          attackPathSteps[0]?.step ??
          "No chained path detected",
      },
    }),
  );

  const scanDurationMs = Date.now() - securityStartedAt;
  const issueFindings = findings.filter((finding) => {
    const status = deriveFindingStatus(finding);
    return status === "fail" || status === "warning";
  });
  const criticalIssues = issueFindings.filter((finding) => finding.severity === "critical").length;
  const missingHeaders = findings.filter(
    (finding) =>
      finding.checkKey &&
      missingHeaderCheckKeys.includes(finding.checkKey) &&
      (deriveFindingStatus(finding) === "fail" || deriveFindingStatus(finding) === "warning"),
  ).length;
  const publicApis = apiClassifications.filter((entry) => entry.classes.includes("public data")).length;
  const sensitiveEndpointCount = uniqueUrls([
    ...notableSensitiveEndpointAttempts.map((attempt) => attempt.finalUrl),
    ...exposedSensitiveFiles.map((probe) => probe.url),
    ...sensitiveRobotsPaths.map((path) => `${primaryOrigin}${path.startsWith("/") ? path : `/${path}`}`),
  ]).length;
  const activeProbesExecuted =
    activeXssProbeConfigs.length * activeXssPayloads.length +
    browserXssExecutionResults.length +
    sqlProbeResults.length +
    booleanSqlProbeResults.length +
    blindSqlProbeResults.length +
    authBypassProbeResults.length +
    authenticatedEndpointProbes.length +
    idorProbeResults.length +
    openRedirectResults.length +
    storedXssProbeResults.length +
    sensitiveEndpointAttempts.length +
    sensitiveFileProbes.length +
    sourceMapAttempts.length;
  const crawledPageCount =
    artifacts.browserInspection.routeMap.pages.length ||
    (primaryPage ? 1 : 0) + artifacts.crawledPages.length;
  await options.onProgress?.({
    phase: "analysis",
    message: "Prioritizing findings, calculating risk, and preparing the live report summary.",
    percent: 86,
    findings,
    urlsChecked: activeProbesExecuted,
  });
  const reportSummary = buildReportSummary({
    target: primaryAttempt.finalUrl,
    scanMode,
    generatedAt: new Date().toISOString(),
    findings,
    attackPaths,
    attackSurface: {
      publicApis,
      sensitiveEndpoints: sensitiveEndpointCount,
      missingHeaders,
      crawledPages: crawledPageCount,
      discoveredEndpoints: apiClassifications.length,
      testedParameters: inputProbeConfigs.length,
      activeProbesExecuted,
      scanDurationMs,
      scanDuration: formatDuration(scanDurationMs),
    },
  });
  const recommendedFix =
    reportSummary.recommendedFirstFix?.title ??
    "No concrete exploitable vulnerability was confirmed";
  const recommendedFixes = reportSummary.topFixes.map((finding, index) => ({
    rank: index + 1,
    id: finding.id,
    title: finding.title,
    riskScore: finding.riskScore ?? 0,
    priorityLabel: finding.priorityLabel ?? "Low priority",
    recommendationLabel: getRecommendationLabel(finding),
    reason:
      "reason" in finding
        ? finding.reason
        : finding.fixFirstReason ?? finding.proofSummary ?? finding.shortDescription,
    recommendation: finding.recommendation,
    findings: "findings" in finding ? finding.findings : undefined,
    affectedUrls: "affectedUrls" in finding ? finding.affectedUrls : undefined,
  }));
  findings.unshift(
    buildSecurityCheck({
      checkKey: "attack-surface-summary",
      title: "Attack surface summary",
      status: "info",
      severity: "info",
      confidence: "info",
      shortDescription:
        `${scanMode} security scan covered ${crawledPageCount} page(s), ${apiClassifications.length} API endpoint(s), and ${inputProbeConfigs.length} tested parameter target(s).`,
      whyItMatters:
        "Coverage metrics make the scan depth explicit, separate confirmed vulnerabilities from weak signals, and show where the attack surface was actually tested.",
      recommendation: `${reportSummary.recommendedFirstLabel}: ${recommendedFix}`,
      evidence: {
        checkedUrl: primaryAttempt.finalUrl,
        expectedLocation: "Scan coverage, browser route map, active probes, and classified attack surface",
        summary:
          "The scanner rendered the target, classified discovered API surface, and executed a bounded set of active probes prioritized for security impact.",
        scanMode,
        crawledPages: crawledPageCount,
        discoveredEndpoints: apiClassifications.length,
        testedParameters: inputProbeConfigs.length,
        activeProbesExecuted,
        scanDurationMs,
        scanDuration: formatDuration(scanDurationMs),
        criticalIssues,
        publicApis,
        sensitiveEndpoints: sensitiveEndpointCount,
        missingHeaders,
        confirmedExploitableFindings: reportSummary.counts.confirmedExploitableVulnerabilities,
        confirmedExploitableVulnerabilities: reportSummary.counts.confirmedExploitableVulnerabilities,
        confirmedSupportingEvidence: reportSummary.counts.confirmedSupportingEvidence,
        likelyHighImpactIssues: reportSummary.counts.likelyHighImpactIssues,
        informationalFindings: reportSummary.counts.informationalFindings,
        securityScore: reportSummary.security.score,
        securityRiskLabel: reportSummary.security.riskLabel,
        securityScoreExplanation: reportSummary.security.explanation,
        securityScoreBreakdown: reportSummary.security.breakdown,
        coverageConfidence: reportSummary.coverageConfidence,
        recommendedFirstFix: recommendedFix,
        recommendedFirstLabel: reportSummary.recommendedFirstLabel,
        recommendedFirstFixId: reportSummary.recommendedFirstFix?.id ?? null,
        recommendedFirstFixReason:
          (reportSummary.recommendedFirstFix && "reason" in reportSummary.recommendedFirstFix
            ? reportSummary.recommendedFirstFix.reason
            : reportSummary.recommendedFirstFix?.fixFirstReason ??
              reportSummary.recommendedFirstFix?.proofSummary ??
              reportSummary.recommendedFirstFix?.shortDescription) ??
          "No concrete exploitable vulnerability was confirmed.",
        topFixes: recommendedFixes,
        attackPaths,
        reportSummary,
        accessMatrix,
        sessionModel,
        apiClassifications: apiClassifications.slice(0, 20),
        routeMap: {
          pages: artifacts.browserInspection.routeMap.pages.slice(0, 12),
          forms: artifacts.browserInspection.routeMap.forms.length,
          buttons: artifacts.browserInspection.routeMap.buttons.length,
          inputs: artifacts.browserInspection.routeMap.inputs.length,
        },
        activeProbeBreakdown: {
          xssPayloads: activeXssProbeConfigs.length * boundedActiveXssPayloads.length,
          browserXss: browserXssExecutionResults.length,
          sqlInjection: sqlProbeResults.length,
          blindSqlInjection: blindSqlProbeResults.length,
          authBypass: authBypassProbeResults.length,
          authenticatedEndpoints: authenticatedEndpointProbes.length,
          idor: idorProbeResults.length,
          storedXss: storedXssProbeResults.length,
          openRedirect: openRedirectResults.length,
          sensitiveEndpoints: sensitiveEndpointAttempts.length,
          sensitiveFiles: sensitiveFileProbes.length,
          sourceMaps: sourceMapAttempts.length,
        },
      },
    }),
  );

  const gated = applyPremiumGating(findings, 10);
  phase("complete", {
    durationMs: Date.now() - securityStartedAt,
    findings: findings.length,
    score: reportSummary.security.score,
  });
  return {
    score: reportSummary.security.score,
    findings: gated,
  };
}
