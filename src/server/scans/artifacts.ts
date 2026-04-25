import tls from "node:tls";
import { load as loadHtml } from "cheerio";
import { type FindingEvidenceLocation } from "@/lib/types";
import {
  describeDomLocation,
  getOrigin,
  isLikelyEdgeInterstitial,
  loadAttempt,
  loadPageContext,
} from "@/server/scans/helpers";
import {
  type HttpAttempt,
  type NormalizedTarget,
  type PageContext,
} from "@/server/scans/types";

type ResourceKind =
  | "script"
  | "stylesheet"
  | "image"
  | "iframe"
  | "font"
  | "form"
  | "link";

export interface PageHeading {
  level: number;
  text: string;
  location: FindingEvidenceLocation;
}

export interface PageLink {
  url: string;
  sourceUrl: string;
  text: string;
  internal: boolean;
  secure: boolean;
  location: FindingEvidenceLocation;
}

export interface PageFormField {
  name: string;
  type: string;
  autocomplete: string | null;
  required: boolean;
  location: FindingEvidenceLocation;
}

export interface PageFormSnapshot {
  url: string;
  sourceUrl: string;
  actionExplicit: boolean;
  method: string;
  enctype: string;
  internal: boolean;
  secure: boolean;
  hasPasswordField: boolean;
  hasFileUpload: boolean;
  fieldNames: string[];
  hiddenFieldNames: string[];
  csrfFieldNames: string[];
  visibleFieldTypes: string[];
  autocompleteHints: string[];
  sensitiveKinds: string[];
  fields: PageFormField[];
  location: FindingEvidenceLocation;
}

export interface PageResource {
  url: string;
  sourceUrl: string;
  kind: ResourceKind;
  internal: boolean;
  secure: boolean;
  attribute: string;
  location: FindingEvidenceLocation;
  alt?: string | null;
  loading?: string | null;
  integrity?: string | null;
  declaredWidth?: number | null;
  declaredHeight?: number | null;
}

export interface PageSnapshot {
  url: string;
  title: string;
  description: string;
  canonical: string;
  robots: string;
  viewport: string;
  lang: string;
  titleLength: number;
  descriptionLength: number;
  h1Count: number;
  headings: PageHeading[];
  links: PageLink[];
  resources: PageResource[];
  images: PageResource[];
  forms: PageResource[];
  formSnapshots: PageFormSnapshot[];
  inlineScripts: Array<{ content: string; location: FindingEvidenceLocation }>;
  nodeCount: number;
  htmlBytes: number;
  openGraphTags: string[];
  twitterTags: string[];
  structuredDataCount: number;
  metaGenerator: string;
}

export interface UrlProbe {
  url: string;
  finalUrl: string;
  status: number | null;
  headers: Record<string, string>;
  contentType: string | null;
  contentLength: number | null;
  contentEncoding: string | null;
  cacheControl: string | null;
  etag: string | null;
  lastModified: string | null;
  durationMs: number | null;
  totalDurationMs: number | null;
  redirectCount: number;
  error: string | null;
}

export interface LinkProbe extends UrlProbe {
  sourceUrl: string;
  text: string;
  internal: boolean;
  secure: boolean;
  location: FindingEvidenceLocation;
}

export interface TlsInspection {
  available: boolean;
  authorized: boolean;
  authorizationError: string | null;
  issuer: string | null;
  subject: string | null;
  validFrom: string | null;
  validTo: string | null;
  subjectAltName: string | null;
  matchedNames: string[];
  domainMatch: boolean;
  daysRemaining: number | null;
}

export interface AuditArtifacts {
  context: PageContext;
  primaryPage: PageSnapshot | null;
  crawledPages: PageSnapshot[];
  resourceProbes: UrlProbe[];
  internalLinkProbes: LinkProbe[];
  externalLinkProbes: LinkProbe[];
  tlsInfo: TlsInspection | null;
  technologyHints: string[];
  wafHints: string[];
}

const globalState = globalThis as typeof globalThis & {
  __cyberAuditArtifactsCache?: Map<string, { expiresAt: number; promise: Promise<AuditArtifacts> }>;
};

function getCache() {
  if (!globalState.__cyberAuditArtifactsCache) {
    globalState.__cyberAuditArtifactsCache = new Map();
  }

  return globalState.__cyberAuditArtifactsCache;
}

function normalizeWhitespace(value: string | null | undefined) {
  return (value ?? "").replace(/\s+/g, " ").trim();
}

function truncate(value: string, maxLength = 160) {
  if (value.length <= maxLength) {
    return value;
  }

  return `${value.slice(0, maxLength - 1).trimEnd()}…`;
}

function parseCountHeader(value: string | undefined) {
  if (!value) {
    return null;
  }

  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : null;
}

function safeAbsoluteUrl(rawValue: string | undefined, baseUrl: string) {
  if (!rawValue) {
    return null;
  }

  if (
    rawValue.startsWith("#") ||
    rawValue.startsWith("mailto:") ||
    rawValue.startsWith("tel:") ||
    rawValue.startsWith("javascript:") ||
    rawValue.startsWith("data:")
  ) {
    return null;
  }

  try {
    const resolved = new URL(rawValue, baseUrl);
    if (!["http:", "https:"].includes(resolved.protocol)) {
      return null;
    }

    return resolved.toString();
  } catch {
    return null;
  }
}

function isInternalHostname(hostname: string, targetHostname: string) {
  return hostname === targetHostname;
}

function looksLikeHtmlPage(url: string) {
  try {
    const parsed = new URL(url);
    const pathname = parsed.pathname.toLowerCase();
    if (!pathname || pathname.endsWith("/")) {
      return true;
    }

    return !/\.(?:jpg|jpeg|png|gif|webp|avif|svg|pdf|zip|xml|json|txt|js|css|woff2?|ttf|eot|ico|mp4|webm|mp3)$/i.test(
      pathname,
    );
  } catch {
    return false;
  }
}

function dedupeByUrl<T extends { url: string }>(items: T[]) {
  const seen = new Set<string>();
  return items.filter((item) => {
    if (seen.has(item.url)) {
      return false;
    }

    seen.add(item.url);
    return true;
  });
}

async function mapWithConcurrency<T, R>(
  items: T[],
  concurrency: number,
  worker: (item: T, index: number) => Promise<R>,
) {
  const results = new Array<R>(items.length);
  let index = 0;

  await Promise.all(
    Array.from({ length: Math.min(concurrency, items.length) }, async () => {
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

async function inspectTls(hostname: string): Promise<TlsInspection | null> {
  return new Promise((resolve) => {
    const socket = tls.connect(
      {
        host: hostname,
        port: 443,
        servername: hostname,
        rejectUnauthorized: false,
        timeout: 7_000,
      },
      () => {
        const certificate = socket.getPeerCertificate(true) as tls.PeerCertificate;
        if (!certificate || !certificate.valid_to) {
          resolve({
            available: false,
            authorized: false,
            authorizationError:
              socket.authorizationError instanceof Error
                ? socket.authorizationError.message
                : String(socket.authorizationError ?? "No certificate received."),
            issuer: null,
            subject: null,
            validFrom: null,
            validTo: null,
            subjectAltName: null,
            matchedNames: [],
            domainMatch: false,
            daysRemaining: null,
          });
          socket.end();
          return;
        }

        const subjectCommonName =
          typeof certificate.subject === "object" && certificate.subject !== null
            ? certificate.subject.CN
            : undefined;
        const matchedNames = [
          ...(Array.isArray(subjectCommonName)
            ? subjectCommonName
            : subjectCommonName
              ? [subjectCommonName]
              : []),
          ...String(certificate.subjectaltname ?? "")
            .split(",")
            .map((entry) => entry.trim())
            .filter((entry) => entry.startsWith("DNS:"))
            .map((entry) => entry.replace(/^DNS:/, "").trim()),
        ];
        const expiry = new Date(certificate.valid_to).getTime();
        const domainMatch = tls.checkServerIdentity(hostname, certificate) === undefined;

        resolve({
          available: true,
          authorized: socket.authorized,
          authorizationError:
            socket.authorizationError instanceof Error
              ? socket.authorizationError.message
              : socket.authorizationError
                ? String(socket.authorizationError)
                : null,
          issuer:
            typeof certificate.issuer === "object" && certificate.issuer !== null
              ? Object.entries(certificate.issuer)
                  .map(([key, value]) => `${key}=${String(value)}`)
                  .join(", ")
              : null,
          subject:
            typeof certificate.subject === "object" && certificate.subject !== null
              ? Object.entries(certificate.subject)
                  .map(([key, value]) => `${key}=${String(value)}`)
                  .join(", ")
              : null,
          validFrom: certificate.valid_from ?? null,
          validTo: certificate.valid_to ?? null,
          subjectAltName: certificate.subjectaltname ?? null,
          matchedNames,
          domainMatch,
          daysRemaining: Number.isFinite(expiry)
            ? Math.round((expiry - Date.now()) / (1000 * 60 * 60 * 24))
            : null,
        });
        socket.end();
      },
    );

    socket.on("error", () => resolve(null));
    socket.on("timeout", () => resolve(null));
  });
}

function buildPageSnapshot(
  attempt: HttpAttempt,
  targetHostname: string,
): PageSnapshot | null {
  if (!attempt.bodyText) {
    return null;
  }

  const contentType = attempt.headers["content-type"] ?? "";
  if (contentType && !contentType.includes("html")) {
    return null;
  }

  const $ = loadHtml(attempt.bodyText);
  const pageUrl = attempt.finalUrl;
  const title = $("title").text().trim();
  const description = $('meta[name="description"]').attr("content")?.trim() ?? "";
  const canonical = $('link[rel="canonical"]').attr("href")?.trim() ?? "";
  const robots = $('meta[name="robots"]').attr("content")?.trim() ?? "";
  const viewport = $('meta[name="viewport"]').attr("content")?.trim() ?? "";
  const lang = $("html").attr("lang")?.trim() ?? "";
  const headings = $("h1, h2, h3, h4, h5, h6")
    .toArray()
    .map((element, index) => {
      const tagName = element.tagName.toLowerCase();
      const level = Number(tagName.replace("h", ""));
      return {
        level,
        text: truncate(normalizeWhitespace($(element).text()), 180),
        location: describeDomLocation($, element, pageUrl, {
          label: `Heading ${index + 1}`,
          note: truncate(normalizeWhitespace($(element).text()), 180),
        }),
      } satisfies PageHeading;
    })
    .filter((heading) => heading.text);

  const links = $("a[href]")
    .toArray()
    .flatMap((element, index) => {
      const url = safeAbsoluteUrl($(element).attr("href"), pageUrl);
      if (!url) {
        return [];
      }

      const parsed = new URL(url);
      const text = truncate(
        normalizeWhitespace(
          $(element).text() || $(element).attr("aria-label") || $(element).attr("title") || url,
        ),
        180,
      );

      return [
        {
          url,
          sourceUrl: pageUrl,
          text,
          internal: isInternalHostname(parsed.hostname, targetHostname),
          secure: parsed.protocol === "https:",
          location: describeDomLocation($, element, pageUrl, {
            label: `Link ${index + 1}`,
            attribute: "href",
            note: text,
          }),
        } satisfies PageLink,
      ];
    });

  const resources: PageResource[] = [];

  $("script[src]").each((index, element) => {
    const url = safeAbsoluteUrl($(element).attr("src"), pageUrl);
    if (!url) {
      return;
    }
    const parsed = new URL(url);
    resources.push({
      url,
      sourceUrl: pageUrl,
      kind: "script",
      internal: isInternalHostname(parsed.hostname, targetHostname),
      secure: parsed.protocol === "https:",
      attribute: "src",
      integrity: $(element).attr("integrity") ?? null,
      location: describeDomLocation($, element, pageUrl, {
        label: `Script ${index + 1}`,
        attribute: "src",
      }),
    });
  });

  $('link[rel="stylesheet"][href]').each((index, element) => {
    const url = safeAbsoluteUrl($(element).attr("href"), pageUrl);
    if (!url) {
      return;
    }
    const parsed = new URL(url);
    resources.push({
      url,
      sourceUrl: pageUrl,
      kind: "stylesheet",
      internal: isInternalHostname(parsed.hostname, targetHostname),
      secure: parsed.protocol === "https:",
      attribute: "href",
      location: describeDomLocation($, element, pageUrl, {
        label: `Stylesheet ${index + 1}`,
        attribute: "href",
      }),
    });
  });

  $('link[rel="preload"][as="font"][href]').each((index, element) => {
    const url = safeAbsoluteUrl($(element).attr("href"), pageUrl);
    if (!url) {
      return;
    }
    const parsed = new URL(url);
    resources.push({
      url,
      sourceUrl: pageUrl,
      kind: "font",
      internal: isInternalHostname(parsed.hostname, targetHostname),
      secure: parsed.protocol === "https:",
      attribute: "href",
      location: describeDomLocation($, element, pageUrl, {
        label: `Font preload ${index + 1}`,
        attribute: "href",
      }),
    });
  });

  $("img[src]").each((index, element) => {
    const url = safeAbsoluteUrl($(element).attr("src"), pageUrl);
    if (!url) {
      return;
    }
    const parsed = new URL(url);
    resources.push({
      url,
      sourceUrl: pageUrl,
      kind: "image",
      internal: isInternalHostname(parsed.hostname, targetHostname),
      secure: parsed.protocol === "https:",
      attribute: "src",
      alt: $(element).attr("alt") ?? null,
      loading: $(element).attr("loading") ?? null,
      declaredWidth: parseCountHeader($(element).attr("width")),
      declaredHeight: parseCountHeader($(element).attr("height")),
      location: describeDomLocation($, element, pageUrl, {
        label: `Image ${index + 1}`,
        attribute: "src",
      }),
    });
  });

  $("iframe[src]").each((index, element) => {
    const url = safeAbsoluteUrl($(element).attr("src"), pageUrl);
    if (!url) {
      return;
    }
    const parsed = new URL(url);
    resources.push({
      url,
      sourceUrl: pageUrl,
      kind: "iframe",
      internal: isInternalHostname(parsed.hostname, targetHostname),
      secure: parsed.protocol === "https:",
      attribute: "src",
      loading: $(element).attr("loading") ?? null,
      location: describeDomLocation($, element, pageUrl, {
        label: `Iframe ${index + 1}`,
        attribute: "src",
      }),
    });
  });

  const formSnapshots = $("form")
    .toArray()
    .flatMap((element, index) => {
      const rawAction = $(element).attr("action")?.trim() ?? "";
      const url = safeAbsoluteUrl(rawAction || pageUrl, pageUrl) ?? pageUrl;
      let parsed: URL;
      try {
        parsed = new URL(url);
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
            location: describeDomLocation($, field, pageUrl, {
              label: `Form field ${fieldIndex + 1}`,
              attribute: "name",
              note: `${name} (${type})`,
            }),
          } satisfies PageFormField;
        });

      const lowerFieldNames = fields.map((field) => field.name.toLowerCase());
      const method = ($(element).attr("method")?.trim().toUpperCase() || "GET");
      const actionExplicit = rawAction.length > 0;
      const lowerAction = rawAction.toLowerCase();
      const visibleFieldTypes = fields
        .filter((field) => field.type !== "hidden")
        .map((field) => field.type);
      const hiddenFieldNames = fields
        .filter((field) => field.type === "hidden")
        .map((field) => field.name);
      const csrfFieldNames = fields
        .filter((field) => /(csrf|xsrf|authenticity|requestverification|form[_-]?token|nonce)/i.test(field.name))
        .map((field) => field.name);
      const sensitiveKinds = new Set<string>();
      const hasPasswordField = fields.some((field) => field.type === "password");
      const hasAuthFieldHints =
        hasPasswordField ||
        lowerFieldNames.some((name) => /(email|username|login|signin|auth|password|otp|code|token)/i.test(name)) ||
        fields.some((field) => /current-password|new-password|username|one-time-code|email/i.test(field.autocomplete ?? ""));
      const hasResetFieldHints =
        lowerFieldNames.some((name) => /(reset|forgot|recover|new[-_]?password|otp|code|token)/i.test(name)) ||
        fields.some((field) => /new-password|one-time-code/i.test(field.autocomplete ?? ""));
      const hasAccountFieldHints = lowerFieldNames.some((name) =>
        /(email|address|billing|card|iban|invoice|profile|settings|phone|account)/i.test(name),
      );

      if (hasPasswordField || /(login|signin|auth|session)/i.test(lowerAction) || (actionExplicit && hasAuthFieldHints)) {
        sensitiveKinds.add("login");
      }
      if (/(reset|forgot|recover|new-password|change-password)/i.test(lowerAction) || (actionExplicit && hasResetFieldHints)) {
        sensitiveKinds.add("password-reset");
      }
      if (
        method !== "GET" &&
        (/(profile|account|settings|email|billing|payment|checkout|invoice)/i.test(lowerAction) ||
          (actionExplicit && hasAccountFieldHints))
      ) {
        sensitiveKinds.add("account");
      }
      if (
        fields.some((field) => field.type === "file") ||
        /multipart\/form-data/i.test($(element).attr("enctype") ?? "")
      ) {
        sensitiveKinds.add("upload");
      }
      if (
        lowerFieldNames.some((name) => /(^q$|query|search|keyword|term)/i.test(name)) ||
        /(search|find)/i.test(lowerAction)
      ) {
        sensitiveKinds.add("search");
      }

      return [
        {
          url,
          sourceUrl: pageUrl,
          actionExplicit,
          method,
          enctype: $(element).attr("enctype")?.trim() || "application/x-www-form-urlencoded",
          internal: isInternalHostname(parsed.hostname, targetHostname),
          secure: parsed.protocol === "https:",
          hasPasswordField,
          hasFileUpload: fields.some((field) => field.type === "file"),
          fieldNames: fields.map((field) => field.name),
          hiddenFieldNames,
          csrfFieldNames,
          visibleFieldTypes,
          autocompleteHints: fields
            .map((field) => field.autocomplete)
            .filter((hint): hint is string => Boolean(hint)),
          sensitiveKinds: [...sensitiveKinds],
          fields,
          location: describeDomLocation($, element, pageUrl, {
            label: `Form ${index + 1}`,
            attribute: "action",
            note: `${$(element).attr("method")?.trim().toUpperCase() || "GET"} ${url}`,
          }),
        } satisfies PageFormSnapshot,
      ];
    });

  formSnapshots.forEach((form, index) => {
    resources.push({
      url: form.url,
      sourceUrl: form.sourceUrl,
      kind: "form",
      internal: form.internal,
      secure: form.secure,
      attribute: "action",
      location: {
        ...form.location,
        label: `Form ${index + 1}`,
      },
    });
  });

  const inlineScripts = $("script:not([src])")
    .toArray()
    .map((element, index) => ({
      content: truncate($(element).html() ?? $(element).text() ?? "", 4_000),
      location: describeDomLocation($, element, pageUrl, {
        label: `Inline script ${index + 1}`,
      }),
    }))
    .filter((script) => script.content.trim().length > 0);

  return {
    url: pageUrl,
    title,
    description,
    canonical,
    robots,
    viewport,
    lang,
    titleLength: title.length,
    descriptionLength: description.length,
    h1Count: $("h1").length,
    headings,
    links,
    resources,
    images: resources.filter((resource) => resource.kind === "image"),
    forms: resources.filter((resource) => resource.kind === "form"),
    formSnapshots,
    inlineScripts,
    nodeCount: $("*").length,
    htmlBytes: Buffer.byteLength(attempt.bodyText, "utf8"),
    openGraphTags: $('meta[property^="og:"]')
      .toArray()
      .map((element) => $(element).attr("property")?.trim() ?? "")
      .filter(Boolean),
    twitterTags: $('meta[name^="twitter:"]')
      .toArray()
      .map((element) => $(element).attr("name")?.trim() ?? "")
      .filter(Boolean),
    structuredDataCount: $('script[type="application/ld+json"]').length,
    metaGenerator: $('meta[name="generator"]').attr("content")?.trim() ?? "",
  };
}

async function probeUrl(url: string): Promise<UrlProbe> {
  const headAttempt = await loadAttempt(url, {
    method: "HEAD",
    includeBody: false,
    timeoutMs: 8_000,
  });
  const needsGetFallback =
    !headAttempt ||
    [403, 405, 429, 500, 501].includes(headAttempt.status) ||
    (
      headAttempt.status < 400 &&
      !headAttempt.headers["content-encoding"] &&
      (
        !headAttempt.headers["content-type"] ||
        /(text\/|javascript|json|css|svg|xml|html)/i.test(headAttempt.headers["content-type"])
      )
    );
  const attempt =
    needsGetFallback
      ? await loadAttempt(url, {
          method: "GET",
          includeBody: false,
          timeoutMs: 8_000,
        })
      : headAttempt;

  if (!attempt) {
    return {
      url,
      finalUrl: url,
      status: null,
      headers: {},
      contentType: null,
      contentLength: null,
      contentEncoding: null,
      cacheControl: null,
      etag: null,
      lastModified: null,
      durationMs: null,
      totalDurationMs: null,
      redirectCount: 0,
      error: "Request failed",
    };
  }

  return {
    url,
    finalUrl: attempt.finalUrl,
    status: attempt.status,
    headers: attempt.headers,
    contentType: attempt.headers["content-type"] ?? null,
    contentLength: parseCountHeader(attempt.headers["content-length"]),
    contentEncoding: attempt.headers["content-encoding"] ?? null,
    cacheControl: attempt.headers["cache-control"] ?? null,
    etag: attempt.headers.etag ?? null,
    lastModified: attempt.headers["last-modified"] ?? null,
    durationMs: attempt.durationMs,
    totalDurationMs: attempt.totalDurationMs,
    redirectCount: attempt.redirectChain.length,
    error: null,
  };
}

function detectTechnologies(context: PageContext, primaryPage: PageSnapshot | null) {
  if (!context.primary || !primaryPage) {
    return [];
  }

  const hints = new Set<string>();
  const headers = context.primary.headers;
  const html = context.primary.bodyText;

  if (headers["x-powered-by"]) {
    hints.add(`X-Powered-By: ${headers["x-powered-by"]}`);
  }
  if (headers.server) {
    hints.add(`Server: ${headers.server}`);
  }
  if (primaryPage.metaGenerator) {
    hints.add(`Generator: ${primaryPage.metaGenerator}`);
  }
  if (/wp-content|wp-includes|wordpress/i.test(html)) {
    hints.add("WordPress");
  }
  if (/elementor/i.test(html)) {
    hints.add("Elementor");
  }
  if (/_next\//.test(html)) {
    hints.add("Next.js");
  }
  if (/react/i.test(html) && /data-reactroot|__next/i.test(html)) {
    hints.add("React");
  }
  if (/shopify/i.test(html)) {
    hints.add("Shopify");
  }

  return [...hints];
}

function detectWafCdn(context: PageContext) {
  if (!context.primary) {
    return [];
  }

  const hints = new Set<string>();
  const headers = context.primary.headers;

  if (headers.server?.toLowerCase().includes("cloudflare") || headers["cf-ray"]) {
    hints.add("Cloudflare");
  }
  if (headers["x-amz-cf-id"] || headers["x-amz-cf-pop"]) {
    hints.add("Amazon CloudFront");
  }
  if (headers["x-served-by"] || headers["x-cache-hits"]) {
    hints.add("Fastly or edge cache");
  }
  if (headers.via || headers["x-cache"]) {
    hints.add("Reverse proxy or CDN");
  }
  if (headers["akamai-grn"] || headers["x-akamai-transformed"]) {
    hints.add("Akamai");
  }

  return [...hints];
}

async function buildArtifacts(target: NormalizedTarget): Promise<AuditArtifacts> {
  const context = await loadPageContext(target);
  const primaryPage = context.primary ? buildPageSnapshot(context.primary, target.targetHostname) : null;
  const primaryIsInterstitial = isLikelyEdgeInterstitial(context.primary);
  const crawlTargets = primaryPage
    ? dedupeByUrl(
        primaryPage.links.filter(
          (link) => link.internal && looksLikeHtmlPage(link.url) && link.url !== primaryPage.url,
        ),
      )
        .slice(0, 4)
        .map((link) => link.url)
    : [];
  const scopedCrawlTargets = primaryIsInterstitial ? [] : crawlTargets;

  const crawledAttempts = await mapWithConcurrency(scopedCrawlTargets, 3, async (url) =>
    loadAttempt(url, {
      timeoutMs: 8_000,
    }),
  );

  const crawledPages = crawledAttempts
    .flatMap((attempt) => (attempt ? [buildPageSnapshot(attempt, target.targetHostname)] : []))
    .filter((page): page is PageSnapshot => Boolean(page));
  const allPages = primaryPage ? [primaryPage, ...crawledPages] : crawledPages;

  const resourceTargets = primaryPage && !primaryIsInterstitial
    ? dedupeByUrl(primaryPage.resources).slice(0, 40)
    : [];
  const resourceProbes = await mapWithConcurrency(resourceTargets, 5, async (resource) =>
    probeUrl(resource.url),
  );

  const internalLinkTargets = dedupeByUrl(
    allPages.flatMap((page) => page.links.filter((link) => link.internal && looksLikeHtmlPage(link.url))),
  ).slice(0, 16);
  const externalLinkTargets = dedupeByUrl(
    allPages.flatMap((page) => page.links.filter((link) => !link.internal)),
  ).slice(0, 10);

  const internalLinkProbes = await mapWithConcurrency(internalLinkTargets, 4, async (link) => {
    const probe = await probeUrl(link.url);
    return {
      ...probe,
      sourceUrl: link.sourceUrl,
      text: link.text,
      internal: link.internal,
      secure: link.secure,
      location: link.location,
    } satisfies LinkProbe;
  });

  const externalLinkProbes = await mapWithConcurrency(externalLinkTargets, 3, async (link) => {
    const probe = await probeUrl(link.url);
    return {
      ...probe,
      sourceUrl: link.sourceUrl,
      text: link.text,
      internal: link.internal,
      secure: link.secure,
      location: link.location,
    } satisfies LinkProbe;
  });

  const tlsInfo = await inspectTls(target.targetHostname);

  return {
    context,
    primaryPage,
    crawledPages,
    resourceProbes,
    internalLinkProbes,
    externalLinkProbes,
    tlsInfo,
    technologyHints: detectTechnologies(context, primaryPage),
    wafHints: detectWafCdn(context),
  };
}

export async function loadAuditArtifacts(target: NormalizedTarget) {
  const cacheKey = target.normalizedTarget;
  const cache = getCache();
  const cached = cache.get(cacheKey);
  if (cached && cached.expiresAt > Date.now()) {
    return cached.promise;
  }

  const promise = buildArtifacts(target).catch((error) => {
    cache.delete(cacheKey);
    throw error;
  });

  cache.set(cacheKey, {
    expiresAt: Date.now() + 30_000,
    promise,
  });

  return promise;
}

export function sumKnownBytes(probes: UrlProbe[]) {
  return probes.reduce((sum, probe) => sum + (probe.contentLength ?? 0), 0);
}

export function isSuccessfulStatus(status: number | null) {
  return typeof status === "number" && status >= 200 && status < 400;
}

export function getPrimaryOrigin(context: PageContext) {
  return context.primary ? getOrigin(context.primary.finalUrl) : null;
}
