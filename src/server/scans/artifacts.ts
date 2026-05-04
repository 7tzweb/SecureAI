import tls from "node:tls";
import { load as loadHtml } from "cheerio";
import type { Browser, BrowserContext, Cookie, Page, Response as PlaywrightResponse } from "playwright";
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
  | "fetch"
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

export interface PageInteractiveElement {
  kind: "button" | "input" | "tab" | "menuitem" | "link" | "dialog";
  text: string;
  name: string | null;
  type: string | null;
  role: string | null;
  href: string | null;
  sourceUrl: string;
  sensitiveKinds: string[];
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
  interactiveElements: PageInteractiveElement[];
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

interface BrowserNetworkResource extends UrlProbe {
  kind: ResourceKind;
  initiatorType: string | null;
  transferSize: number | null;
  decodedBodySize: number | null;
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

export interface BrowserInspection {
  attempted: boolean;
  rendered: boolean;
  finalUrl: string | null;
  durationMs: number | null;
  error: string | null;
  renderedPageCount: number;
  networkRequestCount: number;
  authenticated: boolean;
  routeMap: BrowserRouteMap;
}

export interface BrowserRouteMap {
  pages: string[];
  apiEndpoints: string[];
  forms: Array<{
    url: string;
    method: string;
    sourceUrl: string;
    sensitiveKinds: string[];
    fieldNames: string[];
  }>;
  buttons: Array<{
    text: string;
    kind: PageInteractiveElement["kind"];
    sourceUrl: string;
    sensitiveKinds: string[];
  }>;
  inputs: Array<{
    name: string;
    type: string;
    sourceUrl: string;
    sensitiveKinds: string[];
  }>;
}

export interface AuditArtifacts {
  context: PageContext;
  primaryPage: PageSnapshot | null;
  crawledPages: PageSnapshot[];
  resourceProbes: UrlProbe[];
  internalLinkProbes: LinkProbe[];
  externalLinkProbes: LinkProbe[];
  tlsInfo: TlsInspection | null;
  browserInspection: BrowserInspection;
  technologyHints: string[];
  wafHints: string[];
}

const globalState = globalThis as typeof globalThis & {
  __cyberAuditArtifactsCache?: Map<string, { expiresAt: number; promise: Promise<AuditArtifacts> }>;
};

const BROWSER_NAVIGATION_TIMEOUT_MS = 9_000;
const BROWSER_NETWORK_IDLE_TIMEOUT_MS = 1_200;
const BROWSER_CRAWL_PAGE_LIMIT = 8;
const BROWSER_NETWORK_PROBE_LIMIT = 120;
const FETCH_CRAWL_PAGE_LIMIT = 10;

const emptyBrowserInspection: BrowserInspection = {
  attempted: false,
  rendered: false,
  finalUrl: null,
  durationMs: null,
  error: null,
  renderedPageCount: 0,
  networkRequestCount: 0,
  authenticated: false,
  routeMap: {
    pages: [],
    apiEndpoints: [],
    forms: [],
    buttons: [],
    inputs: [],
  },
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

  const trimmedValue = rawValue.trim();
  if (
    (trimmedValue.startsWith("#") && !/^#(?:!\/?|\/)/.test(trimmedValue)) ||
    trimmedValue.startsWith("mailto:") ||
    trimmedValue.startsWith("tel:") ||
    trimmedValue.startsWith("javascript:") ||
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

function isInternalHostname(hostname: string, targetHostname: string) {
  const normalizedHost = hostname.toLowerCase();
  const normalizedTarget = targetHostname.toLowerCase();

  return (
    normalizedHost === normalizedTarget ||
    normalizedHost.endsWith(`.${normalizedTarget}`) ||
    normalizedTarget.endsWith(`.${normalizedHost}`)
  );
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

  const links = $("a[href], area[href], [routerlink], [ng-reflect-router-link], [data-href], button[formaction]")
    .toArray()
    .flatMap((element, index) => {
      const rawUrl =
        $(element).attr("href") ||
        $(element).attr("routerlink") ||
        $(element).attr("ng-reflect-router-link") ||
        $(element).attr("data-href") ||
        $(element).attr("formaction");
      const url = safeAbsoluteUrl(rawUrl, pageUrl);
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
            attribute:
              $(element).attr("href") !== undefined
                ? "href"
                : $(element).attr("routerlink") !== undefined
                  ? "routerlink"
                  : $(element).attr("ng-reflect-router-link") !== undefined
                    ? "ng-reflect-router-link"
                    : $(element).attr("data-href") !== undefined
                      ? "data-href"
                      : "formaction",
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

  $('link[rel="modulepreload"][href], link[rel="preload"][as="script"][href]').each((index, element) => {
    const url = safeAbsoluteUrl($(element).attr("href"), pageUrl);
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
      attribute: "href",
      integrity: $(element).attr("integrity") ?? null,
      location: describeDomLocation($, element, pageUrl, {
        label: `Preloaded script ${index + 1}`,
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

  const interactiveElements = $(
    "button, input, textarea, select, dialog, [role='button'], [role='tab'], [role='menuitem'], [aria-haspopup], [routerlink], [ng-reflect-router-link], [data-href]",
  )
    .toArray()
    .map((element, index) => {
      const node = $(element);
      const tagName = element.tagName.toLowerCase();
      const role = node.attr("role")?.trim().toLowerCase() ?? null;
      const type =
        tagName === "textarea"
          ? "textarea"
          : tagName === "select"
            ? "select"
            : node.attr("type")?.trim().toLowerCase() ?? null;
      const rawHref =
        node.attr("href") ||
        node.attr("routerlink") ||
        node.attr("ng-reflect-router-link") ||
        node.attr("data-href") ||
        null;
      const href = rawHref ? safeAbsoluteUrl(rawHref, pageUrl) : null;
      const text = truncate(
        normalizeWhitespace(
          node.text() ||
            node.attr("aria-label") ||
            node.attr("title") ||
            node.attr("placeholder") ||
            node.attr("name") ||
            node.attr("id") ||
            "",
        ),
        140,
      );
      const name = node.attr("name")?.trim() || node.attr("id")?.trim() || null;
      const sensitiveKinds = classifySensitiveKinds(`${text} ${name ?? ""} ${type ?? ""} ${href ?? ""}`);
      const kind: PageInteractiveElement["kind"] =
        tagName === "dialog"
          ? "dialog"
          : role === "tab"
            ? "tab"
            : role === "menuitem"
              ? "menuitem"
              : ["input", "textarea", "select"].includes(tagName)
                ? "input"
                : href
                  ? "link"
                  : "button";

      return {
        kind,
        text,
        name,
        type,
        role,
        href,
        sourceUrl: pageUrl,
        sensitiveKinds,
        location: describeDomLocation($, element, pageUrl, {
          label: `Interactive element ${index + 1}`,
          attribute: rawHref ? "href" : name ? "name" : undefined,
          note: [kind, text || name, type].filter(Boolean).join(" "),
        }),
      } satisfies PageInteractiveElement;
    })
    .filter((element) => element.text || element.name || element.href || element.sensitiveKinds.length > 0);

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
    interactiveElements,
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

async function probeUrl(url: string, timeoutMs = 8_000): Promise<UrlProbe> {
  const headAttempt = await loadAttempt(url, {
    method: "HEAD",
    includeBody: false,
    timeoutMs,
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
          timeoutMs,
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

function classifyBrowserResourceKind(
  url: string,
  resourceType: string | null | undefined,
  contentType: string | null | undefined,
): ResourceKind {
  const lowerType = (resourceType ?? "").toLowerCase();
  const lowerContentType = (contentType ?? "").toLowerCase();
  const lowerUrl = url.toLowerCase();

  if (lowerType === "script" || /javascript|ecmascript/.test(lowerContentType) || /\.(?:js|mjs)(?:[?#]|$)/.test(lowerUrl)) {
    return "script";
  }
  if (lowerType === "stylesheet" || /text\/css/.test(lowerContentType) || /\.css(?:[?#]|$)/.test(lowerUrl)) {
    return "stylesheet";
  }
  if (lowerType === "image" || /^image\//.test(lowerContentType)) {
    return "image";
  }
  if (lowerType === "font" || /font|woff|ttf|otf|eot/.test(lowerContentType) || /\.(?:woff2?|ttf|otf|eot)(?:[?#]|$)/.test(lowerUrl)) {
    return "font";
  }
  if (lowerType === "iframe" || lowerType === "frame") {
    return "iframe";
  }
  if (lowerType === "fetch" || lowerType === "xhr" || /json|graphql|xml/.test(lowerContentType)) {
    return "fetch";
  }

  return "link";
}

function browserNetworkLocation(resource: BrowserNetworkResource, pageUrl: string): FindingEvidenceLocation {
  return {
    label: `Browser-loaded ${resource.kind}`,
    url: resource.url,
    path: "browser.network",
    value: resource.url,
    note: `Loaded while rendering ${pageUrl} with JavaScript enabled.`,
  };
}

function mergeBrowserNetworkResources(
  snapshot: PageSnapshot,
  networkResources: BrowserNetworkResource[],
  targetHostname: string,
) {
  const seen = new Set(snapshot.resources.map((resource) => `${resource.kind}::${resource.url}`));
  const additions = networkResources
    .filter((resource) => resource.kind !== "link")
    .flatMap((resource) => {
      const key = `${resource.kind}::${resource.url}`;
      if (seen.has(key)) {
        return [];
      }
      seen.add(key);

      let parsed: URL;
      try {
        parsed = new URL(resource.url);
      } catch {
        return [];
      }

      return [
        {
          url: resource.url,
          sourceUrl: snapshot.url,
          kind: resource.kind,
          internal: isInternalHostname(parsed.hostname, targetHostname),
          secure: parsed.protocol === "https:",
          attribute: "browser.network",
          integrity: null,
          location: browserNetworkLocation(resource, snapshot.url),
        } satisfies PageResource,
      ];
    });

  const resources = [...snapshot.resources, ...additions];
  return {
    ...snapshot,
    resources,
    images: resources.filter((resource) => resource.kind === "image"),
    forms: resources.filter((resource) => resource.kind === "form"),
  } satisfies PageSnapshot;
}

function browserResourceProbeKey(url: string) {
  try {
    const parsed = new URL(url);
    parsed.hash = "";
    return parsed.toString();
  } catch {
    return url;
  }
}

function captureBrowserResponse(
  response: PlaywrightResponse,
  resources: Map<string, BrowserNetworkResource>,
) {
  const url = response.url();
  if (resources.size >= BROWSER_NETWORK_PROBE_LIMIT && !resources.has(browserResourceProbeKey(url))) {
    return;
  }
  if (!/^https?:\/\//i.test(url)) {
    return;
  }

  const headers = response.headers();
  const contentType = headers["content-type"] ?? null;
  const kind = classifyBrowserResourceKind(url, response.request().resourceType(), contentType);
  const contentLength = parseCountHeader(headers["content-length"]);
  const key = browserResourceProbeKey(url);
  const current = resources.get(key);

  resources.set(key, {
    url,
    finalUrl: url,
    status: response.status(),
    headers,
    contentType,
    contentLength: contentLength ?? current?.contentLength ?? null,
    contentEncoding: headers["content-encoding"] ?? null,
    cacheControl: headers["cache-control"] ?? null,
    etag: headers.etag ?? null,
    lastModified: headers["last-modified"] ?? null,
    durationMs: current?.durationMs ?? null,
    totalDurationMs: current?.totalDurationMs ?? null,
    redirectCount: 0,
    error: null,
    kind,
    initiatorType: response.request().resourceType(),
    transferSize: current?.transferSize ?? null,
    decodedBodySize: current?.decodedBodySize ?? null,
  });
}

async function applyBrowserResourceTimings(
  page: Page,
  resources: Map<string, BrowserNetworkResource>,
) {
  const timings = await page
    .evaluate(() =>
      performance.getEntriesByType("resource").map((entry) => {
        const resource = entry as PerformanceResourceTiming;
        return {
          name: resource.name,
          initiatorType: resource.initiatorType,
          transferSize: Number.isFinite(resource.transferSize) ? resource.transferSize : 0,
          decodedBodySize: Number.isFinite(resource.decodedBodySize) ? resource.decodedBodySize : 0,
          duration: Number.isFinite(resource.duration) ? resource.duration : 0,
        };
      }),
    )
    .catch(() => []);

  timings.forEach((timing) => {
    if (!/^https?:\/\//i.test(timing.name)) {
      return;
    }

    const key = browserResourceProbeKey(timing.name);
    const current = resources.get(key);
    const contentLength =
      current?.contentLength ??
      (timing.transferSize > 0
        ? Math.round(timing.transferSize)
        : timing.decodedBodySize > 0
          ? Math.round(timing.decodedBodySize)
          : null);
    const contentType = current?.contentType ?? null;

    resources.set(key, {
      url: current?.url ?? timing.name,
      finalUrl: current?.finalUrl ?? timing.name,
      status: current?.status ?? 200,
      headers: current?.headers ?? {},
      contentType,
      contentLength,
      contentEncoding: current?.contentEncoding ?? null,
      cacheControl: current?.cacheControl ?? null,
      etag: current?.etag ?? null,
      lastModified: current?.lastModified ?? null,
      durationMs: current?.durationMs ?? Math.round(timing.duration),
      totalDurationMs: current?.totalDurationMs ?? Math.round(timing.duration),
      redirectCount: current?.redirectCount ?? 0,
      error: current?.error ?? null,
      kind: current?.kind ?? classifyBrowserResourceKind(timing.name, timing.initiatorType, contentType),
      initiatorType: current?.initiatorType ?? timing.initiatorType,
      transferSize: timing.transferSize > 0 ? Math.round(timing.transferSize) : current?.transferSize ?? null,
      decodedBodySize: timing.decodedBodySize > 0 ? Math.round(timing.decodedBodySize) : current?.decodedBodySize ?? null,
    });
  });
}

function buildRenderedAttempt(input: {
  requestUrl: string;
  finalUrl: string;
  status: number;
  headers: Record<string, string>;
  bodyText: string;
  durationMs: number;
}) {
  return {
    requestUrl: input.requestUrl,
    finalUrl: input.finalUrl,
    status: input.status,
    headers: {
      "content-type": "text/html; charset=utf-8",
      ...input.headers,
    },
    setCookies: [],
    bodyText: input.bodyText,
    durationMs: input.durationMs,
    totalDurationMs: input.durationMs,
    redirectChain: [],
  } satisfies HttpAttempt;
}

function classifySensitiveKinds(value: string) {
  const kinds = new Set<string>();
  if (/(login|log in|signin|sign in|auth|session|password|account)/i.test(value)) {
    kinds.add("login");
  }
  if (/(reset|forgot|recover|new[- ]?password|otp|verification|code)/i.test(value)) {
    kinds.add("password-reset");
  }
  if (/(profile|settings|billing|payment|card|invoice|address|phone|order|basket|cart)/i.test(value)) {
    kinds.add("account");
  }
  if (/(upload|file|avatar|photo|document)/i.test(value)) {
    kinds.add("upload");
  }
  if (/(search|find|query|filter|keyword)/i.test(value)) {
    kinds.add("search");
  }

  return [...kinds];
}

function mergePageSnapshots(base: PageSnapshot, extras: PageSnapshot[]) {
  const mergeByUrl = <T extends { url: string }>(items: T[]) => dedupeByUrl(items);
  const mergeByLocation = <T extends { location: FindingEvidenceLocation }>(items: T[]) => {
    const seen = new Set<string>();
    return items.filter((item) => {
      const key = `${item.location.url ?? ""}::${item.location.path ?? item.location.selector ?? ""}::${item.location.value ?? ""}`;
      if (seen.has(key)) {
        return false;
      }
      seen.add(key);
      return true;
    });
  };
  const resources = mergeByUrl([base, ...extras].flatMap((page) => page.resources));

  return {
    ...base,
    links: mergeByUrl([base, ...extras].flatMap((page) => page.links)),
    resources,
    images: resources.filter((resource) => resource.kind === "image"),
    forms: resources.filter((resource) => resource.kind === "form"),
    formSnapshots: mergeByUrl([base, ...extras].flatMap((page) => page.formSnapshots)),
    interactiveElements: mergeByLocation([base, ...extras].flatMap((page) => page.interactiveElements)),
    inlineScripts: [base, ...extras].flatMap((page) => page.inlineScripts).slice(0, 30),
    headings: mergeByLocation([base, ...extras].flatMap((page) => page.headings)),
    nodeCount: Math.max(base.nodeCount, ...extras.map((page) => page.nodeCount)),
    htmlBytes: Math.max(base.htmlBytes, ...extras.map((page) => page.htmlBytes)),
  } satisfies PageSnapshot;
}

function safeInteractionCandidate(candidate: {
  text: string;
  type: string;
  role: string;
  href: string;
}) {
  const haystack = `${candidate.text} ${candidate.type} ${candidate.role} ${candidate.href}`;
  if (/(delete|remove|destroy|pay|checkout|purchase|buy|order now|confirm|submit|save|send|upload|register|sign up|signup)/i.test(haystack)) {
    return false;
  }

  return /(login|log in|signin|sign in|account|profile|menu|nav|search|filter|tab|modal|dialog|open|details|settings|user)/i.test(
    haystack,
  );
}

async function discoverInteractiveSnapshots(
  page: Page,
  targetHostname: string,
  sharedResources: Map<string, BrowserNetworkResource>,
) {
  const selector = [
    "button",
    "[role='button']",
    "[role='tab']",
    "[role='menuitem']",
    "[aria-haspopup]",
    "[data-toggle]",
    "[data-bs-toggle]",
    "input[type='button']",
    "input[type='search']",
    "input[type='text']",
  ].join(",");
  const locator = page.locator(selector);
  const candidates = (
    await locator
      .evaluateAll((elements) =>
        elements.map((element, index) => {
          const htmlElement = element as HTMLElement;
          return {
            index,
            text:
              htmlElement.innerText ||
              htmlElement.getAttribute("aria-label") ||
              htmlElement.getAttribute("title") ||
              htmlElement.getAttribute("placeholder") ||
              "",
            type: htmlElement.getAttribute("type") || "",
            role: htmlElement.getAttribute("role") || "",
            href:
              htmlElement.getAttribute("href") ||
              htmlElement.getAttribute("routerlink") ||
              htmlElement.getAttribute("ng-reflect-router-link") ||
              "",
          };
        }),
      )
      .catch(() => [])
  )
    .filter(safeInteractionCandidate)
    .slice(0, 6);

  const snapshots: PageSnapshot[] = [];
  for (const candidate of candidates) {
    const element = locator.nth(candidate.index);
    await element.click({ timeout: 1_200 }).catch(() => undefined);
    await page.waitForTimeout(220).catch(() => undefined);
    await applyBrowserResourceTimings(page, sharedResources);
    const bodyText = await page.content().catch(() => "");
    if (!bodyText) {
      continue;
    }

    const snapshot = buildPageSnapshot(
      buildRenderedAttempt({
        requestUrl: page.url(),
        finalUrl: page.url(),
        status: 200,
        headers: {},
        bodyText,
        durationMs: 0,
      }),
      targetHostname,
    );
    if (snapshot) {
      snapshots.push(mergeBrowserNetworkResources(snapshot, [...sharedResources.values()], targetHostname));
    }
  }

  return snapshots;
}

async function renderBrowserPage(
  context: BrowserContext,
  url: string,
  targetHostname: string,
  sharedResources: Map<string, BrowserNetworkResource>,
  options: { interact?: boolean; navigationTimeoutMs?: number; networkIdleTimeoutMs?: number } = {},
) {
  const page = await context.newPage();
  page.on("response", (response) => captureBrowserResponse(response, sharedResources));

  const startedAt = Date.now();
  try {
    const response = await page.goto(url, {
      waitUntil: "domcontentloaded",
      timeout: options.navigationTimeoutMs ?? BROWSER_NAVIGATION_TIMEOUT_MS,
    });
    if (response && response.status() >= 500) {
      return null;
    }

    await page.waitForLoadState("networkidle", { timeout: options.networkIdleTimeoutMs ?? BROWSER_NETWORK_IDLE_TIMEOUT_MS }).catch(() => undefined);
    await page.waitForTimeout(250).catch(() => undefined);
    await applyBrowserResourceTimings(page, sharedResources);

    const finalUrl = page.url();
    const bodyText = await page.content();
    const durationMs = Date.now() - startedAt;
    const renderedAttempt = buildRenderedAttempt({
      requestUrl: url,
      finalUrl,
      status: response?.status() ?? 200,
      headers: response?.headers() ?? {},
      bodyText,
      durationMs,
    });
    const initialSnapshot = buildPageSnapshot(renderedAttempt, targetHostname);
    const interactionSnapshots = options.interact
      ? await discoverInteractiveSnapshots(page, targetHostname, sharedResources)
      : [];
    const snapshot =
      initialSnapshot && interactionSnapshots.length > 0
        ? mergePageSnapshots(initialSnapshot, interactionSnapshots)
        : initialSnapshot;

    return snapshot
      ? mergeBrowserNetworkResources(snapshot, [...sharedResources.values()], targetHostname)
      : null;
  } finally {
    await page.close().catch(() => undefined);
  }
}

export function getConfiguredAuthCookieHeader() {
  const raw =
    process.env.FIXNX_SCAN_AUTH_COOKIE_HEADER?.trim() ||
    process.env.FIXNX_SCAN_AUTH_COOKIES?.trim() ||
    "";
  if (!raw || raw.startsWith("[") || raw.startsWith("{")) {
    return "";
  }

  return raw.slice(0, 8_000);
}

function configuredBrowserCookies(
  primaryOrigin: string,
  targetHostname: string,
  scanAuthCookieHeader?: string | null,
): Cookie[] {
  const raw = process.env.FIXNX_SCAN_AUTH_COOKIES?.trim();
  const fallbackHeader = getConfiguredAuthCookieHeader();
  const secure = primaryOrigin.startsWith("https://");

  if (raw?.startsWith("[")) {
    try {
      const parsed = JSON.parse(raw) as Array<Partial<Cookie> & { name?: string; value?: string }>;
      return parsed
        .filter((cookie) => cookie.name && cookie.value)
        .map((cookie) => ({
          name: String(cookie.name),
          value: String(cookie.value),
          domain: cookie.domain ?? targetHostname,
          path: cookie.path ?? "/",
          expires: cookie.expires ?? -1,
          httpOnly: cookie.httpOnly ?? false,
          secure: cookie.secure ?? secure,
          sameSite: cookie.sameSite ?? "Lax",
        }));
    } catch {
      return [];
    }
  }

  const header = scanAuthCookieHeader?.trim() || fallbackHeader || raw || "";
  if (!header) {
    return [];
  }

  return header
    .split(";")
    .map((part) => part.trim())
    .flatMap((part) => {
      const separatorIndex = part.indexOf("=");
      if (separatorIndex <= 0) {
        return [];
      }

      return [
        {
          name: part.slice(0, separatorIndex).trim(),
          value: part.slice(separatorIndex + 1).trim(),
          domain: targetHostname,
          path: "/",
          expires: -1,
          httpOnly: false,
          secure,
          sameSite: "Lax" as const,
        },
      ];
    });
}

function collectBrowserCrawlTargets(
  primaryPage: PageSnapshot,
  targetHostname: string,
) {
  const origin = new URL(primaryPage.url).origin;
  const hasHashRoutes = primaryPage.links.some((link) => /#\/?/.test(link.url));
  const internalScripts = primaryPage.resources.filter((resource) => resource.kind === "script" && resource.internal);
  const appShellScript =
    internalScripts.some((resource) =>
      /(?:^|\/)(?:main|runtime|polyfills|app|bundle|chunk-[^/?#]+)\.[^/?#]*\.?js(?:[?#]|$)/i.test(resource.url),
    );
  const appShellLikely =
    hasHashRoutes ||
    (
      appShellScript &&
      primaryPage.nodeCount <= 120 &&
      primaryPage.formSnapshots.length === 0 &&
      primaryPage.h1Count === 0
    );
  const commonHashRoutes = [
    "/#/login",
    "/#/register",
    "/#/search",
    "/#/basket",
    "/#/profile",
    "/#/order-history",
    "/#/administration",
    "/#/score-board",
    "/#/contact",
    "/#/complain",
  ];
  const commonAuthRoutes = [
    ...(appShellLikely ? [...commonHashRoutes, "/login", "/signin"] : []),
  ].map((path) => new URL(path, origin).toString());

  return dedupeByUrl(
    [
      ...commonAuthRoutes.map((url) => ({ url })),
      ...primaryPage.links
        .filter((link) => {
          if (!link.internal || link.url === primaryPage.url) {
            return false;
          }

          try {
            const parsed = new URL(link.url);
            return isInternalHostname(parsed.hostname, targetHostname) && looksLikeHtmlPage(link.url);
          } catch {
            return false;
          }
        })
        .map((link) => ({ url: link.url })),
    ],
  )
    .filter((target) => target.url !== primaryPage.url)
    .sort((left, right) => browserCrawlPriority(right.url) - browserCrawlPriority(left.url))
    .slice(0, BROWSER_CRAWL_PAGE_LIMIT - 1)
    .map((target) => target.url);
}

function browserCrawlPriority(url: string) {
  try {
    const parsed = new URL(url);
    const value = `${parsed.pathname} ${parsed.hash} ${parsed.search}`.toLowerCase();
    if (/(login|signin|auth|session|account|profile)/.test(value)) {
      return 80;
    }
    if (/(admin|dashboard|settings|billing|invoice|order|cart|basket)/.test(value)) {
      return 70;
    }
    if (/(search|filter|products|catalog|query)/.test(value)) {
      return 60;
    }
    if (/(api|graphql|rest|upload|file)/.test(value)) {
      return 50;
    }
    return value.includes("#/") ? 40 : 10;
  } catch {
    return 0;
  }
}

async function inspectWithBrowser(
  startUrl: string,
  targetHostname: string,
  scanAuthCookieHeader?: string | null,
  scanMode?: NormalizedTarget["scanMode"] | null,
): Promise<{
  primaryPage: PageSnapshot | null;
  crawledPages: PageSnapshot[];
  resourceProbes: UrlProbe[];
  inspection: BrowserInspection;
}> {
  if (process.env.FIXNX_BROWSER_SCAN === "0") {
    return {
      primaryPage: null,
      crawledPages: [],
      resourceProbes: [],
      inspection: emptyBrowserInspection,
    };
  }

  const startedAt = Date.now();
  const resources = new Map<string, BrowserNetworkResource>();
  let browser: Browser | null = null;
  const primaryOrigin = new URL(startUrl).origin;
  const authCookies = configuredBrowserCookies(primaryOrigin, targetHostname, scanAuthCookieHeader);
  const browserPageLimit = scanMode === "Fast" ? 4 : BROWSER_CRAWL_PAGE_LIMIT;
  const browserNavigationTimeoutMs = scanMode === "Fast" ? 12_000 : BROWSER_NAVIGATION_TIMEOUT_MS;
  const browserNetworkIdleTimeoutMs = scanMode === "Fast" ? 1_200 : BROWSER_NETWORK_IDLE_TIMEOUT_MS;
  const logPrefix = `[fixnx][artifacts][${targetHostname}][browser]`;

  try {
    console.info(`${logPrefix} start url=${startUrl} mode=${scanMode ?? "Fast"} pageLimit=${browserPageLimit}`);
    const { chromium } = await import("playwright");
    browser = await chromium.launch({
      headless: true,
      args: ["--disable-dev-shm-usage", "--no-sandbox"],
    });
    const context = await browser.newContext({
      ignoreHTTPSErrors: true,
      javaScriptEnabled: true,
      userAgent: "fixnx/1.0 browser-audit (+https://example.invalid/cyberaudit)",
      viewport: { width: 1365, height: 768 },
    });

    if (authCookies.length > 0) {
      await context.addCookies(authCookies);
    }

    const primaryPage = await renderBrowserPage(context, startUrl, targetHostname, resources, {
      interact: true,
      navigationTimeoutMs: browserNavigationTimeoutMs,
      networkIdleTimeoutMs: browserNetworkIdleTimeoutMs,
    });
    console.info(
      `${logPrefix} primary-rendered elapsed=${Date.now() - startedAt}ms rendered=${Boolean(primaryPage)} network=${resources.size}`,
    );
    const crawlTargets = primaryPage
      ? collectBrowserCrawlTargets(primaryPage, targetHostname).slice(0, Math.max(0, browserPageLimit - 1))
      : [];
    const crawledPages: PageSnapshot[] = [];

    for (const crawlTarget of crawlTargets) {
      console.info(`${logPrefix} crawl-page start url=${crawlTarget}`);
      const snapshot = await renderBrowserPage(context, crawlTarget, targetHostname, resources, {
        navigationTimeoutMs: browserNavigationTimeoutMs,
        networkIdleTimeoutMs: browserNetworkIdleTimeoutMs,
      }).catch(() => null);
      if (snapshot && snapshot.url !== primaryPage?.url) {
        crawledPages.push(snapshot);
      }
      console.info(
        `${logPrefix} crawl-page done url=${crawlTarget} elapsed=${Date.now() - startedAt}ms captured=${Boolean(snapshot)}`,
      );
    }

    await context.close().catch(() => undefined);

    const renderedPageCount = (primaryPage ? 1 : 0) + crawledPages.length;
    return {
      primaryPage,
      crawledPages,
      resourceProbes: [...resources.values()],
      inspection: {
        attempted: true,
        rendered: Boolean(primaryPage),
        finalUrl: primaryPage?.url ?? null,
        durationMs: Date.now() - startedAt,
        error: null,
        renderedPageCount,
        networkRequestCount: resources.size,
        authenticated: authCookies.length > 0,
        routeMap: emptyBrowserInspection.routeMap,
      },
    };
  } catch (error) {
    console.error(`${logPrefix} failed elapsed=${Date.now() - startedAt}ms`, error);
    return {
      primaryPage: null,
      crawledPages: [],
      resourceProbes: [],
      inspection: {
        attempted: true,
        rendered: false,
        finalUrl: null,
        durationMs: Date.now() - startedAt,
        error: error instanceof Error ? error.message : "Browser rendering failed.",
        renderedPageCount: 0,
        networkRequestCount: resources.size,
        authenticated: authCookies.length > 0,
        routeMap: emptyBrowserInspection.routeMap,
      },
    };
  } finally {
    await browser?.close().catch(() => undefined);
  }
}

function buildBrowserRouteMap(pages: PageSnapshot[], resourceProbes: UrlProbe[]): BrowserRouteMap {
  const apiEndpoints = dedupeByUrl(
    [
      ...pages.flatMap((page) =>
        page.resources
          .filter((resource) => resource.kind === "fetch")
          .map((resource) => ({ url: resource.url })),
      ),
      ...resourceProbes
        .filter((probe) => /json|graphql|xml|text\/plain/i.test(probe.contentType ?? ""))
        .map((probe) => ({ url: probe.url })),
    ],
  ).map((endpoint) => endpoint.url);

  const buttonSeen = new Set<string>();
  const inputSeen = new Set<string>();
  return {
    pages: pages.map((page) => page.url),
    apiEndpoints: apiEndpoints.slice(0, 40),
    forms: pages.flatMap((page) =>
      page.formSnapshots.map((form) => ({
        url: form.url,
        method: form.method,
        sourceUrl: form.sourceUrl,
        sensitiveKinds: form.sensitiveKinds,
        fieldNames: form.fieldNames,
      })),
    ),
    buttons: pages.flatMap((page) =>
      page.interactiveElements
        .filter((element) => element.kind !== "input")
        .map((element) => ({
          text: element.text || element.name || element.href || element.kind,
          kind: element.kind,
          sourceUrl: element.sourceUrl,
          sensitiveKinds: element.sensitiveKinds,
        })),
    ).filter((button) => {
      const key = `${button.sourceUrl}::${button.text}::${button.kind}`;
      if (buttonSeen.has(key)) {
        return false;
      }
      buttonSeen.add(key);
      return true;
    }).slice(0, 60),
    inputs: pages.flatMap((page) =>
      page.interactiveElements
        .filter((element) => element.kind === "input")
        .map((element) => ({
          name: element.name || element.text || "unnamed",
          type: element.type || "text",
          sourceUrl: element.sourceUrl,
          sensitiveKinds: element.sensitiveKinds,
        })),
    ).filter((input) => {
      const key = `${input.sourceUrl}::${input.name}::${input.type}`;
      if (inputSeen.has(key)) {
        return false;
      }
      inputSeen.add(key);
      return true;
    }).slice(0, 60),
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
  if (/__NEXT_DATA__"[^>]*>|next\/static|x-nextjs/i.test(html)) {
    hints.add("Next.js frontend");
  }
  if (/react/i.test(html) && /data-reactroot|__next/i.test(html)) {
    hints.add("React");
  }
  if (/ng-version=["'][^"']+["']|ng-app|_ngcontent-|angular/i.test(html)) {
    const version = html.match(/ng-version=["']([^"']+)["']/i)?.[1];
    hints.add(version ? `Angular ${version}` : "Angular");
  }
  if (/data-v-|__VUE__|vue(?:\.runtime)?(?:\.global)?(?:\.prod)?\.js/i.test(html)) {
    hints.add("Vue.js");
  }
  if (/(?:\/|-)nuxt(?:\/|-)|__NUXT__/i.test(html)) {
    hints.add("Nuxt");
  }
  if (/(?:\/|-)vite(?:\/|-)|@vite\/client/i.test(html)) {
    hints.add("Vite");
  }
  if (/jquery(?:-|\.)(\d+\.\d+(?:\.\d+)?)/i.test(html)) {
    hints.add(`jQuery ${html.match(/jquery(?:-|\.)(\d+\.\d+(?:\.\d+)?)/i)?.[1]}`);
  } else if (/jquery/i.test(html)) {
    hints.add("jQuery");
  }
  if (/bootstrap(?:\.bundle)?(?:\.min)?\.js|bootstrap(?:\.min)?\.css/i.test(html)) {
    const version = html.match(/bootstrap[@/-](\d+\.\d+(?:\.\d+)?)/i)?.[1];
    hints.add(version ? `Bootstrap ${version}` : "Bootstrap");
  }
  if (/cdn\.jsdelivr\.net|cdnjs\.cloudflare\.com|unpkg\.com|esm\.sh/i.test(html)) {
    hints.add("Public package CDN");
  }
  if (
    /cdn\.shopify\.com|myshopify\.com|shopify-payment-button|shopify-section|shopify-analytics|Shopify\.(?:theme|routes|locale|Analytics)/i.test(
      html,
    )
  ) {
    hints.add("Shopify");
  }
  if (/herokuapp\.com/i.test(context.primary.finalUrl) || /heroku/i.test(headers.server ?? "")) {
    hints.add("Heroku hosting");
  }

  primaryPage.resources
    .filter((resource) => resource.kind === "script" || resource.kind === "stylesheet")
    .slice(0, 30)
    .forEach((resource) => {
      const url = resource.url;
      const version = url.match(/(?:react|vue|angular|jquery|bootstrap|lodash|moment|axios)[@/-](\d+\.\d+(?:\.\d+)?)/i)?.[1];
      if (/react/i.test(url)) {
        hints.add(version ? `React ${version}` : "React asset");
      }
      if (/vue/i.test(url)) {
        hints.add(version ? `Vue ${version}` : "Vue asset");
      }
      if (/angular/i.test(url)) {
        hints.add(version ? `Angular ${version}` : "Angular asset");
      }
      if (/jquery/i.test(url)) {
        hints.add(version ? `jQuery ${version}` : "jQuery asset");
      }
      if (/bootstrap/i.test(url)) {
        hints.add(version ? `Bootstrap ${version}` : "Bootstrap asset");
      }
    });

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
  const startedAt = Date.now();
  const scanMode = target.scanMode ?? "Fast";
  const artifactTimeoutMs = scanMode === "Fast" ? 8_000 : 10_000;
  const fetchCrawlLimit = scanMode === "Fast" ? 4 : FETCH_CRAWL_PAGE_LIMIT;
  const resourceProbeLimit = scanMode === "Fast" ? 25 : 40;
  const internalLinkProbeLimit = scanMode === "Fast" ? 8 : 16;
  const externalLinkProbeLimit = scanMode === "Fast" ? 4 : 10;
  const logPrefix = `[fixnx][artifacts][${target.targetHostname}][${scanMode}]`;
  console.info(`${logPrefix} start`);
  const context = await loadPageContext(target);
  console.info(`${logPrefix} page-context loaded elapsed=${Date.now() - startedAt}ms primary=${Boolean(context.primary)}`);
  const fetchedPrimaryPage = context.primary ? buildPageSnapshot(context.primary, target.targetHostname) : null;
  const browserResult = await inspectWithBrowser(
    context.primary?.finalUrl ?? target.httpsUrl,
    target.targetHostname,
    target.authCookieHeader,
    scanMode,
  );
  console.info(
    `${logPrefix} browser complete elapsed=${Date.now() - startedAt}ms rendered=${browserResult.inspection.rendered} pages=${browserResult.inspection.renderedPageCount} network=${browserResult.inspection.networkRequestCount}`,
  );
  const primaryPage = browserResult.primaryPage ?? fetchedPrimaryPage;
  const primaryIsInterstitial = isLikelyEdgeInterstitial(context.primary) && !browserResult.primaryPage;
  const browserCrawledUrls = new Set(browserResult.crawledPages.map((page) => page.url));
  const crawlTargets = primaryPage
    ? dedupeByUrl(
        primaryPage.links.filter(
          (link) =>
            link.internal &&
            looksLikeHtmlPage(link.url) &&
            link.url !== primaryPage.url &&
            !browserCrawledUrls.has(link.url),
        ),
      )
        .slice(0, Math.max(0, fetchCrawlLimit - browserResult.crawledPages.length))
        .map((link) => link.url)
    : [];
  const scopedCrawlTargets = primaryIsInterstitial ? [] : crawlTargets;

  const crawledAttempts = await mapWithConcurrency(scopedCrawlTargets, 3, async (url) =>
    loadAttempt(url, {
      timeoutMs: artifactTimeoutMs,
    }),
  );
  console.info(
    `${logPrefix} fetch-crawl complete elapsed=${Date.now() - startedAt}ms targets=${scopedCrawlTargets.length}`,
  );

  const fetchedCrawledPages = crawledAttempts
    .flatMap((attempt) => (attempt ? [buildPageSnapshot(attempt, target.targetHostname)] : []))
    .filter((page): page is PageSnapshot => Boolean(page));
  const crawledPages = dedupeByUrl([...browserResult.crawledPages, ...fetchedCrawledPages]).filter(
    (page) => page.url !== primaryPage?.url,
  );
  const allPages = primaryPage ? [primaryPage, ...crawledPages] : crawledPages;

  const browserProbeUrls = new Set(browserResult.resourceProbes.map((probe) => probe.url));
  const resourceTargets = primaryPage && !primaryIsInterstitial
    ? dedupeByUrl(primaryPage.resources).slice(0, resourceProbeLimit)
        .filter((resource) => !browserProbeUrls.has(resource.url))
    : [];
  const fetchedResourceProbes = await mapWithConcurrency(resourceTargets, 5, async (resource) =>
    probeUrl(resource.url, artifactTimeoutMs),
  );
  console.info(
    `${logPrefix} resource-probes complete elapsed=${Date.now() - startedAt}ms targets=${resourceTargets.length}`,
  );
  const resourceProbes = dedupeByUrl([...browserResult.resourceProbes, ...fetchedResourceProbes]);
  const browserInspection = {
    ...browserResult.inspection,
    routeMap: buildBrowserRouteMap(allPages, resourceProbes),
  } satisfies BrowserInspection;

  const internalLinkTargets = dedupeByUrl(
    allPages.flatMap((page) => page.links.filter((link) => link.internal && looksLikeHtmlPage(link.url))),
  ).slice(0, internalLinkProbeLimit);
  const externalLinkTargets = dedupeByUrl(
    allPages.flatMap((page) => page.links.filter((link) => !link.internal)),
  ).slice(0, externalLinkProbeLimit);

  const internalLinkProbes = await mapWithConcurrency(internalLinkTargets, 4, async (link) => {
    const probe = await probeUrl(link.url, artifactTimeoutMs);
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
    const probe = await probeUrl(link.url, artifactTimeoutMs);
    return {
      ...probe,
      sourceUrl: link.sourceUrl,
      text: link.text,
      internal: link.internal,
      secure: link.secure,
      location: link.location,
    } satisfies LinkProbe;
  });
  console.info(
    `${logPrefix} link-probes complete elapsed=${Date.now() - startedAt}ms internal=${internalLinkTargets.length} external=${externalLinkTargets.length}`,
  );

  const tlsInfo = await inspectTls(target.targetHostname);
  console.info(`${logPrefix} tls complete elapsed=${Date.now() - startedAt}ms`);

  return {
    context,
    primaryPage,
    crawledPages,
    resourceProbes,
    internalLinkProbes,
    externalLinkProbes,
    tlsInfo,
    browserInspection,
    technologyHints: detectTechnologies(context, primaryPage),
    wafHints: detectWafCdn(context),
  };
}

export async function loadAuditArtifacts(target: NormalizedTarget) {
  if (target.authCookieHeader || target.secondaryAuthCookieHeader) {
    return buildArtifacts(target);
  }

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
