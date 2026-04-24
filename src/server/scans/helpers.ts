import { randomUUID } from "node:crypto";
import { lookup } from "node:dns/promises";
import net from "node:net";
import { type CheerioAPI } from "cheerio";
import { type AnyNode, type Element } from "domhandler";
import {
  type CategoryKey,
  type FindingEvidenceLocation,
  type FindingStatus,
  type ScanFinding,
  type ScanFindingEvidence,
  type Severity,
} from "@/lib/types";
import { badRequest } from "@/server/api/errors";
import { type HttpAttempt, type NormalizedTarget, type PageContext } from "@/server/scans/types";

const HOSTNAME_PATTERN =
  /^(?=.{1,253}$)(?!-)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i;

function normalizeHostInput(input: string) {
  const value = input.trim();
  if (!value) {
    throw badRequest("A target domain is required.");
  }

  const candidate = /^https?:\/\//i.test(value) ? value : `https://${value}`;
  let url: URL;
  try {
    url = new URL(candidate);
  } catch {
    throw badRequest("Enter a valid domain or URL.");
  }

  if (!["http:", "https:"].includes(url.protocol)) {
    throw badRequest("Only http and https targets are supported.");
  }

  if (url.username || url.password) {
    throw badRequest("Credentials are not allowed in targets.");
  }

  const hostname = url.hostname.toLowerCase();
  if (!HOSTNAME_PATTERN.test(hostname)) {
    throw badRequest("Enter a valid public domain.");
  }

  return {
    originalInput: value,
    normalizedTarget: hostname,
    targetHostname: hostname,
    httpsUrl: `https://${hostname}`,
    httpUrl: `http://${hostname}`,
  } satisfies NormalizedTarget;
}

function isPrivateIpv4(address: string) {
  const parts = address.split(".").map((part) => Number(part));
  if (parts.length !== 4 || parts.some((part) => Number.isNaN(part))) {
    return false;
  }

  const [a, b] = parts;
  return (
    a === 10 ||
    a === 127 ||
    a === 0 ||
    (a === 100 && b >= 64 && b <= 127) ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    (a === 198 && (b === 18 || b === 19)) ||
    a >= 224
  );
}

function isPrivateIpv6(address: string) {
  const normalized = address.toLowerCase();
  return (
    normalized === "::1" ||
    normalized === "::" ||
    normalized.startsWith("fc") ||
    normalized.startsWith("fd") ||
    normalized.startsWith("fe8") ||
    normalized.startsWith("fe9") ||
    normalized.startsWith("fea") ||
    normalized.startsWith("feb")
  );
}

export async function assertPublicHostname(hostname: string) {
  if (
    hostname === "localhost" ||
    hostname.endsWith(".local") ||
    hostname.endsWith(".internal") ||
    hostname.endsWith(".lan") ||
    net.isIP(hostname) !== 0
  ) {
    throw badRequest("Only public domains are supported.");
  }

  let addresses;
  try {
    addresses = await lookup(hostname, { all: true });
  } catch {
    throw badRequest("The target domain could not be resolved.");
  }

  if (!Array.isArray(addresses) || !addresses.length) {
    throw badRequest("The target domain could not be resolved.");
  }

  for (const address of addresses) {
    if (
      (address.family === 4 && isPrivateIpv4(address.address)) ||
      (address.family === 6 && isPrivateIpv6(address.address))
    ) {
      throw badRequest("Private or internal network targets are blocked.");
    }
  }
}

async function safeFetchInternal(
  url: string,
  init: RequestInit & { timeoutMs?: number; followRedirects?: boolean } = {},
  depth = 0,
  redirectChain: Array<{ url: string; status: number; location: string }> = [],
): Promise<{ response: Response; finalUrl: string; redirectChain: Array<{ url: string; status: number; location: string }> }> {
  if (depth > 4) {
    throw badRequest("Too many redirects while fetching the target.");
  }

  const parsed = new URL(url);
  if (!["http:", "https:"].includes(parsed.protocol)) {
    throw badRequest("Unsupported target protocol.");
  }

  await assertPublicHostname(parsed.hostname);

  const controller = new AbortController();
  const headers = new Headers(init.headers);
  headers.set(
    "user-agent",
    "CyberAudit/1.0 (+https://example.invalid/cyberaudit)",
  );
  headers.set(
    "accept",
    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
  );

  const timeout = setTimeout(() => controller.abort(), init.timeoutMs ?? 8_000);

  try {
    const response = await fetch(parsed.toString(), {
      ...init,
      headers,
      redirect: "manual",
      signal: controller.signal,
    });

    if (
      init.followRedirects !== false &&
      response.status >= 300 &&
      response.status < 400 &&
      response.headers.get("location")
    ) {
      const redirectTarget = new URL(response.headers.get("location")!, parsed);
      return safeFetchInternal(redirectTarget.toString(), init, depth + 1, [
        ...redirectChain,
        {
          url: parsed.toString(),
          status: response.status,
          location: redirectTarget.toString(),
        },
      ]);
    }

    return {
      response,
      finalUrl: parsed.toString(),
      redirectChain,
    };
  } finally {
    clearTimeout(timeout);
  }
}

function headersToObject(headers: Headers) {
  return Object.fromEntries(headers.entries());
}

function splitSetCookie(headers: Headers) {
  const headerBag = headers as Headers & { getSetCookie?: () => string[] };
  if (typeof headerBag.getSetCookie === "function") {
    return headerBag.getSetCookie();
  }

  const raw = headers.get("set-cookie");
  return raw ? [raw] : [];
}

export async function loadAttempt(
  url: string,
  init: RequestInit & { timeoutMs?: number; includeBody?: boolean; followRedirects?: boolean } = {},
): Promise<HttpAttempt | null> {
  try {
    const startedAt = Date.now();
    const { response, finalUrl, redirectChain } = await safeFetchInternal(url, init);
    const responseReceivedAt = Date.now();
    const bodyText =
      init.includeBody === false ? "" : (await response.text().catch(() => "")).slice(0, 700_000);
    const completedAt = Date.now();

    return {
      requestUrl: url,
      finalUrl,
      status: response.status,
      headers: headersToObject(response.headers),
      setCookies: splitSetCookie(response.headers),
      bodyText,
      durationMs: responseReceivedAt - startedAt,
      totalDurationMs: completedAt - startedAt,
      redirectChain,
    };
  } catch {
    return null;
  }
}

export async function loadPageContext(target: NormalizedTarget): Promise<PageContext> {
  const [https, http] = await Promise.all([
    loadAttempt(target.httpsUrl),
    loadAttempt(target.httpUrl),
  ]);

  return {
    https,
    http,
    primary:
      https && https.status < 500 ? https : http && http.status < 500 ? http : https ?? http,
  };
}

export function normalizeScanTarget(input: string) {
  return normalizeHostInput(input);
}

export async function validateTarget(input: string) {
  const target = normalizeScanTarget(input);
  await assertPublicHostname(target.targetHostname);
  return target;
}

export function createFinding(input: {
  category: CategoryKey;
  status?: FindingStatus;
  severity: Severity;
  scoreWeight?: number;
  title: string;
  shortDescription: string;
  whyItMatters: string;
  recommendation: string;
  evidence?: ScanFindingEvidence;
  references?: string[];
  premiumOnly?: boolean;
  id?: string;
  checkKey?: string;
}) {
  const timestamp = new Date().toISOString();
  return {
    id: input.id ?? `${input.category}-${randomUUID()}`,
    checkKey: input.checkKey,
    category: input.category,
    status: input.status ?? (input.severity === "info" ? "info" : input.severity === "low" || input.severity === "medium" ? "warning" : "fail"),
    severity: input.severity,
    scoreWeight: input.scoreWeight,
    title: input.title,
    shortDescription: input.shortDescription,
    whyItMatters: input.whyItMatters,
    recommendation: input.recommendation,
    evidence: input.evidence ?? {},
    references: input.references ?? [],
    premiumOnly: input.premiumOnly ?? false,
    createdAt: timestamp,
    updatedAt: timestamp,
  } satisfies ScanFinding;
}

export function getOrigin(url: string) {
  return new URL(url).origin;
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

function isElementNode(node: AnyNode | null | undefined): node is Element {
  return Boolean(node && "tagName" in node && typeof node.tagName === "string");
}

function cssSegment($: CheerioAPI, element: Element) {
  const node = $(element);
  const tag = element.tagName.toLowerCase();
  const id = normalizeWhitespace(node.attr("id"));
  if (id) {
    return `${tag}#${id}`;
  }

  if (tag === "meta") {
    const name = normalizeWhitespace(node.attr("name"));
    const property = normalizeWhitespace(node.attr("property"));
    if (name) {
      return `${tag}[name="${name}"]`;
    }
    if (property) {
      return `${tag}[property="${property}"]`;
    }
  }

  if (tag === "link") {
    const rel = normalizeWhitespace(node.attr("rel"));
    if (rel) {
      return `${tag}[rel="${rel}"]`;
    }
  }

  const classes = normalizeWhitespace(node.attr("class"))
    .split(" ")
    .filter(Boolean)
    .slice(0, 2);
  if (classes.length > 0) {
    return `${tag}.${classes.join(".")}`;
  }

  const siblings = node.parent().children(tag);
  if (siblings.length > 1) {
    const index = siblings.toArray().findIndex((candidate) => candidate === element);
    return `${tag}:nth-of-type(${index + 1})`;
  }

  return tag;
}

export function buildDomPath($: CheerioAPI, node: AnyNode, maxDepth = 6) {
  const segments: string[] = [];
  let current: AnyNode | null | undefined = node;

  while (isElementNode(current) && segments.length < maxDepth) {
    segments.unshift(cssSegment($, current));
    current = current.parent;
  }

  return segments.join(" > ");
}

export function getNearbyContext($: CheerioAPI, node: AnyNode, maxLength = 160) {
  if (!isElementNode(node)) {
    return "";
  }

  const element = $(node);
  const candidates = [
    element.attr("aria-label"),
    element.attr("title"),
    element.siblings("figcaption").first().text(),
    element
      .closest("figure, article, section, main, header, footer, nav, aside, li, form, div")
      .find("h1, h2, h3, h4, h5, h6")
      .first()
      .text(),
    element.parent().text(),
  ]
    .map((value) => truncate(normalizeWhitespace(value), maxLength))
    .filter((value) => value.length >= 4);

  return candidates[0] ?? "";
}

function resolveElementUrl(rawValue: string | undefined, pageUrl: string) {
  if (!rawValue) {
    return undefined;
  }

  try {
    return new URL(rawValue, pageUrl).toString();
  } catch {
    return rawValue;
  }
}

export function describeDomLocation(
  $: CheerioAPI,
  node: AnyNode,
  pageUrl: string,
  input: {
    label: string;
    attribute?: string;
    note?: string;
  },
): FindingEvidenceLocation {
  const element = $(node);
  const attribute = input.attribute;
  const rawValue = attribute ? element.attr(attribute) : undefined;

  return {
    label: input.label,
    selector: isElementNode(node) ? cssSegment($, node) : undefined,
    path: buildDomPath($, node),
    url: resolveElementUrl(rawValue, pageUrl) ?? pageUrl,
    context: getNearbyContext($, node),
    value: truncate(normalizeWhitespace(rawValue), 180) || undefined,
    attribute,
    note: input.note,
  };
}

export function createResponseLocation(input: {
  label: string;
  url: string;
  path: string;
  value?: string | null;
  note?: string;
}): FindingEvidenceLocation {
  return {
    label: input.label,
    url: input.url,
    path: input.path,
    value: input.value ? truncate(normalizeWhitespace(input.value), 180) : undefined,
    note: input.note,
  };
}
