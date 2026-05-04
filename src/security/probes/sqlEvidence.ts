import { createHash } from "node:crypto";

export type EvidenceStrength = "weak" | "moderate" | "strong" | "exploit-proof";

export type ParameterContext =
  | "search"
  | "id"
  | "filter"
  | "sort"
  | "pagination"
  | "redirect"
  | "auth-flow"
  | "tracking"
  | "csrf"
  | "unknown";

export type DbErrorFamily =
  | "mysql"
  | "postgres"
  | "mssql"
  | "oracle"
  | "sqlite"
  | "odbc"
  | "pdo"
  | "unknown";

export type StrictDbErrorMatch = {
  signature: string;
  family: DbErrorFamily;
  excerpt: string;
};

export type NormalizedSqlResponseSignature = {
  status: number;
  contentType: string;
  normalizedHash: string;
  stableTextHash: string;
  lengthBucket: string;
  title?: string;
  importantTokens: string[];
  recordCount?: number | null;
  jsonShape?: string[];
  formCount?: number;
  linkCount?: number;
  isCaptchaOrBotPage?: boolean;
  isLoginPage?: boolean;
  isSearchPage?: boolean;
  isRedirectValidationPage?: boolean;
  stableTextLength: number;
};

const strictDbErrorPatterns: Array<{ pattern: RegExp; family: DbErrorFamily; signature: string }> = [
  { pattern: /You have an error in your SQL syntax/i, family: "mysql", signature: "You have an error in your SQL syntax" },
  { pattern: /Warning:\s*mysql_/i, family: "mysql", signature: "Warning: mysql_" },
  { pattern: /MySQLSyntaxErrorException/i, family: "mysql", signature: "MySQLSyntaxErrorException" },
  { pattern: /MariaDB server version/i, family: "mysql", signature: "MariaDB server version" },

  { pattern: /PostgreSQL.*ERROR/i, family: "postgres", signature: "PostgreSQL ERROR" },
  { pattern: /PG::SyntaxError/i, family: "postgres", signature: "PG::SyntaxError" },
  { pattern: /org\.postgresql\.util\.PSQLException/i, family: "postgres", signature: "org.postgresql.util.PSQLException" },
  { pattern: /unterminated quoted string at or near/i, family: "postgres", signature: "unterminated quoted string at or near" },

  { pattern: /Microsoft SQL Server/i, family: "mssql", signature: "Microsoft SQL Server" },
  { pattern: /ODBC SQL Server Driver/i, family: "mssql", signature: "ODBC SQL Server Driver" },
  { pattern: /SQLServerException/i, family: "mssql", signature: "SQLServerException" },
  { pattern: /Unclosed quotation mark after the character string/i, family: "mssql", signature: "Unclosed quotation mark after the character string" },

  { pattern: /ORA-\d{5}/i, family: "oracle", signature: "ORA-nnnnn" },
  { pattern: /Oracle error/i, family: "oracle", signature: "Oracle error" },
  { pattern: /Oracle.*Driver/i, family: "oracle", signature: "Oracle Driver" },

  { pattern: /SQLiteException/i, family: "sqlite", signature: "SQLiteException" },
  { pattern: /SQLITE_ERROR/i, family: "sqlite", signature: "SQLITE_ERROR" },
  { pattern: /near\s+.{1,120}\s+syntax error/i, family: "sqlite", signature: "near ... syntax error" },

  { pattern: /PDOException/i, family: "pdo", signature: "PDOException" },
  { pattern: /Doctrine\\DBAL/i, family: "pdo", signature: "Doctrine DBAL" },
  { pattern: /SequelizeDatabaseError/i, family: "unknown", signature: "SequelizeDatabaseError" },
  { pattern: /PrismaClientKnownRequestError/i, family: "unknown", signature: "PrismaClientKnownRequestError" },
];

function hash(value: string) {
  return createHash("sha256").update(value).digest("hex").slice(0, 16);
}

function shortExcerpt(bodyText: string, matchIndex: number, maxLength = 180) {
  const start = Math.max(0, matchIndex - 70);
  const value = bodyText
    .slice(start, start + maxLength)
    .replace(/\s+/g, " ")
    .trim();
  return value.length > maxLength ? `${value.slice(0, maxLength - 1)}…` : value;
}

export function findStrictDbErrorSignature(bodyText: string): StrictDbErrorMatch | null {
  for (const entry of strictDbErrorPatterns) {
    const match = entry.pattern.exec(bodyText);
    if (match?.index !== undefined) {
      return {
        signature: entry.signature,
        family: entry.family,
        excerpt: shortExcerpt(bodyText, match.index),
      };
    }
  }

  return null;
}

export function classifyParameter(name: string, rawUrl = ""): ParameterContext {
  const normalized = name.trim().toLowerCase();
  const path = (() => {
    try {
      return new URL(rawUrl).pathname.toLowerCase();
    } catch {
      return "";
    }
  })();

  if (/^(?:utm_.+|gclid|fbclid|msclkid|yclid|mc_cid|mc_eid)$/.test(normalized)) {
    return "tracking";
  }
  if (/^(?:csrf|xsrf|state_token|authenticity_token|requestverificationtoken|nonce)$/.test(normalized)) {
    return "csrf";
  }
  if (/^(?:continue|next|redirect|redirect_uri|return|returnurl|url|target|dest|destination|callback|relaystate|service|goto)$/.test(normalized)) {
    return "redirect";
  }
  if (/^(?:state|code|client_id|scope|response_type|ec|hl|passive|authuser|prompt|login_hint)$/.test(normalized)) {
    return "auth-flow";
  }
  if (/^(?:q|query|search|keyword|term|s)$/.test(normalized) || /(?:search|catalog|products)/.test(path)) {
    return "search";
  }
  if (/^(?:id|uid|user_id|userid|product_id|order_id|item|basket|cart)$/.test(normalized)) {
    return "id";
  }
  if (/^(?:filter|category|tag|type|status)$/.test(normalized)) {
    return "filter";
  }
  if (/^(?:sort|order|orderby|order_by)$/.test(normalized)) {
    return "sort";
  }
  if (/^(?:page|p|offset|limit|per_page|size)$/.test(normalized)) {
    return "pagination";
  }

  return "unknown";
}

function jsonShape(value: unknown, prefix = ""): string[] {
  if (Array.isArray(value)) {
    return value.slice(0, 2).flatMap((entry, index) => jsonShape(entry, `${prefix}[${index}]`));
  }
  if (!value || typeof value !== "object") {
    return prefix ? [prefix] : [];
  }
  return Object.entries(value as Record<string, unknown>)
    .slice(0, 40)
    .flatMap(([key, entry]) => jsonShape(entry, prefix ? `${prefix}.${key}` : key));
}

function parseJson(bodyText: string) {
  try {
    return JSON.parse(bodyText) as unknown;
  } catch {
    return null;
  }
}

function recordCountFromJson(value: unknown): number | null {
  if (Array.isArray(value)) {
    return value.length;
  }
  if (value && typeof value === "object") {
    for (const entry of Object.values(value as Record<string, unknown>)) {
      if (Array.isArray(entry)) {
        return entry.length;
      }
    }
  }
  return null;
}

function normalizeText(bodyText: string) {
  return bodyText
    .replace(/<script\b[^>]*>[\s\S]*?<\/script>/gi, " ")
    .replace(/<style\b[^>]*>[\s\S]*?<\/style>/gi, " ")
    .replace(/<!--[\s\S]*?-->/g, " ")
    .replace(/\bnonce=["'][^"']+["']/gi, 'nonce="[nonce]"')
    .replace(/\b(?:csrf|xsrf|request|trace|correlation|session|client)[_-]?(?:id|token)=["'][^"']+["']/gi, "[token-field]=[token]")
    .replace(/\b[A-Za-z0-9_-]{32,}\b/g, "[token]")
    .replace(/\b\d{10,}\b/g, "0")
    .replace(/https?:\/\/[^\s"'<>]+/gi, "[url]")
    .replace(/<[^>]+>/g, " ")
    .replace(/&(?:nbsp|amp|quot|lt|gt);/gi, " ")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, 120_000);
}

function lengthBucket(length: number) {
  if (length < 1_000) return "<1k";
  if (length < 5_000) return "1k-5k";
  if (length < 15_000) return "5k-15k";
  if (length < 50_000) return "15k-50k";
  if (length < 150_000) return "50k-150k";
  return "150k+";
}

function extractTitle(bodyText: string) {
  const match = /<title[^>]*>([\s\S]{0,300}?)<\/title>/i.exec(bodyText);
  return match?.[1]?.replace(/\s+/g, " ").trim();
}

export function buildSqlResponseSignature(input: {
  status: number;
  contentType?: string;
  bodyText: string;
  url?: string;
}): NormalizedSqlResponseSignature {
  const contentType = input.contentType ?? "";
  const parsed = /json/i.test(contentType) || /^[\s\r\n]*[{\[]/.test(input.bodyText) ? parseJson(input.bodyText) : null;
  const stableText = parsed ? JSON.stringify(parsed).replace(/\b\d{10,}\b/g, "0") : normalizeText(input.bodyText);
  const lowerText = stableText.toLowerCase();
  const rawLower = input.bodyText.toLowerCase();
  const pathname = (() => {
    try {
      return input.url ? new URL(input.url).pathname.toLowerCase() : "";
    } catch {
      return "";
    }
  })();

  return {
    status: input.status,
    contentType,
    normalizedHash: hash(stableText.slice(0, 80_000)),
    stableTextHash: hash(stableText.slice(0, 40_000)),
    lengthBucket: lengthBucket(stableText.length),
    title: extractTitle(input.bodyText),
    importantTokens: Array.from(
      new Set(
        stableText
          .match(/\b(?:login|signin|captcha|search|results|invalid|redirect|continue|forbidden|unauthorized|database|sql|error)\b/gi)
          ?.map((token) => token.toLowerCase())
          .slice(0, 20) ?? [],
      ),
    ),
    recordCount: parsed ? recordCountFromJson(parsed) : null,
    jsonShape: parsed ? jsonShape(parsed).slice(0, 40) : undefined,
    formCount: (input.bodyText.match(/<form\b/gi) ?? []).length,
    linkCount: (input.bodyText.match(/<a\b/gi) ?? []).length,
    isCaptchaOrBotPage: /captcha|unusual traffic|verify you are human|enable javascript and cookies|sorry\/index|bot detection/i.test(
      input.bodyText,
    ),
    isLoginPage: /login|signin|serviceLogin|identifier|password|account/i.test(rawLower) || /login|signin|account/.test(pathname),
    isSearchPage: /search|results/.test(lowerText) || /\/search/.test(pathname),
    isRedirectValidationPage: /redirect|continue|return url|invalid url|malformed url|unsupported redirect/.test(lowerText),
    stableTextLength: stableText.length,
  };
}

export function responseDiffDimensions(left: NormalizedSqlResponseSignature, right: NormalizedSqlResponseSignature) {
  const dimensions: string[] = [];
  if (left.status !== right.status) {
    dimensions.push("status");
  }
  if (left.recordCount !== null && right.recordCount !== null && Math.abs((left.recordCount ?? 0) - (right.recordCount ?? 0)) >= 3) {
    dimensions.push("record-count");
  }
  if (left.jsonShape && right.jsonShape && left.jsonShape.join("|") !== right.jsonShape.join("|")) {
    dimensions.push("json-shape");
  }
  if (left.lengthBucket !== right.lengthBucket && Math.abs(left.stableTextLength - right.stableTextLength) > 800) {
    dimensions.push("length-bucket");
  }
  if (left.stableTextHash !== right.stableTextHash && !left.isCaptchaOrBotPage && !right.isCaptchaOrBotPage) {
    dimensions.push("stable-text");
  }
  return dimensions;
}

export function highDynamicResponseSignal(input: {
  url?: string;
  headers?: Record<string, string>;
  bodyText: string;
  signature?: NormalizedSqlResponseSignature;
}) {
  const server = input.headers?.server ?? input.headers?.Server ?? "";
  const setCookie = input.headers?.["set-cookie"] ?? input.headers?.["Set-Cookie"] ?? "";
  const urlText = input.url ?? "";
  const body = input.bodyText;
  const signals = [
    /^gws$/i.test(server) ? "search-provider-server" : "",
    /\/ServiceLogin|accounts\./i.test(urlText) ? "auth-provider-flow" : "",
    /\/search\b/i.test(urlText) && /[?&]q=/.test(urlText) ? "search-result-page" : "",
    input.signature?.isCaptchaOrBotPage ? "anti-abuse-page" : "",
    input.signature?.isLoginPage ? "login-page" : "",
    /\bnonce[-=]|csp_nonce|AF_initDataCallback|data-nonce/i.test(body) ? "dynamic-nonce-heavy-page" : "",
    (setCookie.match(/,/g) ?? []).length >= 4 ? "many-response-cookies" : "",
  ].filter(Boolean);

  return {
    highDynamic: signals.length >= 2,
    signals,
  };
}
