import { createHash } from "node:crypto";
import type { AuthContext } from "@/security/auth/authContextStore";
import { loadAttempt } from "@/server/scans/helpers";

export type OwnedResource = {
  contextLabel: string;
  url: string;
  method: string;
  objectId?: string;
  ownerUserId?: string | number | null;
  ownerEmail?: string | null;
  ownerMarkers: string[];
  status: number;
  contentType: string;
  normalizedHash: string;
  responseShape: string[];
  sensitiveFields: string[];
};

export type IdorOwnershipVerification = {
  victimResource: OwnedResource;
  attackerContext: string;
  victimContext: string;
  status: number | null;
  ownershipConfirmed: boolean;
  likely: boolean;
  leakedFields: string[];
  leakedMarkers: string[];
  responseDiff: string;
};

function normalizeBody(body: string) {
  return body
    .replace(/\b\d{10,}\b/g, "0")
    .replace(/\b[0-9a-f]{16,}\b/gi, "id")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, 80_000);
}

function hashBody(body: string) {
  return createHash("sha256").update(normalizeBody(body)).digest("hex").slice(0, 16);
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

function parseJson(body: string) {
  try {
    return JSON.parse(body) as unknown;
  } catch {
    return null;
  }
}

function sensitiveFieldsFromBody(body: string) {
  const matches = new Set<string>();
  for (const match of body.matchAll(/"(email|userId|uid|id|basketId|orderId|invoiceId|accountId|token|address|phone|payment|card)"\s*:/gi)) {
    matches.add(match[1]);
  }
  return [...matches].slice(0, 12);
}

function extractObjectId(url: string) {
  try {
    const parsed = new URL(url);
    const queryId = [...parsed.searchParams.entries()].find(([key]) => /id|user|basket|order|invoice|account/i.test(key))?.[1];
    if (queryId) {
      return queryId;
    }
    return parsed.pathname.match(/\/(\d+|[0-9a-f-]{8,})(?:\/)?$/i)?.[1];
  } catch {
    return undefined;
  }
}

function contextMarkers(context: AuthContext) {
  return [
    context.userId !== null && context.userId !== undefined ? String(context.userId) : "",
    context.email ?? "",
    context.token ? context.token.slice(0, 12) : "",
  ].filter((entry) => entry.length >= 2);
}

export function buildOwnedResource(input: {
  context: AuthContext;
  url: string;
  method?: string;
  status: number;
  contentType: string;
  bodyText: string;
}): OwnedResource {
  const parsed = parseJson(input.bodyText);
  return {
    contextLabel: input.context.label,
    url: input.url,
    method: input.method ?? "GET",
    objectId: extractObjectId(input.url),
    ownerUserId: input.context.userId ?? null,
    ownerEmail: input.context.email ?? null,
    ownerMarkers: contextMarkers(input.context),
    status: input.status,
    contentType: input.contentType,
    normalizedHash: hashBody(input.bodyText),
    responseShape: parsed ? jsonShape(parsed).slice(0, 40) : [],
    sensitiveFields: sensitiveFieldsFromBody(input.bodyText),
  };
}

export async function verifyIdorOwnership(input: {
  victimContext: AuthContext;
  attackerContext: AuthContext;
  victimUrl: string;
  timeoutMs?: number;
}): Promise<IdorOwnershipVerification | null> {
  const victimHeaders = input.victimContext.headers;
  const attackerHeaders = input.attackerContext.headers;
  const [victimAttempt, attackerAttempt] = await Promise.all([
    loadAttempt(input.victimUrl, {
      timeoutMs: input.timeoutMs ?? 8_000,
      followRedirects: false,
      headers: victimHeaders,
    }),
    loadAttempt(input.victimUrl, {
      timeoutMs: input.timeoutMs ?? 8_000,
      followRedirects: false,
      headers: attackerHeaders,
    }),
  ]);
  if (!victimAttempt) {
    return null;
  }

  const victimResource = buildOwnedResource({
    context: input.victimContext,
    url: victimAttempt.finalUrl,
    status: victimAttempt.status,
    contentType: victimAttempt.headers["content-type"] ?? "",
    bodyText: victimAttempt.bodyText,
  });

  if (!attackerAttempt) {
    return {
      victimResource,
      attackerContext: input.attackerContext.label,
      victimContext: input.victimContext.label,
      status: null,
      ownershipConfirmed: false,
      likely: false,
      leakedFields: [],
      leakedMarkers: [],
      responseDiff: "attacker request failed",
    };
  }

  const attackerBody = attackerAttempt.bodyText;
  const leakedMarkers = victimResource.ownerMarkers.filter((marker) => attackerBody.includes(marker));
  const leakedFields = victimResource.sensitiveFields.filter((field) => new RegExp(`"${field}"\\s*:`, "i").test(attackerBody));
  const success = attackerAttempt.status >= 200 && attackerAttempt.status < 300;
  const sameShape =
    victimResource.responseShape.length > 0 &&
    victimResource.responseShape.filter((field) => attackerBody.includes(field.split(".").at(-1) ?? field)).length >=
      Math.min(3, victimResource.responseShape.length);
  const ownershipConfirmed = success && (leakedMarkers.length > 0 || (leakedFields.length > 0 && victimResource.ownerMarkers.length > 0));

  return {
    victimResource,
    attackerContext: input.attackerContext.label,
    victimContext: input.victimContext.label,
    status: attackerAttempt.status,
    ownershipConfirmed,
    likely: success && (sameShape || leakedFields.length > 0),
    leakedFields,
    leakedMarkers,
    responseDiff: ownershipConfirmed
      ? "attacker received victim ownership markers"
      : success
        ? "attacker received comparable successful response without ownership proof"
        : `attacker received ${attackerAttempt.status}`,
  };
}
