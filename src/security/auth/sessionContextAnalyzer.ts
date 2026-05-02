import { maskSecretPreview } from "@/security/findings";

export type SessionArtifact = {
  type:
    | "cookie"
    | "localStorage"
    | "sessionStorage"
    | "authorizationHeader"
    | "jsonToken"
    | "csrfToken"
    | "jwt"
    | "unknownToken";
  name: string;
  location: string;
  valuePreview: string;
  sensitive: boolean;
  httpOnly?: boolean;
  secure?: boolean;
  sameSite?: string;
  expires?: string;
  jwtHeader?: Record<string, unknown>;
  jwtPayloadSummary?: {
    hasExp: boolean;
    hasSub: boolean;
    hasRole: boolean;
    issuer?: string;
    audience?: string;
  };
  riskFlags: string[];
};

export type SessionModel = {
  sessionType: "cookie-based" | "token-based" | "mixed" | "unknown";
  authenticatedContextObtained: boolean;
  storageLocations: string[];
  tokenExposedToJavaScript: "yes" | "no" | "unknown";
  artifacts: SessionArtifact[];
  risks: string[];
  summary: string;
};

function safeJsonParse(value: string): unknown {
  try {
    return JSON.parse(value);
  } catch {
    return null;
  }
}

function decodeJwtPart(part: string): Record<string, unknown> | null {
  try {
    const normalized = part.replace(/-/g, "+").replace(/_/g, "/");
    const padded = `${normalized}${"=".repeat((4 - (normalized.length % 4)) % 4)}`;
    const decoded = Buffer.from(padded, "base64").toString("utf8");
    const parsed = safeJsonParse(decoded);
    return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? parsed as Record<string, unknown> : null;
  } catch {
    return null;
  }
}

function isJwtLike(value: string) {
  return /^[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}$/.test(value);
}

function jwtSummary(value: string) {
  if (!isJwtLike(value)) {
    return {};
  }

  const [headerPart, payloadPart] = value.split(".");
  const header = decodeJwtPart(headerPart);
  const payload = decodeJwtPart(payloadPart);
  if (!payload) {
    return {};
  }

  return {
    jwtHeader: header ?? undefined,
    jwtPayloadSummary: {
      hasExp: typeof payload.exp !== "undefined",
      hasSub: typeof payload.sub !== "undefined",
      hasRole: typeof payload.role !== "undefined" || typeof payload.roles !== "undefined" || typeof payload.authorities !== "undefined",
      issuer: typeof payload.iss === "string" ? payload.iss : undefined,
      audience:
        typeof payload.aud === "string"
          ? payload.aud
          : Array.isArray(payload.aud)
            ? payload.aud.filter((entry): entry is string => typeof entry === "string").slice(0, 3).join(", ")
            : undefined,
    },
  };
}

function cookieFlags(cookie: string) {
  const parts = cookie.split(";").map((part) => part.trim());
  const [nameValue] = parts;
  const [name, ...valueParts] = nameValue.split("=");
  const lowerFlags = parts.slice(1).map((part) => part.toLowerCase());
  const sameSite = parts.slice(1).find((part) => /^samesite=/i.test(part))?.split("=")[1];
  const expires = parts.slice(1).find((part) => /^expires=/i.test(part))?.slice("expires=".length);

  return {
    name: name.trim() || "cookie",
    value: valueParts.join("="),
    httpOnly: lowerFlags.includes("httponly"),
    secure: lowerFlags.includes("secure"),
    sameSite,
    expires,
  };
}

function sensitiveName(name: string) {
  return /session|sid|token|jwt|auth|access|refresh|csrf|xsrf/i.test(name);
}

function addTokenArtifact(artifacts: SessionArtifact[], input: {
  type: SessionArtifact["type"];
  name: string;
  location: string;
  value: string;
  javascriptExposed?: boolean;
}) {
  if (!input.value || input.value.length < 8) {
    return;
  }

  const riskFlags: string[] = [];
  const jwt = jwtSummary(input.value);
  const type = isJwtLike(input.value) ? "jwt" : input.type;
  if (input.javascriptExposed) {
    riskFlags.push("token-readable-by-javascript");
  }
  if (jwt.jwtPayloadSummary && !jwt.jwtPayloadSummary.hasExp) {
    riskFlags.push("jwt-without-exp");
  }

  artifacts.push({
    type,
    name: input.name,
    location: input.location,
    valuePreview: maskSecretPreview(input.value),
    sensitive: true,
    ...jwt,
    riskFlags,
  });
}

function collectJsonTokens(value: unknown, path = "response"): Array<{ name: string; value: string; location: string }> {
  if (!value || typeof value !== "object") {
    return [];
  }

  const tokens: Array<{ name: string; value: string; location: string }> = [];
  for (const [key, entry] of Object.entries(value as Record<string, unknown>)) {
    const nextPath = `${path}.${key}`;
    if (
      typeof entry === "string" &&
      /token|jwt|authorization|auth/i.test(key) &&
      entry.length >= 8
    ) {
      tokens.push({ name: key, value: entry, location: nextPath });
    } else if (entry && typeof entry === "object") {
      tokens.push(...collectJsonTokens(entry, nextPath));
    }
  }
  return tokens.slice(0, 12);
}

export function analyzeSessionContext(input: {
  setCookies?: string[];
  browserCookies?: Array<{ name: string; value: string; httpOnly?: boolean; secure?: boolean; sameSite?: string; expires?: number }>;
  responseJson?: unknown;
  authorizationHeader?: string | null;
  token?: string | null;
  cookieHeader?: string | null;
  localStorage?: Record<string, string>;
  sessionStorage?: Record<string, string>;
  authenticatedContextObtained?: boolean;
  verifiedEndpoint?: string | null;
}): SessionModel {
  const artifacts: SessionArtifact[] = [];
  for (const cookie of input.setCookies ?? []) {
    const parsed = cookieFlags(cookie);
    const sensitive = sensitiveName(parsed.name);
    const riskFlags = [
      sensitive && !parsed.httpOnly ? "missing-httponly" : "",
      sensitive && !parsed.secure ? "missing-secure" : "",
      sensitive && !parsed.sameSite ? "missing-samesite" : "",
    ].filter(Boolean);
    artifacts.push({
      type: sensitiveName(parsed.name) && /csrf|xsrf/i.test(parsed.name) ? "csrfToken" : "cookie",
      name: parsed.name,
      location: "Set-Cookie",
      valuePreview: maskSecretPreview(parsed.value || parsed.name),
      sensitive,
      httpOnly: parsed.httpOnly,
      secure: parsed.secure,
      sameSite: parsed.sameSite,
      expires: parsed.expires,
      riskFlags,
    });
  }

  for (const cookie of input.browserCookies ?? []) {
    const sensitive = sensitiveName(cookie.name);
    artifacts.push({
      type: sensitiveName(cookie.name) && /csrf|xsrf/i.test(cookie.name) ? "csrfToken" : "cookie",
      name: cookie.name,
      location: "browser-cookie",
      valuePreview: maskSecretPreview(cookie.value || cookie.name),
      sensitive,
      httpOnly: cookie.httpOnly,
      secure: cookie.secure,
      sameSite: cookie.sameSite,
      expires: cookie.expires ? new Date(cookie.expires * 1000).toISOString() : undefined,
      riskFlags: [
        sensitive && !cookie.httpOnly ? "missing-httponly" : "",
        sensitive && !cookie.secure ? "missing-secure" : "",
        sensitive && !cookie.sameSite ? "missing-samesite" : "",
      ].filter(Boolean),
    });
  }

  const bearer = input.authorizationHeader?.match(/bearer\s+(.+)/i)?.[1] ?? null;
  if (bearer) {
    addTokenArtifact(artifacts, {
      type: "authorizationHeader",
      name: "Authorization",
      location: "request-header",
      value: bearer,
    });
  }
  if (input.token) {
    addTokenArtifact(artifacts, {
      type: "jsonToken",
      name: "token",
      location: "scanner-auth-context",
      value: input.token,
    });
  }
  collectJsonTokens(input.responseJson).forEach((token) => {
    addTokenArtifact(artifacts, {
      type: "jsonToken",
      name: token.name,
      location: token.location,
      value: token.value,
    });
  });
  Object.entries(input.localStorage ?? {}).forEach(([key, value]) => {
    if (/token|jwt|auth|session/i.test(key) || isJwtLike(value)) {
      addTokenArtifact(artifacts, {
        type: "localStorage",
        name: key,
        location: "localStorage",
        value,
        javascriptExposed: true,
      });
    }
  });
  Object.entries(input.sessionStorage ?? {}).forEach(([key, value]) => {
    if (/token|jwt|auth|session/i.test(key) || isJwtLike(value)) {
      addTokenArtifact(artifacts, {
        type: "sessionStorage",
        name: key,
        location: "sessionStorage",
        value,
        javascriptExposed: true,
      });
    }
  });

  const hasSensitiveCookie = artifacts.some((artifact) => artifact.type === "cookie" && artifact.sensitive);
  const hasToken = artifacts.some((artifact) => artifact.type !== "cookie" && artifact.type !== "csrfToken");
  const sessionType = hasSensitiveCookie && hasToken ? "mixed" : hasToken ? "token-based" : hasSensitiveCookie ? "cookie-based" : "unknown";
  const risks = [...new Set(artifacts.flatMap((artifact) => artifact.riskFlags))];
  const storageLocations = [...new Set(artifacts.map((artifact) => artifact.location))];
  const authenticatedContextObtained = Boolean(input.authenticatedContextObtained || input.verifiedEndpoint || hasSensitiveCookie || hasToken);

  return {
    sessionType,
    authenticatedContextObtained,
    storageLocations,
    tokenExposedToJavaScript: artifacts.some((artifact) =>
      artifact.riskFlags.includes("token-readable-by-javascript"),
    )
      ? "yes"
      : hasToken
        ? "unknown"
        : "no",
    artifacts,
    risks,
    summary:
      sessionType === "token-based"
        ? "No session cookies were required for the confirmed context; the application appears to use token-based authentication."
        : sessionType === "mixed"
          ? "The scanner observed both cookies and token-style authentication artifacts."
          : sessionType === "cookie-based"
            ? "The scanner observed cookie-based session artifacts."
            : "No reusable session artifact was observed in the sampled surface.",
  };
}
