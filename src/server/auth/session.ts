import "server-only";

import { createHmac, createPublicKey, createVerify, timingSafeEqual } from "node:crypto";
import type { NextRequest } from "next/server";
import { type SessionUser, type UserRecord } from "@/lib/types";
import { unauthorized, serviceUnavailable } from "@/server/api/errors";
import { hasFirebaseAdminConfig, hasSessionAuthConfig, serverConfig } from "@/server/config";
import { getFirebaseAdminAuth } from "@/server/firebase-admin";
import { getRepository } from "@/server/repository";

export const SESSION_COOKIE_NAME = "cyberaudit_session";
const SESSION_MAX_AGE_MS = 1000 * 60 * 60 * 24 * 5;
const FIREBASE_CERTS_URL =
  "https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com";

type SessionCookiePayload = {
  uid: string;
  email: string | null;
  displayName: string | null;
  photoURL: string | null;
  exp: number;
};

type FirebaseIdTokenPayload = {
  aud?: string;
  email?: string;
  exp?: number;
  iat?: number;
  iss?: string;
  name?: string;
  picture?: string;
  sub?: string;
  uid?: string;
};

const globalState = globalThis as typeof globalThis & {
  __cyberAuditFirebaseCertsCache?: {
    certs: Record<string, string>;
    expiresAt: number;
  };
};

function toUserRecord(sessionUser: SessionUser): UserRecord {
  const timestamp = new Date().toISOString();
  return {
    uid: sessionUser.uid,
    email: sessionUser.email,
    displayName: sessionUser.displayName,
    photoURL: sessionUser.photoURL,
    createdAt: timestamp,
    lastLoginAt: timestamp,
    roles: [],
    subscriptionStatus: sessionUser.subscriptionStatus,
    stripeCustomerId: null,
    entitlementLevel: sessionUser.entitlementLevel,
    purchasedScanCredits: 0,
  };
}

function base64UrlEncode(value: string | Buffer) {
  return Buffer.from(value)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function base64UrlDecode(value: string) {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized.padEnd(normalized.length + ((4 - (normalized.length % 4)) % 4), "=");
  return Buffer.from(padded, "base64");
}

function signSessionPayload(encodedPayload: string) {
  return createHmac("sha256", serverConfig.sessionSecret).update(encodedPayload).digest();
}

function encodeSessionCookie(payload: SessionCookiePayload) {
  const encodedPayload = base64UrlEncode(JSON.stringify(payload));
  const signature = signSessionPayload(encodedPayload);
  return `${encodedPayload}.${base64UrlEncode(signature)}`;
}

function decodeSessionCookie(cookieValue: string) {
  const [encodedPayload, encodedSignature] = cookieValue.split(".");
  if (!encodedPayload || !encodedSignature) {
    return null;
  }

  const expectedSignature = signSessionPayload(encodedPayload);
  const providedSignature = base64UrlDecode(encodedSignature);
  if (
    expectedSignature.length !== providedSignature.length ||
    !timingSafeEqual(expectedSignature, providedSignature)
  ) {
    return null;
  }

  try {
    const payload = JSON.parse(
      base64UrlDecode(encodedPayload).toString("utf8"),
    ) as SessionCookiePayload;
    if (!payload.uid || payload.exp <= Math.floor(Date.now() / 1000)) {
      return null;
    }
    return payload;
  } catch {
    return null;
  }
}

async function fetchFirebasePublicKeys() {
  const cached = globalState.__cyberAuditFirebaseCertsCache;
  if (cached && cached.expiresAt > Date.now()) {
    return cached.certs;
  }

  const response = await fetch(FIREBASE_CERTS_URL, {
    headers: {
      "user-agent": "CyberAudit/1.0 (+https://example.invalid/cyberaudit)",
    },
    cache: "no-store",
  });

  if (!response.ok) {
    throw serviceUnavailable("Unable to fetch Firebase public keys.");
  }

  const certs = (await response.json()) as Record<string, string>;
  const cacheControl = response.headers.get("cache-control") ?? "";
  const maxAgeMatch = cacheControl.match(/max-age=(\d+)/i);
  const maxAgeMs = maxAgeMatch ? Number(maxAgeMatch[1]) * 1000 : 60 * 60 * 1000;

  globalState.__cyberAuditFirebaseCertsCache = {
    certs,
    expiresAt: Date.now() + maxAgeMs,
  };

  return certs;
}

function parseJwtSection<T>(value: string) {
  return JSON.parse(base64UrlDecode(value).toString("utf8")) as T;
}

async function verifyFirebaseIdTokenWithoutAdmin(idToken: string) {
  if (!serverConfig.firebaseProjectId) {
    throw serviceUnavailable("Firebase project configuration is missing.");
  }

  const [encodedHeader, encodedPayload, encodedSignature] = idToken.split(".");
  if (!encodedHeader || !encodedPayload || !encodedSignature) {
    throw unauthorized("Invalid Firebase ID token.");
  }

  const header = parseJwtSection<{ alg?: string; kid?: string }>(encodedHeader);
  const payload = parseJwtSection<FirebaseIdTokenPayload>(encodedPayload);

  if (header.alg !== "RS256" || !header.kid) {
    throw unauthorized("Firebase ID token header is invalid.");
  }

  const certs = await fetchFirebasePublicKeys();
  const publicCert = certs[header.kid];
  if (!publicCert) {
    throw unauthorized("Firebase signing key was not found.");
  }

  const verifier = createVerify("RSA-SHA256");
  verifier.update(`${encodedHeader}.${encodedPayload}`);
  verifier.end();
  const signatureValid = verifier.verify(
    createPublicKey(publicCert),
    base64UrlDecode(encodedSignature),
  );

  if (!signatureValid) {
    throw unauthorized("Firebase ID token signature is invalid.");
  }

  const nowSeconds = Math.floor(Date.now() / 1000);
  if (
    payload.aud !== serverConfig.firebaseProjectId ||
    payload.iss !== `https://securetoken.google.com/${serverConfig.firebaseProjectId}` ||
    !payload.sub ||
    payload.sub.length === 0 ||
    typeof payload.exp !== "number" ||
    typeof payload.iat !== "number" ||
    payload.exp <= nowSeconds ||
    payload.iat > nowSeconds
  ) {
    throw unauthorized("Firebase ID token payload is invalid.");
  }

  return {
    uid: payload.uid ?? payload.sub,
    email: payload.email ?? null,
    displayName: payload.name ?? null,
    photoURL: payload.picture ?? null,
  };
}

export function buildSessionCookie(value: string) {
  return {
    name: SESSION_COOKIE_NAME,
    value,
    httpOnly: true,
    sameSite: "lax" as const,
    secure: serverConfig.nodeEnv === "production",
    path: "/",
    maxAge: SESSION_MAX_AGE_MS / 1000,
  };
}

export function buildExpiredSessionCookie() {
  return {
    ...buildSessionCookie(""),
    maxAge: 0,
  };
}

export async function createServerSessionFromIdToken(idToken: string) {
  if (!hasSessionAuthConfig) {
    throw serviceUnavailable("Google session configuration is missing.");
  }

  const decoded = hasFirebaseAdminConfig
    ? await getFirebaseAdminAuth().verifyIdToken(idToken)
    : await verifyFirebaseIdTokenWithoutAdmin(idToken);

  const repository = getRepository();
  const existingUser = await repository.getUser(decoded.uid);

  const sessionUser: SessionUser = {
    uid: decoded.uid,
    email: decoded.email ?? null,
    displayName:
      "name" in decoded && typeof decoded.name === "string"
        ? decoded.name
        : "displayName" in decoded && typeof decoded.displayName === "string"
          ? decoded.displayName
          : existingUser?.displayName ?? null,
    photoURL:
      "picture" in decoded && typeof decoded.picture === "string"
        ? decoded.picture
        : "photoURL" in decoded && typeof decoded.photoURL === "string"
          ? decoded.photoURL
          : existingUser?.photoURL ?? null,
    subscriptionStatus: existingUser?.subscriptionStatus ?? "free",
    entitlementLevel: existingUser?.entitlementLevel ?? "free",
  };

  await repository.upsertUser({
    ...(existingUser ?? toUserRecord(sessionUser)),
    ...sessionUser,
    createdAt: existingUser?.createdAt ?? new Date().toISOString(),
    lastLoginAt: new Date().toISOString(),
  });

  const sessionCookie = encodeSessionCookie({
    uid: sessionUser.uid,
    email: sessionUser.email,
    displayName: sessionUser.displayName,
    photoURL: sessionUser.photoURL,
    exp: Math.floor((Date.now() + SESSION_MAX_AGE_MS) / 1000),
  });

  return { sessionCookie, sessionUser };
}

export async function getOptionalSessionUser(request: NextRequest): Promise<SessionUser | null> {
  if (!hasSessionAuthConfig) {
    return null;
  }

  const cookieValue = request.cookies.get(SESSION_COOKIE_NAME)?.value;
  if (!cookieValue) {
    return null;
  }

  const payload = decodeSessionCookie(cookieValue);
  if (!payload) {
    return null;
  }

  const repository = getRepository();
  const existingUser = await repository.getUser(payload.uid);

  return {
    uid: payload.uid,
    email: payload.email,
    displayName: payload.displayName,
    photoURL: payload.photoURL,
    subscriptionStatus: existingUser?.subscriptionStatus ?? "free",
    entitlementLevel: existingUser?.entitlementLevel ?? "free",
  };
}

export async function requireSessionUser(request: NextRequest) {
  if (!hasSessionAuthConfig) {
    throw serviceUnavailable("Google session configuration is missing.");
  }

  const user = await getOptionalSessionUser(request);
  if (!user) {
    throw unauthorized("Sign in with Google to continue.");
  }

  return user;
}
