import "server-only";
import { existsSync } from "node:fs";
import { resolve } from "node:path";

function firstNonEmpty(...values: Array<string | null | undefined>) {
  return values.find((value) => value?.trim())?.trim() ?? "";
}

function unwrapEnvValue(value: string) {
  const trimmed = value.trim();
  const first = trimmed.at(0);
  const last = trimmed.at(-1);

  if ((first === '"' && last === '"') || (first === "'" && last === "'")) {
    return trimmed.slice(1, -1);
  }

  return trimmed;
}

function normalizePrivateKey(value: string) {
  return unwrapEnvValue(value).replace(/\\n/g, "\n");
}

const firebaseServiceAccountJson = firstNonEmpty(process.env.FIREBASE_SERVICE_ACCOUNT_JSON);

function parseFirebaseServiceAccountJson(value: string) {
  if (!value) {
    return null;
  }

  const unwrappedValue = unwrapEnvValue(value);
  const candidates = [unwrappedValue, Buffer.from(unwrappedValue, "base64").toString("utf8")];
  for (const candidate of candidates) {
    try {
      return JSON.parse(candidate) as {
        project_id?: string;
        client_email?: string;
        private_key?: string;
      };
    } catch {
      // Try the next supported representation.
    }
  }

  return null;
}

const firebaseServiceAccount = parseFirebaseServiceAccountJson(firebaseServiceAccountJson);
const firebaseProjectId = firstNonEmpty(
  process.env.FIREBASE_PROJECT_ID,
  process.env.NEXT_PUBLIC_FIREBASE_PROJECT_ID,
  process.env.VITE_FIREBASE_PROJECT_ID,
  firebaseServiceAccount?.project_id,
);
const firebaseServiceAccountPath = firstNonEmpty(process.env.FIREBASE_SERVICE_ACCOUNT_PATH);
const googleApplicationCredentialsPath = firstNonEmpty(process.env.GOOGLE_APPLICATION_CREDENTIALS);
const googleApplicationCredentialsResolvedPath = googleApplicationCredentialsPath
  ? resolve(/* turbopackIgnore: true */ process.cwd(), googleApplicationCredentialsPath)
  : "";
const firebaseClientEmail = firstNonEmpty(
  process.env.FIREBASE_CLIENT_EMAIL,
  firebaseServiceAccount?.client_email,
);
const firebasePrivateKey = normalizePrivateKey(
  firstNonEmpty(process.env.FIREBASE_PRIVATE_KEY, firebaseServiceAccount?.private_key),
);
const firebaseServiceAccountResolvedPath = firebaseServiceAccountPath
  ? resolve(/* turbopackIgnore: true */ process.cwd(), firebaseServiceAccountPath)
  : "";
const paypalEnv = process.env.PAYPAL_ENV === "live" ? "live" : "sandbox";
const paypalLegacyClientId =
  process.env.PAYPAL_CLIENT_ID ?? process.env.NEXT_PUBLIC_PAYPAL_CLIENT_ID ?? "";
const paypalLegacyClientSecret = process.env.PAYPAL_CLIENT_SECRET ?? "";
const paypalLiveClientId = process.env.PAYPAL_LIVE_CLIENT_ID ?? paypalLegacyClientId;
const paypalLiveClientSecret =
  process.env.PAYPAL_LIVE_CLIENT_SECRET ?? paypalLegacyClientSecret;
const paypalSandboxClientId =
  process.env.PAYPAL_SANDBOX_CLIENT_ID ?? (paypalEnv === "sandbox" ? paypalLegacyClientId : "");
const paypalSandboxClientSecret =
  process.env.PAYPAL_SANDBOX_CLIENT_SECRET ??
  (paypalEnv === "sandbox" ? paypalLegacyClientSecret : "");

export const serverConfig = {
  appUrl: process.env.NEXT_PUBLIC_APP_URL ?? "http://localhost:3000",
  firebaseProjectId,
  firebaseServiceAccountJson,
  firebaseServiceAccountPath,
  firebaseServiceAccountResolvedPath,
  googleApplicationCredentialsPath,
  googleApplicationCredentialsResolvedPath,
  firebaseClientEmail,
  firebasePrivateKey,
  redisUrl: process.env.REDIS_URL ?? "",
  stripeSecretKey: process.env.STRIPE_SECRET_KEY ?? "",
  stripeWebhookSecret: process.env.STRIPE_WEBHOOK_SECRET ?? "",
  stripePriceIdPremium: process.env.STRIPE_PRICE_ID_PREMIUM ?? "",
  stripeScanPlanPriceUsd: Number(process.env.STRIPE_SCAN_PLAN_PRICE_USD ?? "9"),
  paypalClientId: paypalLegacyClientId,
  paypalClientSecret: paypalLegacyClientSecret,
  paypalEnv,
  paypalLiveClientId,
  paypalLiveClientSecret,
  paypalSandboxClientId,
  paypalSandboxClientSecret,
  googleOAuthClientId: process.env.GOOGLE_OAUTH_CLIENT_ID ?? "",
  googleOAuthClientSecret: process.env.GOOGLE_OAUTH_CLIENT_SECRET ?? "",
  sessionSecret: firstNonEmpty(
    process.env.SESSION_SECRET,
    process.env.GOOGLE_OAUTH_CLIENT_SECRET,
    firebasePrivateKey,
  ),
  nodeEnv: process.env.NODE_ENV ?? "development",
};

const hasFirebaseCredentialPair = Boolean(
  serverConfig.firebaseClientEmail && serverConfig.firebasePrivateKey,
);
const hasFirebaseServiceAccountFile = Boolean(
  serverConfig.firebaseServiceAccountResolvedPath &&
    existsSync(serverConfig.firebaseServiceAccountResolvedPath),
);
const hasGoogleApplicationCredentialsFile = Boolean(
  serverConfig.googleApplicationCredentialsResolvedPath &&
    existsSync(serverConfig.googleApplicationCredentialsResolvedPath),
);

export const hasFirebaseApplicationDefaultConfig = Boolean(
  serverConfig.firebaseProjectId &&
    (hasGoogleApplicationCredentialsFile || process.env.FIREBASE_USE_APPLICATION_DEFAULT === "true"),
);

export const hasFirebaseAdminConfig = Boolean(
  serverConfig.firebaseProjectId &&
    (hasFirebaseServiceAccountFile ||
      hasFirebaseCredentialPair ||
      hasFirebaseApplicationDefaultConfig),
);

export const hasRedisConfig = Boolean(serverConfig.redisUrl);
export const hasSessionAuthConfig = Boolean(
  serverConfig.firebaseProjectId && serverConfig.sessionSecret,
);

export const hasStripeConfig = Boolean(serverConfig.stripeSecretKey);
export const hasStripeWebhookConfig = Boolean(
  serverConfig.stripeSecretKey && serverConfig.stripeWebhookSecret,
);
export const hasPayPalConfig = Boolean(
  (serverConfig.paypalLiveClientId && serverConfig.paypalLiveClientSecret) ||
    (serverConfig.paypalSandboxClientId && serverConfig.paypalSandboxClientSecret),
);
