import "server-only";
import { existsSync } from "node:fs";
import { resolve } from "node:path";

const firebaseProjectId =
  process.env.FIREBASE_PROJECT_ID ??
  process.env.NEXT_PUBLIC_FIREBASE_PROJECT_ID ??
  process.env.VITE_FIREBASE_PROJECT_ID ??
  "";
const firebaseServiceAccountPath = process.env.FIREBASE_SERVICE_ACCOUNT_PATH ?? "";
const firebaseClientEmail = process.env.FIREBASE_CLIENT_EMAIL ?? "";
const firebasePrivateKey = process.env.FIREBASE_PRIVATE_KEY?.replace(/\\n/g, "\n") ?? "";
const firebaseServiceAccountResolvedPath = firebaseServiceAccountPath
  ? resolve(/* turbopackIgnore: true */ process.cwd(), firebaseServiceAccountPath)
  : "";

export const serverConfig = {
  appUrl: process.env.NEXT_PUBLIC_APP_URL ?? "http://localhost:3000",
  firebaseProjectId,
  firebaseServiceAccountPath,
  firebaseServiceAccountResolvedPath,
  firebaseClientEmail,
  firebasePrivateKey,
  redisUrl: process.env.REDIS_URL ?? "",
  stripeSecretKey: process.env.STRIPE_SECRET_KEY ?? "",
  stripeWebhookSecret: process.env.STRIPE_WEBHOOK_SECRET ?? "",
  stripePriceIdPremium: process.env.STRIPE_PRICE_ID_PREMIUM ?? "",
  stripeScanPlanPriceUsd: Number(process.env.STRIPE_SCAN_PLAN_PRICE_USD ?? "9"),
  paypalClientId: process.env.PAYPAL_CLIENT_ID ?? process.env.NEXT_PUBLIC_PAYPAL_CLIENT_ID ?? "",
  paypalClientSecret: process.env.PAYPAL_CLIENT_SECRET ?? "",
  paypalEnv: process.env.PAYPAL_ENV === "live" ? "live" : "sandbox",
  googleOAuthClientId: process.env.GOOGLE_OAUTH_CLIENT_ID ?? "",
  googleOAuthClientSecret: process.env.GOOGLE_OAUTH_CLIENT_SECRET ?? "",
  sessionSecret:
    process.env.SESSION_SECRET ??
    process.env.GOOGLE_OAUTH_CLIENT_SECRET ??
    process.env.FIREBASE_PRIVATE_KEY?.replace(/\\n/g, "\n") ??
    "",
  nodeEnv: process.env.NODE_ENV ?? "development",
};

const hasFirebaseServiceAccountFile = Boolean(
  serverConfig.firebaseServiceAccountResolvedPath &&
    existsSync(serverConfig.firebaseServiceAccountResolvedPath),
);

export const hasFirebaseAdminConfig = Boolean(
  serverConfig.firebaseProjectId &&
    (hasFirebaseServiceAccountFile ||
      (serverConfig.firebaseClientEmail && serverConfig.firebasePrivateKey)),
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
  serverConfig.paypalClientId && serverConfig.paypalClientSecret,
);
