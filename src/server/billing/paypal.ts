import { randomUUID } from "node:crypto";
import { badRequest, serviceUnavailable } from "@/server/api/errors";
import { hasPayPalConfig, serverConfig } from "@/server/config";
import { getRepository } from "@/server/repository";
import {
  getScanQuotaSummary,
  SCAN_CREDIT_PACK_PRICE_USD,
  SCAN_CREDIT_PACK_SIZE,
} from "@/server/scans/service";

export const SCAN_CREDIT_PACK_PRODUCT_KEY = "scan-credit-purchase";
const PAYPAL_SANDBOX_TEST_EMAIL = "xsever77@gmail.com";
const SCAN_CREDIT_UNIT_PRICE_USD = SCAN_CREDIT_PACK_PRICE_USD / SCAN_CREDIT_PACK_SIZE;

type PayPalEnvironment = "live" | "sandbox";
type PayPalProfile = {
  clientId: string;
  clientSecret: string;
  env: PayPalEnvironment;
};

type PayPalOrderResponse = {
  id?: string;
  status?: string;
  purchase_units?: Array<{
    custom_id?: string;
    amount?: {
      currency_code?: string;
      value?: string;
    };
    payments?: {
      captures?: Array<{
        id?: string;
        status?: string;
        amount?: {
          currency_code?: string;
          value?: string;
        };
      }>;
    };
  }>;
};

type PayPalErrorResponse = {
  error?: string;
  error_description?: string;
  message?: string;
  name?: string;
  details?: Array<{
    description?: string;
    issue?: string;
  }>;
};

function getPayPalApiBaseUrl(env: PayPalEnvironment) {
  return env === "live" ? "https://api-m.paypal.com" : "https://api-m.sandbox.paypal.com";
}

function assertPayPalConfigured() {
  if (!hasPayPalConfig) {
    throw serviceUnavailable("PayPal checkout is not configured.");
  }
}

function isSandboxTestUser(email: string | null | undefined) {
  return email?.trim().toLowerCase() === PAYPAL_SANDBOX_TEST_EMAIL;
}

function getDefaultPayPalProfile(): PayPalProfile {
  assertPayPalConfigured();

  if (serverConfig.paypalEnv === "live") {
    return getLivePayPalProfile();
  }

  return getSandboxPayPalProfile();
}

function getLivePayPalProfile(): PayPalProfile {
  assertPayPalConfigured();

  if (!serverConfig.paypalLiveClientId || !serverConfig.paypalLiveClientSecret) {
    throw serviceUnavailable("PayPal live checkout is not configured.");
  }

  return {
    clientId: serverConfig.paypalLiveClientId,
    clientSecret: serverConfig.paypalLiveClientSecret,
    env: "live",
  };
}

function getSandboxPayPalProfile(): PayPalProfile {
  assertPayPalConfigured();

  if (!serverConfig.paypalSandboxClientId || !serverConfig.paypalSandboxClientSecret) {
    throw serviceUnavailable("PayPal sandbox checkout is not configured.");
  }

  return {
    clientId: serverConfig.paypalSandboxClientId,
    clientSecret: serverConfig.paypalSandboxClientSecret,
    env: "sandbox",
  };
}

function getPayPalProfile(userEmail: string | null | undefined): PayPalProfile {
  if (isSandboxTestUser(userEmail)) {
    return getSandboxPayPalProfile();
  }

  if (serverConfig.paypalLiveClientId && serverConfig.paypalLiveClientSecret) {
    return getLivePayPalProfile();
  }

  return getDefaultPayPalProfile();
}

export function getPayPalCheckoutConfig(userEmail: string | null | undefined) {
  const profile = getPayPalProfile(userEmail);
  return {
    clientId: profile.clientId,
    mode: profile.env,
  };
}

function normalizeCreditsPurchase(credits: number) {
  if (!Number.isFinite(credits) || !Number.isInteger(credits)) {
    throw badRequest("Credits must be a whole number.", "PAYPAL_CREDITS_INVALID");
  }

  if (credits < SCAN_CREDIT_PACK_SIZE) {
    throw badRequest(
      `Credits must start at ${SCAN_CREDIT_PACK_SIZE}.`,
      "PAYPAL_CREDITS_BELOW_MINIMUM",
    );
  }

  if (credits > 10_000) {
    throw badRequest("Credits request is too large.", "PAYPAL_CREDITS_TOO_LARGE");
  }

  return credits;
}

function calculateCreditsAmountUsd(credits: number) {
  return Number((credits * SCAN_CREDIT_UNIT_PRICE_USD).toFixed(2));
}

function inferCreditsFromAmount(value: string | undefined) {
  const amountUsd = Number(value);
  if (!Number.isFinite(amountUsd)) {
    return null;
  }

  const credits = amountUsd / SCAN_CREDIT_UNIT_PRICE_USD;
  if (!Number.isInteger(credits) || credits < SCAN_CREDIT_PACK_SIZE) {
    return null;
  }

  return credits;
}

function resolvePayPalErrorMessage(payload: PayPalErrorResponse | null) {
  const detail = payload?.details?.[0];
  return (
    payload?.message ??
    payload?.error_description ??
    detail?.description ??
    detail?.issue ??
    payload?.error ??
    payload?.name ??
    "PayPal request failed."
  );
}

async function paypalFetch<T>(profile: PayPalProfile, path: string, init: RequestInit = {}) {
  const response = await fetch(`${getPayPalApiBaseUrl(profile.env)}${path}`, {
    cache: "no-store",
    ...init,
    headers: {
      Accept: "application/json",
      ...(init.headers ?? {}),
    },
  });

  const payload = (await response.json().catch(() => null)) as T | PayPalErrorResponse | null;
  if (!response.ok) {
    throw badRequest(
      resolvePayPalErrorMessage(payload as PayPalErrorResponse | null),
      "PAYPAL_REQUEST_FAILED",
      payload,
    );
  }

  return payload as T;
}

async function getPayPalAccessToken(profile: PayPalProfile) {
  const credentials = Buffer.from(`${profile.clientId}:${profile.clientSecret}`).toString("base64");

  const payload = await paypalFetch<{ access_token?: string }>(profile, "/v1/oauth2/token", {
    method: "POST",
    headers: {
      Authorization: `Basic ${credentials}`,
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: "grant_type=client_credentials",
  });

  if (!payload.access_token) {
    throw serviceUnavailable("PayPal did not return an access token.");
  }

  return payload.access_token;
}

export async function createPayPalScanCreditOrder(
  userId: string,
  credits: number,
  userEmail: string | null | undefined,
) {
  const requestedCredits = normalizeCreditsPurchase(credits);
  const profile = getPayPalProfile(userEmail);
  const accessToken = await getPayPalAccessToken(profile);
  const amountUsd = calculateCreditsAmountUsd(requestedCredits);
  const price = amountUsd.toFixed(2);

  const order = await paypalFetch<PayPalOrderResponse>(profile, "/v2/checkout/orders", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${accessToken}`,
      "Content-Type": "application/json",
      "PayPal-Request-Id": randomUUID(),
    },
    body: JSON.stringify({
      intent: "CAPTURE",
      purchase_units: [
        {
          custom_id: userId,
          description: `${requestedCredits} CyberAudit scan credits`,
          amount: {
            currency_code: "USD",
            value: price,
            breakdown: {
              item_total: {
                currency_code: "USD",
                value: price,
              },
            },
          },
          items: [
            {
              name: "CyberAudit scan credit",
              quantity: String(requestedCredits),
              unit_amount: {
                currency_code: "USD",
                value: SCAN_CREDIT_UNIT_PRICE_USD.toFixed(2),
              },
            },
          ],
        },
      ],
    }),
  });

  if (!order.id) {
    throw serviceUnavailable("PayPal did not return an order id.");
  }

  await getRepository().upsertPayment({
    id: randomUUID(),
    userId,
    scanId: `credits:${userId}`,
    stripeCustomerId: null,
    checkoutSessionId: order.id,
    paymentStatus: "pending",
    productKey: SCAN_CREDIT_PACK_PRODUCT_KEY,
    paymentProvider: "paypal",
    paypalOrderId: order.id,
    creditsPurchased: requestedCredits,
    amountUsd,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  });

  return order.id;
}

export async function capturePayPalScanCreditOrder(
  orderId: string,
  userId: string,
  userEmail: string | null | undefined,
) {
  const repository = getRepository();
  const existingPayment = await repository.getPaymentByCheckoutSessionId(orderId);

  if (existingPayment && existingPayment.userId !== userId) {
    throw badRequest("This PayPal order belongs to another account.", "PAYPAL_ACCOUNT_MISMATCH");
  }

  if (existingPayment?.paymentStatus === "paid") {
    return getScanQuotaSummary(userId);
  }

  const profile = getPayPalProfile(userEmail);
  const accessToken = await getPayPalAccessToken(profile);
  const order = await paypalFetch<PayPalOrderResponse>(
    profile,
    `/v2/checkout/orders/${encodeURIComponent(orderId)}/capture`,
    {
      method: "POST",
      headers: {
        Authorization: `Bearer ${accessToken}`,
        "Content-Type": "application/json",
        "PayPal-Request-Id": randomUUID(),
      },
    },
  );

  const purchaseUnit = order.purchase_units?.[0];
  const capture = purchaseUnit?.payments?.captures?.[0];
  const amount = capture?.amount ?? purchaseUnit?.amount;
  const expectedCredits = existingPayment?.creditsPurchased ?? inferCreditsFromAmount(amount?.value);
  const expectedAmountUsd = existingPayment?.amountUsd ?? calculateCreditsAmountUsd(expectedCredits ?? 0);
  const capturedAmountUsd = Number(amount?.value);

  if (order.status !== "COMPLETED" || capture?.status !== "COMPLETED") {
    throw badRequest("PayPal payment was not completed.", "PAYPAL_PAYMENT_INCOMPLETE", order);
  }

  if (purchaseUnit?.custom_id && purchaseUnit.custom_id !== userId) {
    throw badRequest("This PayPal order belongs to another account.", "PAYPAL_ACCOUNT_MISMATCH");
  }

  if (!expectedCredits) {
    throw badRequest("PayPal payment credits are invalid.", "PAYPAL_CREDITS_INVALID", order);
  }

  if (
    amount?.currency_code !== "USD" ||
    !Number.isFinite(capturedAmountUsd) ||
    Math.abs(capturedAmountUsd - expectedAmountUsd) > 0.001
  ) {
    throw badRequest("PayPal payment amount is invalid.", "PAYPAL_AMOUNT_MISMATCH", order);
  }

  const now = new Date().toISOString();
  await repository.upsertPayment({
    ...(existingPayment ?? {
      id: randomUUID(),
      createdAt: now,
    }),
    userId,
    scanId: `credits:${userId}`,
    stripeCustomerId: null,
    checkoutSessionId: orderId,
    paymentStatus: "paid",
    productKey: SCAN_CREDIT_PACK_PRODUCT_KEY,
    paymentProvider: "paypal",
    paypalOrderId: orderId,
    creditsPurchased: expectedCredits,
    amountUsd: expectedAmountUsd,
    updatedAt: now,
  });

  await repository.addUserScanCredits(userId, expectedCredits);
  return getScanQuotaSummary(userId);
}
