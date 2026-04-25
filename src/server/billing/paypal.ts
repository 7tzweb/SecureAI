import { randomUUID } from "node:crypto";
import { badRequest, serviceUnavailable } from "@/server/api/errors";
import { hasPayPalConfig, serverConfig } from "@/server/config";
import { getRepository } from "@/server/repository";
import {
  getScanQuotaSummary,
  SCAN_CREDIT_PACK_PRICE_USD,
  SCAN_CREDIT_PACK_SIZE,
} from "@/server/scans/service";

export const SCAN_CREDIT_PACK_PRODUCT_KEY = "scan-credit-pack-30";

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

function getPayPalApiBaseUrl() {
  return serverConfig.paypalEnv === "live"
    ? "https://api-m.paypal.com"
    : "https://api-m.sandbox.paypal.com";
}

function assertPayPalConfigured() {
  if (!hasPayPalConfig) {
    throw serviceUnavailable("PayPal checkout is not configured.");
  }
}

async function paypalFetch<T>(path: string, init: RequestInit = {}) {
  assertPayPalConfigured();

  const response = await fetch(`${getPayPalApiBaseUrl()}${path}`, {
    cache: "no-store",
    ...init,
    headers: {
      Accept: "application/json",
      ...(init.headers ?? {}),
    },
  });

  const payload = (await response.json().catch(() => null)) as T | { message?: string } | null;
  if (!response.ok) {
    throw badRequest(
      payload && typeof payload === "object" && "message" in payload && payload.message
        ? payload.message
        : "PayPal request failed.",
      "PAYPAL_REQUEST_FAILED",
      payload,
    );
  }

  return payload as T;
}

async function getPayPalAccessToken() {
  assertPayPalConfigured();

  const credentials = Buffer.from(
    `${serverConfig.paypalClientId}:${serverConfig.paypalClientSecret}`,
  ).toString("base64");

  const payload = await paypalFetch<{ access_token?: string }>("/v1/oauth2/token", {
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

export async function createPayPalScanCreditOrder(userId: string) {
  const accessToken = await getPayPalAccessToken();
  const price = SCAN_CREDIT_PACK_PRICE_USD.toFixed(2);

  const order = await paypalFetch<PayPalOrderResponse>("/v2/checkout/orders", {
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
          description: `${SCAN_CREDIT_PACK_SIZE} CyberAudit scan credits`,
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
              name: `${SCAN_CREDIT_PACK_SIZE} CyberAudit scans`,
              quantity: "1",
              unit_amount: {
                currency_code: "USD",
                value: price,
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
    creditsPurchased: SCAN_CREDIT_PACK_SIZE,
    amountUsd: SCAN_CREDIT_PACK_PRICE_USD,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  });

  return order.id;
}

export async function capturePayPalScanCreditOrder(orderId: string, userId: string) {
  const repository = getRepository();
  const existingPayment = await repository.getPaymentByCheckoutSessionId(orderId);

  if (existingPayment && existingPayment.userId !== userId) {
    throw badRequest("This PayPal order belongs to another account.", "PAYPAL_ACCOUNT_MISMATCH");
  }

  if (existingPayment?.paymentStatus === "paid") {
    return getScanQuotaSummary(userId);
  }

  const accessToken = await getPayPalAccessToken();
  const order = await paypalFetch<PayPalOrderResponse>(
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

  if (order.status !== "COMPLETED" || capture?.status !== "COMPLETED") {
    throw badRequest("PayPal payment was not completed.", "PAYPAL_PAYMENT_INCOMPLETE", order);
  }

  if (purchaseUnit?.custom_id && purchaseUnit.custom_id !== userId) {
    throw badRequest("This PayPal order belongs to another account.", "PAYPAL_ACCOUNT_MISMATCH");
  }

  if (
    amount?.currency_code !== "USD" ||
    Number(amount.value) < SCAN_CREDIT_PACK_PRICE_USD
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
    creditsPurchased: SCAN_CREDIT_PACK_SIZE,
    amountUsd: SCAN_CREDIT_PACK_PRICE_USD,
    updatedAt: now,
  });

  await repository.addUserScanCredits(userId, SCAN_CREDIT_PACK_SIZE);
  return getScanQuotaSummary(userId);
}
