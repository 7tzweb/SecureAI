import { randomUUID } from "node:crypto";
import Stripe from "stripe";
import { badRequest, forbidden, serviceUnavailable } from "@/server/api/errors";
import { serverConfig } from "@/server/config";
import { getRepository } from "@/server/repository";
import { unlockPremiumForScan } from "@/server/scans/service";

export const SCAN_PLAN_PRODUCT_KEY = "scan-plan-unlimited";
export const REPORT_UPGRADE_PRODUCT_KEY = "premium-report";

export async function ensureStripeCustomerForUser(input: {
  uid: string;
  email: string | null;
  displayName: string | null;
  stripe: Stripe;
}) {
  const repository = getRepository();
  const userRecord = await repository.getUser(input.uid);

  let stripeCustomerId = userRecord?.stripeCustomerId ?? null;
  if (!stripeCustomerId) {
    const customer = await input.stripe.customers.create({
      email: input.email ?? undefined,
      name: input.displayName ?? undefined,
      metadata: {
        userId: input.uid,
      },
    });
    stripeCustomerId = customer.id;
    if (userRecord) {
      await repository.updateUserEntitlement(
        input.uid,
        userRecord.subscriptionStatus,
        userRecord.entitlementLevel,
        stripeCustomerId,
      );
    }
  }

  return { stripeCustomerId, userRecord };
}

export function buildScanPlanLineItems(): Stripe.Checkout.SessionCreateParams.LineItem[] {
  if (serverConfig.stripePriceIdPremium) {
    return [
      {
        price: serverConfig.stripePriceIdPremium,
        quantity: 1,
      },
    ];
  }

  const unitAmount = Math.round(serverConfig.stripeScanPlanPriceUsd * 100);
  if (!unitAmount) {
    throw serviceUnavailable("Stripe plan pricing is not configured.");
  }

  return [
    {
      price_data: {
        currency: "usd",
        unit_amount: unitAmount,
        product_data: {
          name: "fixnx Unlimited Scans",
          description: "Unlock unlimited scans for your signed-in Google account.",
        },
      },
      quantity: 1,
    },
  ];
}

export async function finalizeCheckoutSession(session: Stripe.Checkout.Session) {
  const userId = session.metadata?.userId;
  const productKey = session.metadata?.productKey;
  if (!userId || !productKey) {
    throw badRequest("Checkout session metadata is incomplete.");
  }

  if (session.payment_status !== "paid") {
    throw badRequest("Checkout session is not paid.");
  }

  const repository = getRepository();
  const payment = await repository.getPaymentByCheckoutSessionId(session.id);
  if (payment) {
    await repository.upsertPayment({
      ...payment,
      paymentStatus: "paid",
      stripeCustomerId:
        typeof session.customer === "string" ? session.customer : payment.stripeCustomerId,
      updatedAt: new Date().toISOString(),
    });
  } else {
    await repository.upsertPayment({
      id: randomUUID(),
      userId,
      scanId: session.metadata?.scanId ?? `plan:${userId}`,
      stripeCustomerId: typeof session.customer === "string" ? session.customer : null,
      checkoutSessionId: session.id,
      paymentStatus: "paid",
      productKey,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    });
  }

  const user = await repository.getUser(userId);
  if (user) {
    await repository.updateUserEntitlement(
      userId,
      "premium",
      "premium",
      typeof session.customer === "string" ? session.customer : user.stripeCustomerId,
    );
  }

  if (productKey === REPORT_UPGRADE_PRODUCT_KEY) {
    const scanId = session.metadata?.scanId;
    if (!scanId) {
      throw badRequest("Scan upgrade is missing scanId metadata.");
    }

    await unlockPremiumForScan(scanId, userId);
  }
}

export function assertCheckoutBelongsToUser(session: Stripe.Checkout.Session, userId: string) {
  if (session.metadata?.userId !== userId) {
    throw forbidden("This checkout session belongs to another account.");
  }
}
