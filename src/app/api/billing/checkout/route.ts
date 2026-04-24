import { randomUUID } from "node:crypto";
import { NextRequest, NextResponse } from "next/server";
import { handleRouteError } from "@/server/api/errors";
import { requireSessionUser } from "@/server/auth/session";
import {
  buildScanPlanLineItems,
  ensureStripeCustomerForUser,
  REPORT_UPGRADE_PRODUCT_KEY,
  SCAN_PLAN_PRODUCT_KEY,
} from "@/server/billing/service";
import { getStripeClient } from "@/server/billing/stripe";
import { assertRateLimit } from "@/server/rate-limit";
import { serverConfig } from "@/server/config";
import { getRepository } from "@/server/repository";
import { checkoutSchema } from "@/server/scans/schemas";
import { getScanQuotaSummary, requireOwnedScan } from "@/server/scans/service";

export const runtime = "nodejs";

export async function POST(request: NextRequest) {
  try {
    const user = await requireSessionUser(request);
    assertRateLimit("checkout", user.uid);
    const parsed = checkoutSchema.parse(await request.json());
    const repository = getRepository();
    const stripe = getStripeClient();
    const returnPath = parsed.returnPath?.startsWith("/") ? parsed.returnPath : "/history";
    const quota = await getScanQuotaSummary(user.uid);

    if (parsed.purpose === "scan-plan" && quota.hasUnlimitedPlan) {
      return NextResponse.json({
        alreadyActive: true,
      });
    }

    const { stripeCustomerId } = await ensureStripeCustomerForUser({
      uid: user.uid,
      email: user.email,
      displayName: user.displayName,
      stripe,
    });

    const scan =
      parsed.purpose === "report-upgrade" && parsed.scanId
        ? await requireOwnedScan(parsed.scanId, user.uid)
        : null;

    const successUrl = new URL(returnPath, serverConfig.appUrl);
    successUrl.searchParams.set("checkout", "success");
    successUrl.searchParams.set("session_id", "{CHECKOUT_SESSION_ID}");

    const cancelUrl = new URL(returnPath, serverConfig.appUrl);
    cancelUrl.searchParams.set("checkout", "cancelled");

    const session = await stripe.checkout.sessions.create({
      mode: "payment",
      customer: stripeCustomerId ?? undefined,
      line_items:
        parsed.purpose === "report-upgrade"
          ? buildScanPlanLineItems()
          : buildScanPlanLineItems(),
      success_url: successUrl.toString(),
      cancel_url: cancelUrl.toString(),
      metadata: {
        userId: user.uid,
        ...(scan ? { scanId: scan.id } : {}),
        productKey:
          parsed.purpose === "report-upgrade"
            ? REPORT_UPGRADE_PRODUCT_KEY
            : SCAN_PLAN_PRODUCT_KEY,
      },
    });

    await repository.upsertPayment({
      id: randomUUID(),
      userId: user.uid,
      scanId: scan?.id ?? `plan:${user.uid}`,
      stripeCustomerId,
      checkoutSessionId: session.id,
      paymentStatus: "pending",
      productKey:
        parsed.purpose === "report-upgrade"
          ? REPORT_UPGRADE_PRODUCT_KEY
          : SCAN_PLAN_PRODUCT_KEY,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    });

    return NextResponse.json({
      url: session.url,
    });
  } catch (error) {
    return handleRouteError(error);
  }
}
