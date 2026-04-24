import { NextRequest, NextResponse } from "next/server";
import { handleRouteError } from "@/server/api/errors";
import { requireSessionUser } from "@/server/auth/session";
import {
  assertCheckoutBelongsToUser,
  finalizeCheckoutSession,
} from "@/server/billing/service";
import { getStripeClient } from "@/server/billing/stripe";
import { assertRateLimit } from "@/server/rate-limit";
import { checkoutConfirmSchema } from "@/server/scans/schemas";

export const runtime = "nodejs";

export async function POST(request: NextRequest) {
  try {
    const user = await requireSessionUser(request);
    assertRateLimit("checkout", user.uid);
    const parsed = checkoutConfirmSchema.parse(await request.json());
    const stripe = getStripeClient();
    const session = await stripe.checkout.sessions.retrieve(parsed.sessionId);
    assertCheckoutBelongsToUser(session, user.uid);
    await finalizeCheckoutSession(session);
    return NextResponse.json({ ok: true });
  } catch (error) {
    return handleRouteError(error);
  }
}
