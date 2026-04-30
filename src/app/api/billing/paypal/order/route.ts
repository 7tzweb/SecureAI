import { NextRequest, NextResponse } from "next/server";
import { handleRouteError } from "@/server/api/errors";
import { requireSessionUser } from "@/server/auth/session";
import { createPayPalScanCreditOrder } from "@/server/billing/paypal";
import { assertRateLimit } from "@/server/rate-limit";
import { paypalOrderSchema } from "@/server/scans/schemas";

export const runtime = "nodejs";

export async function POST(request: NextRequest) {
  try {
    const user = await requireSessionUser(request);
    assertRateLimit("checkout", user.uid);
    const parsed = paypalOrderSchema.parse(await request.json());
    const orderId = await createPayPalScanCreditOrder(user.uid, parsed.credits, user.email);
    return NextResponse.json({ orderId });
  } catch (error) {
    return handleRouteError(error);
  }
}
