import { NextRequest, NextResponse } from "next/server";
import { handleRouteError } from "@/server/api/errors";
import { requireSessionUser } from "@/server/auth/session";
import { createPayPalScanCreditOrder } from "@/server/billing/paypal";
import { assertRateLimit } from "@/server/rate-limit";

export const runtime = "nodejs";

export async function POST(request: NextRequest) {
  try {
    const user = await requireSessionUser(request);
    assertRateLimit("checkout", user.uid);
    const orderId = await createPayPalScanCreditOrder(user.uid);
    return NextResponse.json({ orderId });
  } catch (error) {
    return handleRouteError(error);
  }
}
