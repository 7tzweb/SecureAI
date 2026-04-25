import { NextRequest, NextResponse } from "next/server";
import { handleRouteError } from "@/server/api/errors";
import { requireSessionUser } from "@/server/auth/session";
import { capturePayPalScanCreditOrder } from "@/server/billing/paypal";
import { assertRateLimit } from "@/server/rate-limit";
import { paypalCaptureSchema } from "@/server/scans/schemas";

export const runtime = "nodejs";

export async function POST(request: NextRequest) {
  try {
    const user = await requireSessionUser(request);
    assertRateLimit("checkout", user.uid);
    const parsed = paypalCaptureSchema.parse(await request.json());
    const quota = await capturePayPalScanCreditOrder(parsed.orderId, user.uid);
    return NextResponse.json({ ok: true, quota });
  } catch (error) {
    return handleRouteError(error);
  }
}
