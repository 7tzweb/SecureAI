import { NextRequest, NextResponse } from "next/server";
import { handleRouteError } from "@/server/api/errors";
import { requireSessionUser } from "@/server/auth/session";
import { capturePayPalScanOrder } from "@/server/billing/paypal";
import { assertRateLimit } from "@/server/rate-limit";
import { paypalCaptureSchema } from "@/server/scans/schemas";

export const runtime = "nodejs";

export async function POST(request: NextRequest) {
  try {
    const user = await requireSessionUser(request);
    assertRateLimit("checkout", user.uid);
    const parsed = paypalCaptureSchema.parse(await request.json());
    const quota = await capturePayPalScanOrder(parsed.orderId, user.uid, user.email);
    return NextResponse.json({ ok: true, quota });
  } catch (error) {
    return handleRouteError(error);
  }
}
