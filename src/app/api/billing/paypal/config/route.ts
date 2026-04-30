import { NextRequest, NextResponse } from "next/server";
import { handleRouteError } from "@/server/api/errors";
import { requireSessionUser } from "@/server/auth/session";
import { getPayPalCheckoutConfig } from "@/server/billing/paypal";

export const runtime = "nodejs";

export async function GET(request: NextRequest) {
  try {
    const user = await requireSessionUser(request);
    const config = getPayPalCheckoutConfig(user.email);
    return NextResponse.json(config);
  } catch (error) {
    return handleRouteError(error);
  }
}
