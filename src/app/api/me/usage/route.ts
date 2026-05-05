import { NextRequest, NextResponse } from "next/server";
import { handleRouteError } from "@/server/api/errors";
import { requireSessionUser } from "@/server/auth/session";
import { getScanQuotaSummary } from "@/server/scans/service";

export const runtime = "nodejs";

export async function GET(request: NextRequest) {
  try {
    const user = await requireSessionUser(request);
    const quota = await getScanQuotaSummary(user.uid, user.email);
    return NextResponse.json({ quota });
  } catch (error) {
    return handleRouteError(error);
  }
}
