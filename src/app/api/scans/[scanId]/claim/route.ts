import { NextRequest, NextResponse } from "next/server";
import { handleRouteError } from "@/server/api/errors";
import { requireSessionUser } from "@/server/auth/session";
import { assertRateLimit } from "@/server/rate-limit";
import { claimScanToUser } from "@/server/scans/service";

export const runtime = "nodejs";

export async function POST(
  request: NextRequest,
  { params }: { params: Promise<{ scanId: string }> },
) {
  try {
    const user = await requireSessionUser(request);
    assertRateLimit("claim-scan", user.uid);
    const { scanId } = await params;
    const scan = await claimScanToUser(scanId, user);
    return NextResponse.json({ scan });
  } catch (error) {
    return handleRouteError(error);
  }
}
