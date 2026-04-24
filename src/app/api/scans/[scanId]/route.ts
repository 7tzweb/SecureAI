import { NextRequest, NextResponse } from "next/server";
import { notFound, handleRouteError } from "@/server/api/errors";
import { getOptionalSessionUser } from "@/server/auth/session";
import { getScanSummary } from "@/server/scans/service";

export const runtime = "nodejs";

export async function GET(
  request: NextRequest,
  { params }: { params: Promise<{ scanId: string }> },
) {
  try {
    const { scanId } = await params;
    const sessionUser = await getOptionalSessionUser(request);
    const summary = await getScanSummary(scanId, sessionUser?.uid ?? null);
    if (!summary) {
      throw notFound("Scan not found.");
    }

    return NextResponse.json(summary);
  } catch (error) {
    return handleRouteError(error);
  }
}
