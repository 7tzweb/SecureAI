import { NextRequest, NextResponse } from "next/server";
import { handleRouteError } from "@/server/api/errors";
import { getOptionalSessionUser } from "@/server/auth/session";
import { listRecentScansForSidebar } from "@/server/scans/service";

export const runtime = "nodejs";

export async function GET(request: NextRequest) {
  try {
    const sessionUser = await getOptionalSessionUser(request);
    const scans = await listRecentScansForSidebar(sessionUser);
    return NextResponse.json({ scans });
  } catch (error) {
    return handleRouteError(error);
  }
}
