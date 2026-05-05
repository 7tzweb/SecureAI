import { NextRequest, NextResponse } from "next/server";
import { handleRouteError } from "@/server/api/errors";
import { requireSessionUser } from "@/server/auth/session";
import { listScansForUser } from "@/server/scans/service";

export const runtime = "nodejs";

export async function GET(request: NextRequest) {
  try {
    const user = await requireSessionUser(request);
    const scans = await listScansForUser(user.uid, user.email);
    return NextResponse.json({ scans });
  } catch (error) {
    return handleRouteError(error);
  }
}
