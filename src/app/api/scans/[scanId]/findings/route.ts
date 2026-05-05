import { NextRequest, NextResponse } from "next/server";
import { handleRouteError, notFound } from "@/server/api/errors";
import { getOptionalSessionUser } from "@/server/auth/session";
import { findingsQuerySchema } from "@/server/scans/schemas";
import { getScanFindings } from "@/server/scans/service";

export const runtime = "nodejs";

export async function GET(
  request: NextRequest,
  { params }: { params: Promise<{ scanId: string }> },
) {
  try {
    const { scanId } = await params;
    const sessionUser = await getOptionalSessionUser(request);
    const query = findingsQuerySchema.parse({
      category: request.nextUrl.searchParams.get("category") ?? undefined,
    });

    const findings = await getScanFindings(scanId, sessionUser, query.category);
    if (!findings) {
      throw notFound("Scan not found.");
    }

    return NextResponse.json(findings);
  } catch (error) {
    return handleRouteError(error);
  }
}
