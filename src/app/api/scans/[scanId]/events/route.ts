import { NextResponse } from "next/server";
import { handleRouteError } from "@/server/api/errors";
import { getScanEvents } from "@/server/scans/service";

export const runtime = "nodejs";

export async function GET(
  _request: Request,
  { params }: { params: Promise<{ scanId: string }> },
) {
  try {
    const { scanId } = await params;
    const events = await getScanEvents(scanId);
    return NextResponse.json({ events });
  } catch (error) {
    return handleRouteError(error);
  }
}
