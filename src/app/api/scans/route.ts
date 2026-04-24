import { NextRequest, NextResponse } from "next/server";
import { handleRouteError } from "@/server/api/errors";
import { getOptionalSessionUser } from "@/server/auth/session";
import { assertRateLimit } from "@/server/rate-limit";
import { createScanSchema } from "@/server/scans/schemas";
import { createScan } from "@/server/scans/service";

export const runtime = "nodejs";

export async function POST(request: NextRequest) {
  try {
    const sessionUser = await getOptionalSessionUser(request);
    const identifier =
      sessionUser?.uid ?? request.headers.get("x-forwarded-for") ?? "anonymous";
    assertRateLimit("create-scan", identifier);

    const parsed = createScanSchema.parse(await request.json());
    const scan = await createScan(parsed.target, sessionUser?.uid ?? null);
    return NextResponse.json({ scan }, { status: 201 });
  } catch (error) {
    return handleRouteError(error);
  }
}
