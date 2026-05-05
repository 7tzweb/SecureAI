import { randomUUID } from "node:crypto";
import { NextRequest, NextResponse } from "next/server";
import { handleRouteError } from "@/server/api/errors";
import { getOptionalSessionUser } from "@/server/auth/session";
import { assertRateLimit } from "@/server/rate-limit";
import { createScanSchema } from "@/server/scans/schemas";
import { createScan } from "@/server/scans/service";

export const runtime = "nodejs";

const ANONYMOUS_SCAN_COOKIE = "fixnx_anonymous_scan_id";
const ANONYMOUS_SCAN_COOKIE_MAX_AGE = 60 * 60 * 24 * 365;

export async function POST(request: NextRequest) {
  try {
    const sessionUser = await getOptionalSessionUser(request);
    const existingAnonymousId = request.cookies.get(ANONYMOUS_SCAN_COOKIE)?.value ?? null;
    const anonymousClientId = sessionUser ? null : existingAnonymousId ?? randomUUID();
    const identifier =
      sessionUser?.uid ?? anonymousClientId ?? request.headers.get("x-forwarded-for") ?? "anonymous";
    assertRateLimit("create-scan", identifier);

    const parsed = createScanSchema.parse(await request.json());
    const scan = await createScan(
      parsed.target,
      sessionUser?.uid ?? null,
      sessionUser?.email ?? null,
      anonymousClientId,
      {
        scanMode: parsed.scanMode,
        authCookieHeader: parsed.authCookieHeader,
        secondaryAuthCookieHeader: parsed.secondaryAuthCookieHeader,
        authLoginUrl: parsed.authLoginUrl,
        authUsername: parsed.authUsername,
        authPassword: parsed.authPassword,
        authRoleLabel: parsed.authRoleLabel,
        secondaryAuthLoginUrl: parsed.secondaryAuthLoginUrl,
        secondaryAuthUsername: parsed.secondaryAuthUsername,
        secondaryAuthPassword: parsed.secondaryAuthPassword,
        secondaryAuthRoleLabel: parsed.secondaryAuthRoleLabel,
      },
    );
    const response = NextResponse.json({ scan }, { status: 201 });

    if (!sessionUser && !existingAnonymousId && anonymousClientId) {
      response.cookies.set(ANONYMOUS_SCAN_COOKIE, anonymousClientId, {
        httpOnly: true,
        maxAge: ANONYMOUS_SCAN_COOKIE_MAX_AGE,
        path: "/",
        sameSite: "lax",
        secure: process.env.NODE_ENV === "production",
      });
    }

    return response;
  } catch (error) {
    return handleRouteError(error);
  }
}
