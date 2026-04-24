import { NextRequest, NextResponse } from "next/server";
import { handleRouteError } from "@/server/api/errors";
import {
  buildExpiredSessionCookie,
  buildSessionCookie,
  createServerSessionFromIdToken,
  getOptionalSessionUser,
} from "@/server/auth/session";
import { sessionSchema } from "@/server/scans/schemas";

export const runtime = "nodejs";

export async function GET(request: NextRequest) {
  try {
    const user = await getOptionalSessionUser(request);
    return NextResponse.json({ user });
  } catch (error) {
    return handleRouteError(error);
  }
}

export async function POST(request: NextRequest) {
  try {
    const parsed = sessionSchema.parse(await request.json());
    const { sessionCookie, sessionUser } = await createServerSessionFromIdToken(parsed.idToken);
    const response = NextResponse.json({ user: sessionUser });
    response.cookies.set(buildSessionCookie(sessionCookie));
    return response;
  } catch (error) {
    return handleRouteError(error);
  }
}

export async function DELETE() {
  const response = NextResponse.json({ ok: true });
  response.cookies.set(buildExpiredSessionCookie());
  return response;
}
