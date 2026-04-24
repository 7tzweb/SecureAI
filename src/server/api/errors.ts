import { NextResponse } from "next/server";

export class ApiError extends Error {
  status: number;
  code: string;
  details?: unknown;

  constructor(status: number, code: string, message: string, details?: unknown) {
    super(message);
    this.status = status;
    this.code = code;
    this.details = details;
  }
}

export function badRequest(message: string, code = "BAD_REQUEST", details?: unknown) {
  return new ApiError(400, code, message, details);
}

export function unauthorized(message: string, code = "UNAUTHORIZED") {
  return new ApiError(401, code, message);
}

export function forbidden(message: string, code = "FORBIDDEN") {
  return new ApiError(403, code, message);
}

export function notFound(message: string, code = "NOT_FOUND") {
  return new ApiError(404, code, message);
}

export function conflict(message: string, code = "CONFLICT") {
  return new ApiError(409, code, message);
}

export function tooManyRequests(message: string, code = "RATE_LIMITED") {
  return new ApiError(429, code, message);
}

export function paymentRequired(message: string, code = "PAYMENT_REQUIRED", details?: unknown) {
  return new ApiError(402, code, message, details);
}

export function serviceUnavailable(message: string, code = "SERVICE_UNAVAILABLE") {
  return new ApiError(503, code, message);
}

export function handleRouteError(error: unknown) {
  if (error instanceof ApiError) {
    return NextResponse.json(
      {
        error: error.message,
        code: error.code,
        details: error.details,
      },
      { status: error.status },
    );
  }

  console.error("Unhandled API error", error);
  return NextResponse.json(
    {
      error: "Internal server error.",
      code: "INTERNAL_ERROR",
    },
    { status: 500 },
  );
}
