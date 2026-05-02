import { createHash } from "node:crypto";
import type { AuthContext } from "@/security/auth/authContextStore";
import { loadAttempt } from "@/server/scans/helpers";

export type AccessMatrixRow = {
  endpoint: string;
  method: string;
  sensitivity: "public" | "authenticated" | "user-owned" | "admin" | "unknown";
  expectedAccess?: string[];
  observed: Record<string, {
    status: number;
    contentLength: number;
    normalizedHash: string;
    responseClass: "success" | "redirect" | "unauthorized" | "forbidden" | "not-found" | "error";
  }>;
  issueType?:
    | "anonymous_can_access_protected"
    | "user_can_access_admin"
    | "cross_user_access"
    | "admin_endpoint_public"
    | "unexpected_access_difference";
  evidenceSummary?: string;
};

function normalizedHash(bodyText: string) {
  return createHash("sha256")
    .update(bodyText.replace(/\s+/g, " ").trim().slice(0, 40_000))
    .digest("hex")
    .slice(0, 16);
}

function responseClass(status: number): AccessMatrixRow["observed"][string]["responseClass"] {
  if (status >= 200 && status < 300) {
    return "success";
  }
  if (status >= 300 && status < 400) {
    return "redirect";
  }
  if (status === 401) {
    return "unauthorized";
  }
  if (status === 403) {
    return "forbidden";
  }
  if (status === 404) {
    return "not-found";
  }
  return "error";
}

export function classifyEndpointSensitivity(endpoint: string): AccessMatrixRow["sensitivity"] {
  const lower = endpoint.toLowerCase();
  if (/\/(?:admin|administrator|manage|internal|configuration|debug|metrics|status|actuator|api\/admin|graphql)/i.test(lower)) {
    return "admin";
  }
  if (/\/(?:user|users|profile|account|basket|cart|orders?|invoice|payment|address|documents?|reports?)(?:\/|$|\?)/i.test(lower)) {
    return "user-owned";
  }
  if (/\/(?:auth|session|me|whoami|token|logout|password)/i.test(lower)) {
    return "authenticated";
  }
  if (/\/(?:api|rest|graphql)/i.test(lower)) {
    return "unknown";
  }
  return "public";
}

function sensitiveBody(bodyText: string) {
  return /"(?:email|token|role|admin|password|configuration|secret|basket|order|invoice|address|payment)"\s*:/i.test(bodyText);
}

export async function buildRoleBasedAccessMatrix(input: {
  endpoints: string[];
  contexts: AuthContext[];
  timeoutMs?: number;
  maxEndpoints?: number;
}) {
  const endpoints = [...new Set(input.endpoints)]
    .filter(Boolean)
    .slice(0, input.maxEndpoints ?? 12);
  const contexts = input.contexts.length
    ? input.contexts
    : [{ id: "anonymous", label: "anonymous" as const, headers: {} }];
  const rows: AccessMatrixRow[] = [];

  for (const endpoint of endpoints) {
    const sensitivity = classifyEndpointSensitivity(endpoint);
    const observed: AccessMatrixRow["observed"] = {};
    const bodySensitivity: Record<string, boolean> = {};

    await Promise.all(
      contexts.map(async (context) => {
        const attempt = await loadAttempt(endpoint, {
          timeoutMs: input.timeoutMs ?? 7_000,
          followRedirects: false,
          headers: context.headers,
        });
        if (!attempt) {
          observed[context.label] = {
            status: 0,
            contentLength: 0,
            normalizedHash: "",
            responseClass: "error",
          };
          return;
        }
        observed[context.label] = {
          status: attempt.status,
          contentLength: attempt.bodyText.length,
          normalizedHash: normalizedHash(attempt.bodyText),
          responseClass: responseClass(attempt.status),
        };
        bodySensitivity[context.label] = sensitiveBody(attempt.bodyText);
      }),
    );

    const anonymousSuccess = observed.anonymous?.responseClass === "success";
    const lowUserSuccess = Object.entries(observed).some(
      ([label, observation]) => !/admin/i.test(label) && label !== "anonymous" && observation.responseClass === "success",
    );
    const issueType =
      sensitivity === "admin" && anonymousSuccess && bodySensitivity.anonymous
        ? "admin_endpoint_public"
        : sensitivity !== "public" && anonymousSuccess && bodySensitivity.anonymous
          ? "anonymous_can_access_protected"
          : sensitivity === "admin" && lowUserSuccess
            ? "user_can_access_admin"
            : undefined;

    rows.push({
      endpoint,
      method: "GET",
      sensitivity,
      expectedAccess:
        sensitivity === "public"
          ? ["anonymous", "userA", "userB", "admin"]
          : sensitivity === "admin"
            ? ["admin"]
            : ["userA", "userB", "admin"],
      observed,
      issueType,
      evidenceSummary: issueType
        ? `${issueType.replace(/_/g, " ")} observed on ${endpoint}`
        : "Access pattern recorded; no clear role violation was proven.",
    });
  }

  return rows;
}
