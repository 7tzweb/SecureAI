import { createHash } from "node:crypto";
import type { AuthContext } from "@/security/auth/authContextStore";
import { loadAttempt } from "@/server/scans/helpers";

export type AccessResponseClass =
  | "success-sensitive-data"
  | "success-public-data"
  | "success-empty"
  | "anonymous-empty"
  | "authenticated-user-data"
  | "admin-data"
  | "redirect"
  | "unauthorized"
  | "forbidden"
  | "not-found"
  | "error"
  | "not-tested";

export type AccessMatrixCell = {
  status?: number;
  responseClass: AccessResponseClass;
  sensitiveFields?: string[];
  ownerMarkers?: string[];
  contentLength?: number;
  normalizedHash?: string;
  notes?: string;
};

export type AccessMatrixRow = {
  endpoint: string;
  method?: string;
  sensitivity: "public" | "authenticated" | "user-owned" | "admin" | "debug" | "config" | "unknown";
  expectedAccess?: string[];
  anonymous?: AccessMatrixCell;
  scannerAuthContext?: AccessMatrixCell;
  userA?: AccessMatrixCell;
  userB?: AccessMatrixCell;
  admin?: AccessMatrixCell;
  observed?: Record<string, AccessMatrixCell>;
  issue:
    | "none"
    | "partial-coverage"
    | "anonymous-sensitive-access"
    | "user-admin-access"
    | "cross-user-access"
    | "needs-review";
  issueType?: AccessMatrixRow["issue"];
  explanation: string;
  evidenceSummary?: string;
};

function normalizedHash(bodyText: string) {
  return createHash("sha256")
    .update(bodyText.replace(/\s+/g, " ").trim().slice(0, 40_000))
    .digest("hex")
    .slice(0, 16);
}

function extractSensitiveFields(bodyText: string) {
  const fields = new Set<string>();
  [
    "email",
    "token",
    "role",
    "admin",
    "password",
    "configuration",
    "secret",
    "basket",
    "order",
    "invoice",
    "address",
    "payment",
    "userId",
    "id",
    "profile",
  ].forEach((field) => {
    if (new RegExp(`"?(?:${field})"?\\s*:`, "i").test(bodyText)) {
      fields.add(field);
    }
  });

  return [...fields];
}

function isEmptyBody(bodyText: string) {
  const compact = bodyText.replace(/\s+/g, "").trim().toLowerCase();
  return compact === "" || compact === "{}" || compact === "[]" || compact === "null";
}

function containsAnonymousIdentity(bodyText: string) {
  return /anonymous|unauthenticated|null/i.test(bodyText) && !/"email"\s*:|"userId"\s*:|"id"\s*:\s*[1-9]/i.test(bodyText);
}

function responseClass(input: {
  status: number;
  bodyText: string;
  sensitivity: AccessMatrixRow["sensitivity"];
  contextKey: string;
  sensitiveFields: string[];
}): AccessResponseClass {
  if (input.status >= 300 && input.status < 400) {
    return "redirect";
  }
  if (input.status === 401) {
    return "unauthorized";
  }
  if (input.status === 403) {
    return "forbidden";
  }
  if (input.status === 404) {
    return "not-found";
  }
  if (input.status < 200 || input.status >= 300) {
    return "error";
  }
  if (isEmptyBody(input.bodyText)) {
    return input.contextKey === "anonymous" ? "anonymous-empty" : "success-empty";
  }
  if (input.contextKey === "anonymous" && containsAnonymousIdentity(input.bodyText)) {
    return "anonymous-empty";
  }
  if (
    input.sensitivity === "admin" ||
    input.sensitivity === "config" ||
    input.sensitivity === "debug" ||
    input.sensitiveFields.some((field) => /admin|configuration|secret/i.test(field))
  ) {
    return "admin-data";
  }
  if (
    input.sensitiveFields.some((field) =>
      /email|userId|basket|order|invoice|address|payment|profile|token|role/i.test(field),
    )
  ) {
    return input.contextKey === "anonymous" ? "success-sensitive-data" : "authenticated-user-data";
  }
  return "success-public-data";
}

export function classifyEndpointSensitivity(endpoint: string): AccessMatrixRow["sensitivity"] {
  const lower = endpoint.toLowerCase();
  if (/\/(?:admin|administrator|manage|api\/admin)/i.test(lower)) {
    return "admin";
  }
  if (/\/(?:debug|metrics|status|actuator|server-status|phpinfo)/i.test(lower)) {
    return "debug";
  }
  if (/\/(?:configuration|config|internal|graphql)/i.test(lower)) {
    return "config";
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

function contextKey(context: AuthContext): "anonymous" | "scannerAuthContext" | "userA" | "userB" | "admin" {
  const label = `${context.id} ${context.label} ${context.role ?? ""}`.toLowerCase();
  if (/admin/.test(label)) {
    return "admin";
  }
  if (context.id === "anonymous" || context.label === "anonymous") {
    return "anonymous";
  }
  if (/userb|user b|secondary/.test(label)) {
    return "userB";
  }
  if (/usera|user a/.test(label)) {
    return "scannerAuthContext";
  }
  return "scannerAuthContext";
}

function emptyCell(notes = "No request was made for this role."): AccessMatrixCell {
  return {
    responseClass: "not-tested",
    notes,
  };
}

function hasSensitiveAccess(cell: AccessMatrixCell | undefined) {
  return cell?.responseClass === "success-sensitive-data" || cell?.responseClass === "admin-data";
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
    const observed: Record<string, AccessMatrixCell> = {};
    const cells: Pick<AccessMatrixRow, "anonymous" | "scannerAuthContext" | "userA" | "userB" | "admin"> = {
      anonymous: emptyCell(),
      scannerAuthContext: emptyCell(),
      userA: emptyCell(),
      userB: emptyCell(),
      admin: emptyCell(),
    };

    await Promise.all(
      contexts.map(async (context) => {
        const key = contextKey(context);
        const attempt = await loadAttempt(endpoint, {
          timeoutMs: input.timeoutMs ?? 7_000,
          followRedirects: false,
          headers: context.headers,
        });
        if (!attempt) {
          const cell: AccessMatrixCell = {
            status: 0,
            contentLength: 0,
            normalizedHash: "",
            responseClass: "error",
            notes: "The request failed or timed out.",
          };
          observed[key] = cell;
          cells[key] = cell;
          return;
        }

        const sensitiveFields = extractSensitiveFields(attempt.bodyText);
        const cell: AccessMatrixCell = {
          status: attempt.status,
          contentLength: attempt.bodyText.length,
          normalizedHash: normalizedHash(attempt.bodyText),
          responseClass: responseClass({
            status: attempt.status,
            bodyText: attempt.bodyText,
            sensitivity,
            contextKey: key,
            sensitiveFields,
          }),
          sensitiveFields,
          notes:
            key === "anonymous" && attempt.status === 200 && sensitiveFields.length === 0
              ? "Anonymous access returned 200 but did not expose identity or sensitive fields in the sampled response."
              : undefined,
        };
        observed[key] = cell;
        cells[key] = cell;
      }),
    );

    const hasUserA = cells.userA?.responseClass !== "not-tested";
    const hasUserB = cells.userB?.responseClass !== "not-tested";
    const hasAdmin = cells.admin?.responseClass !== "not-tested";
    const partialCoverage = !hasUserA || !hasUserB || !hasAdmin;
    const lowUserAdminAccess =
      (sensitivity === "admin" || sensitivity === "config" || sensitivity === "debug") &&
      (hasSensitiveAccess(cells.scannerAuthContext) || hasSensitiveAccess(cells.userA) || hasSensitiveAccess(cells.userB));
    const anonymousSensitiveAccess =
      sensitivity !== "public" &&
      (hasSensitiveAccess(cells.anonymous) || cells.anonymous?.responseClass === "authenticated-user-data");
    const issue: AccessMatrixRow["issue"] =
      anonymousSensitiveAccess
        ? "anonymous-sensitive-access"
        : lowUserAdminAccess
          ? "user-admin-access"
          : partialCoverage && sensitivity !== "public"
            ? "partial-coverage"
            : "none";
    const explanation =
      issue === "anonymous-sensitive-access"
        ? "Anonymous access returned sensitive or authenticated-looking data from a non-public endpoint."
        : issue === "user-admin-access"
          ? "A low-privileged authenticated context received admin/config/debug-looking data."
          : issue === "partial-coverage"
            ? "Only anonymous and scanner-auth-context coverage was available. Provide userA, userB, and admin contexts for full role-based authorization proof."
            : "The sampled role responses did not prove an authorization issue.";

    rows.push({
      endpoint,
      method: "GET",
      sensitivity,
      expectedAccess:
        sensitivity === "public"
          ? ["anonymous", "userA", "userB", "admin"]
          : sensitivity === "admin" || sensitivity === "config" || sensitivity === "debug"
            ? ["admin"]
            : ["userA", "userB", "admin"],
      ...cells,
      observed,
      issue,
      issueType: issue,
      explanation,
      evidenceSummary: `${issue.replace(/-/g, " ")} on ${endpoint}. ${explanation}`,
    });
  }

  return rows;
}
