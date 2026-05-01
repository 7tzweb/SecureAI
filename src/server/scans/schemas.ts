import { z } from "zod";
import { categoryKeys } from "@/lib/types";
import { SCAN_CREDIT_PACK_SIZE } from "@/server/scans/service";

export const createScanSchema = z.object({
  target: z.string().trim().min(1).max(255),
  authCookieHeader: z.string().trim().max(8_000).optional(),
  secondaryAuthCookieHeader: z.string().trim().max(8_000).optional(),
});

export const checkoutSchema = z.object({
  purpose: z.enum(["scan-plan", "report-upgrade"]).default("scan-plan"),
  scanId: z.string().trim().min(8).max(128).optional(),
  returnPath: z.string().trim().min(1).max(255).optional(),
}).superRefine((value, ctx) => {
  if (value.purpose === "report-upgrade" && !value.scanId) {
    ctx.addIssue({
      code: z.ZodIssueCode.custom,
      message: "scanId is required for report upgrades.",
      path: ["scanId"],
    });
  }
});

export const checkoutConfirmSchema = z.object({
  sessionId: z.string().trim().min(8).max(255),
});

export const paypalCaptureSchema = z.object({
  orderId: z.string().trim().min(8).max(255),
});

export const paypalOrderSchema = z.object({
  credits: z.coerce.number().int().min(SCAN_CREDIT_PACK_SIZE).max(10_000),
});

export const sessionSchema = z.object({
  idToken: z.string().trim().min(10),
});

export const findingsQuerySchema = z.object({
  category: z.enum(categoryKeys).optional(),
});
