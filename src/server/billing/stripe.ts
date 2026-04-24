import "server-only";

import Stripe from "stripe";
import { serviceUnavailable } from "@/server/api/errors";
import { hasStripeConfig, serverConfig } from "@/server/config";

let stripeClient: Stripe | null = null;

export function getStripeClient() {
  if (!hasStripeConfig) {
    throw serviceUnavailable("Stripe checkout is not configured.");
  }

  if (!stripeClient) {
    stripeClient = new Stripe(serverConfig.stripeSecretKey, {
      apiVersion: "2025-10-29.clover",
    });
  }

  return stripeClient;
}
