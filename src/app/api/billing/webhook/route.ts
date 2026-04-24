import { NextRequest, NextResponse } from "next/server";
import Stripe from "stripe";
import { handleRouteError } from "@/server/api/errors";
import { finalizeCheckoutSession } from "@/server/billing/service";
import { getStripeClient } from "@/server/billing/stripe";
import { hasStripeWebhookConfig, serverConfig } from "@/server/config";

export const runtime = "nodejs";

export async function POST(request: NextRequest) {
  try {
    if (!hasStripeWebhookConfig) {
      return NextResponse.json({ error: "Stripe webhook is not configured." }, { status: 503 });
    }

    const stripe = getStripeClient();
    const signature = request.headers.get("stripe-signature");
    const rawBody = await request.text();

    if (!signature) {
      return NextResponse.json({ error: "Missing webhook signature." }, { status: 400 });
    }

    const event = stripe.webhooks.constructEvent(
      rawBody,
      signature,
      serverConfig.stripeWebhookSecret,
    );

    if (
      event.type === "checkout.session.completed" ||
      event.type === "checkout.session.async_payment_succeeded"
    ) {
      await finalizeCheckoutSession(event.data.object as Stripe.Checkout.Session);
    }

    return NextResponse.json({ received: true });
  } catch (error) {
    return handleRouteError(error);
  }
}
