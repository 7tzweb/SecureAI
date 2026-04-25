"use client";

import { useEffect, useRef, useState } from "react";
import { Loader2, X } from "lucide-react";
import { Button } from "@/components/ui/button";
import { publicConfig } from "@/lib/public-config";
import { type ScanQuotaSummary } from "@/lib/types";

type PayPalApproveData = {
  orderID?: string;
};

type PayPalButtonsInstance = {
  render: (container: HTMLElement) => Promise<void>;
  close?: () => void;
};

type PayPalButtonsOptions = {
  style?: {
    layout?: "vertical" | "horizontal";
    color?: "gold" | "blue" | "silver" | "white" | "black";
    shape?: "rect" | "pill";
    label?: "paypal" | "checkout" | "buynow" | "pay";
  };
  createOrder: () => Promise<string>;
  onApprove: (data: PayPalApproveData) => Promise<void>;
  onCancel?: () => void;
  onError?: (error: unknown) => void;
};

declare global {
  interface Window {
    paypal?: {
      Buttons: (options: PayPalButtonsOptions) => PayPalButtonsInstance;
    };
  }
}

type PaypalCreditsDialogProps = {
  open: boolean;
  quota: ScanQuotaSummary | null;
  onClose: () => void;
  onApproved: (quota: ScanQuotaSummary) => void | Promise<void>;
};

let paypalSdkPromise: Promise<void> | null = null;

function loadPayPalSdk() {
  if (window.paypal?.Buttons) {
    return Promise.resolve();
  }

  if (!publicConfig.paypalClientId) {
    return Promise.reject(new Error("PayPal client ID is missing."));
  }

  if (paypalSdkPromise) {
    return paypalSdkPromise;
  }

  paypalSdkPromise = new Promise<void>((resolve, reject) => {
    const existingScript = document.getElementById("paypal-js-sdk");
    if (existingScript) {
      existingScript.addEventListener("load", () => resolve(), { once: true });
      existingScript.addEventListener("error", () => reject(new Error("Unable to load PayPal.")), {
        once: true,
      });
      return;
    }

    const script = document.createElement("script");
    const params = new URLSearchParams({
      "client-id": publicConfig.paypalClientId,
      currency: "USD",
      intent: "capture",
      components: "buttons",
    });

    script.id = "paypal-js-sdk";
    script.src = `https://www.paypal.com/sdk/js?${params.toString()}`;
    script.async = true;
    script.onload = () => resolve();
    script.onerror = () => reject(new Error("Unable to load PayPal."));
    document.head.appendChild(script);
  });

  return paypalSdkPromise;
}

async function parseJsonResponse<T>(response: Response) {
  const payload = (await response.json().catch(() => null)) as T | { error?: string } | null;
  if (!response.ok) {
    throw new Error(
      payload && typeof payload === "object" && "error" in payload && payload.error
        ? payload.error
        : "Payment request failed.",
    );
  }

  return payload as T;
}

export function PaypalCreditsDialog({
  open,
  quota,
  onClose,
  onApproved,
}: PaypalCreditsDialogProps) {
  const buttonsRef = useRef<HTMLDivElement | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [status, setStatus] = useState<"idle" | "loading" | "ready" | "capturing" | "complete">(
    "idle",
  );

  useEffect(() => {
    if (!open) {
      return;
    }

    let cancelled = false;
    let buttons: PayPalButtonsInstance | null = null;

    const renderButtons = async () => {
      if (!buttonsRef.current) {
        return;
      }

      setStatus("loading");
      setError(null);

      try {
        await loadPayPalSdk();
        if (cancelled || !buttonsRef.current || !window.paypal?.Buttons) {
          return;
        }

        buttonsRef.current.innerHTML = "";
        buttons = window.paypal.Buttons({
          style: {
            layout: "vertical",
            color: "blue",
            shape: "pill",
            label: "paypal",
          },
          createOrder: async () => {
            const response = await fetch("/api/billing/paypal/order", {
              method: "POST",
            });
            const payload = await parseJsonResponse<{ orderId: string }>(response);
            return payload.orderId;
          },
          onApprove: async (data) => {
            if (!data.orderID) {
              throw new Error("PayPal did not return an order id.");
            }

            setStatus("capturing");
            const response = await fetch("/api/billing/paypal/capture", {
              method: "POST",
              headers: {
                "Content-Type": "application/json",
              },
              body: JSON.stringify({ orderId: data.orderID }),
            });
            const payload = await parseJsonResponse<{ quota: ScanQuotaSummary }>(response);
            setStatus("complete");
            await onApproved(payload.quota);
          },
          onCancel: () => {
            setStatus("ready");
          },
          onError: (nextError) => {
            setStatus("ready");
            setError(nextError instanceof Error ? nextError.message : "PayPal checkout failed.");
          },
        });

        await buttons.render(buttonsRef.current);
        if (!cancelled) {
          setStatus("ready");
        }
      } catch (nextError) {
        if (!cancelled) {
          setStatus("idle");
          setError(nextError instanceof Error ? nextError.message : "Unable to start PayPal.");
        }
      }
    };

    void renderButtons();

    return () => {
      cancelled = true;
      buttons?.close?.();
    };
  }, [onApproved, open]);

  if (!open) {
    return null;
  }

  const packSize = quota?.upgradeScanCredits ?? 30;
  const price = quota?.upgradePriceUsd ?? 4.9;

  return (
    <div className="fixed inset-0 z-[80] flex items-center justify-center bg-slate-950/35 px-4 backdrop-blur-sm">
      <div className="w-full max-w-[440px] rounded-[1.5rem] border border-white/70 bg-white p-5 shadow-[0_24px_80px_rgba(15,23,42,0.24)]">
        <div className="flex items-start justify-between gap-4">
          <div>
            <p className="text-sm font-semibold text-slate-900">Buy more scans</p>
            <p className="mt-1 text-sm leading-6 text-slate-500">
              Add {packSize} scans to this Google account for ${price.toFixed(2)}.
            </p>
          </div>
          <button
            type="button"
            onClick={onClose}
            className="rounded-full p-2 text-slate-500 transition-colors hover:bg-slate-100 hover:text-slate-900"
            aria-label="Close PayPal checkout"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        <div className="mt-5 min-h-[120px]">
          {publicConfig.paypalClientId ? (
            <>
              <div ref={buttonsRef} />
              {status === "loading" || status === "capturing" ? (
                <div className="mt-3 flex items-center gap-2 text-sm text-slate-500">
                  <Loader2 className="h-4 w-4 animate-spin" />
                  {status === "capturing" ? "Confirming payment..." : "Loading PayPal..."}
                </div>
              ) : null}
            </>
          ) : (
            <div className="rounded-[1rem] bg-amber-50 p-4 text-sm leading-6 text-amber-800">
              PayPal client ID is missing. Add it to `NEXT_PUBLIC_PAYPAL_CLIENT_ID`.
            </div>
          )}

          {status === "complete" ? (
            <p className="mt-3 text-sm font-medium text-emerald-700">
              Payment complete. Scan credits were added.
            </p>
          ) : null}

          {error ? <p className="mt-3 text-sm font-medium text-[var(--danger)]">{error}</p> : null}
        </div>

        <Button variant="outline" size="sm" className="mt-4 w-full" onClick={onClose}>
          Close
        </Button>
      </div>
    </div>
  );
}
