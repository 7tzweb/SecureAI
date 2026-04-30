"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { createPortal } from "react-dom";
import { Loader2, X } from "lucide-react";
import { useAuth } from "@/components/providers/auth-provider";
import { Button } from "@/components/ui/button";
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

type PayPalConfigResponse = {
  clientId: string;
  mode: "live" | "sandbox";
};

let paypalSdkPromise: Promise<void> | null = null;
let loadedPayPalClientId: string | null = null;

function resetPayPalSdk() {
  document.getElementById("paypal-js-sdk")?.remove();
  window.paypal = undefined;
  paypalSdkPromise = null;
  loadedPayPalClientId = null;
}

function loadPayPalSdk(clientId: string) {
  if (!clientId) {
    return Promise.reject(new Error("PayPal client ID is missing."));
  }

  if (window.paypal?.Buttons && loadedPayPalClientId === clientId) {
    return Promise.resolve();
  }

  const existingScript = document.getElementById("paypal-js-sdk") as HTMLScriptElement | null;
  const existingClientId = existingScript?.dataset.paypalClientId ?? null;
  if (existingClientId && existingClientId !== clientId) {
    resetPayPalSdk();
  }

  if (paypalSdkPromise && loadedPayPalClientId === clientId) {
    return paypalSdkPromise;
  }

  loadedPayPalClientId = clientId;
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
      "client-id": clientId,
      currency: "USD",
      intent: "capture",
      components: "buttons",
    });

    script.id = "paypal-js-sdk";
    script.dataset.paypalClientId = clientId;
    script.src = `https://www.paypal.com/sdk/js?${params.toString()}`;
    script.async = true;
    script.onload = () => resolve();
    script.onerror = () => {
      resetPayPalSdk();
      reject(new Error("Unable to load PayPal."));
    };
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
  const { user } = useAuth();
  const buttonsRef = useRef<HTMLDivElement | null>(null);
  const creditsRef = useRef<number | null>(quota?.upgradeScanCredits ?? 20);
  const [error, setError] = useState<string | null>(null);
  const [creditsInput, setCreditsInput] = useState(String(quota?.upgradeScanCredits ?? 20));
  const [checkoutMode, setCheckoutMode] = useState<"live" | "sandbox" | null>(null);
  const [status, setStatus] = useState<"idle" | "loading" | "ready" | "capturing" | "complete">(
    "idle",
  );
  const minimumCredits = quota?.upgradeScanCredits ?? 20;
  const basePriceUsd = quota?.upgradePriceUsd ?? 10;
  const pricePerCreditUsd = basePriceUsd / minimumCredits;
  const parsedCredits = Number.parseInt(creditsInput, 10);
  const hasValidCreditsInput = Number.isInteger(parsedCredits) && parsedCredits >= minimumCredits;
  const selectedCredits = hasValidCreditsInput ? parsedCredits : minimumCredits;
  const totalPriceUsd = Number((selectedCredits * pricePerCreditUsd).toFixed(2));
  const quickSelectOptions = [
    minimumCredits,
    minimumCredits * 2,
    minimumCredits * 5,
    minimumCredits * 10,
  ];

  useEffect(() => {
    creditsRef.current = hasValidCreditsInput ? parsedCredits : null;
  }, [hasValidCreditsInput, parsedCredits]);

  const resetDialogState = useCallback(() => {
    creditsRef.current = minimumCredits;
    setCreditsInput(String(minimumCredits));
    setCheckoutMode(null);
    setError(null);
    setStatus("idle");
  }, [minimumCredits]);

  const handleClose = () => {
    resetDialogState();
    onClose();
  };

  useEffect(() => {
    if (!open || typeof document === "undefined") {
      return;
    }

    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => {
      document.body.style.overflow = previousOverflow;
    };
  }, [open]);

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
        const configResponse = await fetch("/api/billing/paypal/config", {
          cache: "no-store",
        });
        const config = await parseJsonResponse<PayPalConfigResponse>(configResponse);
        if (cancelled) {
          return;
        }

        setCheckoutMode(config.mode);
        await loadPayPalSdk(config.clientId);
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
            if (!creditsRef.current) {
              throw new Error(`Minimum purchase is ${minimumCredits} credits.`);
            }

            const response = await fetch("/api/billing/paypal/order", {
              method: "POST",
              headers: {
                "Content-Type": "application/json",
              },
              body: JSON.stringify({ credits: creditsRef.current }),
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
            resetDialogState();
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
  }, [minimumCredits, onApproved, open, resetDialogState]);

  if (!open || typeof document === "undefined") {
    return null;
  }

  const dialog = (
    <div className="fixed inset-0 z-[90] overflow-y-auto bg-slate-950/45 px-4 py-6 backdrop-blur-sm">
      <div className="flex min-h-full items-center justify-center">
        <div className="w-full max-w-[480px] rounded-[1.5rem] border border-white/70 bg-white p-5 shadow-[0_24px_80px_rgba(15,23,42,0.24)]">
          <div className="flex items-start justify-between gap-4">
            <div>
              <p className="text-sm font-semibold text-slate-900">Buy more credits</p>
              <p className="mt-1 text-sm leading-6 text-slate-500">
                Start at {minimumCredits} credits for ${basePriceUsd.toFixed(2)} and choose the amount you
                want for this Google account.
              </p>
            </div>
            <button
              type="button"
              onClick={handleClose}
              className="rounded-full p-2 text-slate-500 transition-colors hover:bg-slate-100 hover:text-slate-900"
              aria-label="Close PayPal checkout"
            >
              <X className="h-4 w-4" />
            </button>
          </div>

          <div className="mt-5 rounded-[1.25rem] bg-slate-50 p-4">
            <div className="flex items-center justify-between gap-4">
              <label htmlFor="paypal-credits-input" className="text-sm font-medium text-slate-700">
                Credits to buy
              </label>
              <p className="text-xs font-medium text-slate-500">${pricePerCreditUsd.toFixed(2)} per credit</p>
            </div>

            <div className="mt-3 flex items-center gap-3">
              <input
                id="paypal-credits-input"
                type="number"
                min={minimumCredits}
                step={1}
                inputMode="numeric"
                value={creditsInput}
                onChange={(event) => setCreditsInput(event.target.value)}
                className="h-12 w-full rounded-2xl border border-slate-200 bg-white px-4 text-base font-semibold text-slate-900 outline-none transition-colors focus:border-[var(--primary)]"
              />
              <div className="min-w-[118px] rounded-2xl border border-slate-200 bg-white px-4 py-3 text-right">
                <p className="text-[11px] font-bold uppercase tracking-[0.16em] text-slate-400">Total</p>
                <p className="mt-1 text-lg font-semibold text-slate-900">${totalPriceUsd.toFixed(2)}</p>
              </div>
            </div>

            <div className="mt-3 flex flex-wrap gap-2">
              {quickSelectOptions.map((credits) => (
                <button
                  key={credits}
                  type="button"
                  onClick={() => setCreditsInput(String(credits))}
                  className="rounded-full border border-slate-200 bg-white px-3 py-1.5 text-sm font-medium text-slate-700 transition-colors hover:bg-slate-100"
                >
                  {credits} credits
                </button>
              ))}
            </div>

            {!hasValidCreditsInput ? (
              <p className="mt-3 text-sm font-medium text-[var(--danger)]">
                Minimum purchase is {minimumCredits} credits.
              </p>
            ) : null}

            {checkoutMode === "sandbox" ? (
              <p className="mt-3 text-sm font-medium text-amber-700">
                PayPal sandbox mode is active for {user?.email ?? "this Google account"}.
              </p>
            ) : null}
          </div>

          <div className="mt-5 min-h-[120px]">
            <div ref={buttonsRef} />
            {status === "loading" || status === "capturing" ? (
              <div className="mt-3 flex items-center gap-2 text-sm text-slate-500">
                <Loader2 className="h-4 w-4 animate-spin" />
                {status === "capturing" ? "Confirming payment..." : "Loading PayPal..."}
              </div>
            ) : null}

            {status === "complete" ? (
              <p className="mt-3 text-sm font-medium text-emerald-700">
                Payment complete. Credits were added to your account.
              </p>
            ) : null}

            {error ? <p className="mt-3 text-sm font-medium text-[var(--danger)]">{error}</p> : null}
          </div>

          <Button variant="outline" size="sm" className="mt-4 w-full" onClick={handleClose}>
            Close
          </Button>
        </div>
      </div>
    </div>
  );

  return createPortal(dialog, document.body);
}
