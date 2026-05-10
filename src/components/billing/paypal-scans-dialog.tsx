"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { createPortal } from "react-dom";
import { Loader2, X } from "lucide-react";
import { useAuth } from "@/components/providers/auth-provider";
import { Button } from "@/components/ui/button";
import { defaultScanPack, getScanPack, scanPacks } from "@/lib/scan-packs";
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

type PaypalScansDialogProps = {
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

export function PaypalScansDialog({
  open,
  quota,
  onClose,
  onApproved,
}: PaypalScansDialogProps) {
  const { user, ensureServerSession } = useAuth();
  const buttonsRef = useRef<HTMLDivElement | null>(null);
  const scansRef = useRef<number | null>(defaultScanPack.scans);
  const [error, setError] = useState<string | null>(null);
  const [selectedScans, setSelectedScans] = useState<number>(defaultScanPack.scans);
  const [checkoutMode, setCheckoutMode] = useState<"live" | "sandbox" | null>(null);
  const [status, setStatus] = useState<"idle" | "loading" | "ready" | "capturing" | "complete">(
    "idle",
  );
  const defaultScans = quota?.upgradeScans ?? defaultScanPack.scans;
  const defaultPack = getScanPack(defaultScans) ?? defaultScanPack;
  const selectedPack = getScanPack(selectedScans) ?? defaultPack;

  useEffect(() => {
    scansRef.current = selectedPack.scans;
  }, [selectedPack.scans]);

  const resetDialogState = useCallback(() => {
    scansRef.current = defaultScanPack.scans;
    setSelectedScans(defaultScanPack.scans);
    setCheckoutMode(null);
    setError(null);
    setStatus("idle");
  }, []);

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
        await ensureServerSession();
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
            if (!scansRef.current) {
              throw new Error("Select a scan pack.");
            }

            await ensureServerSession();
            const response = await fetch("/api/billing/paypal/order", {
              method: "POST",
              headers: {
                "Content-Type": "application/json",
              },
              body: JSON.stringify({ scans: scansRef.current }),
            });
            const payload = await parseJsonResponse<{ orderId: string }>(response);
            return payload.orderId;
          },
          onApprove: async (data) => {
            if (!data.orderID) {
              throw new Error("PayPal did not return an order id.");
            }

            setStatus("capturing");
            await ensureServerSession();
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
  }, [ensureServerSession, onApproved, open, resetDialogState]);

  if (!open || typeof document === "undefined") {
    return null;
  }

  const dialog = (
    <div className="fixed inset-0 z-[90] overflow-y-auto bg-slate-950/45 px-4 py-6 backdrop-blur-sm">
      <div className="flex min-h-full items-center justify-center">
        <div className="w-full max-w-[480px] rounded-[1.5rem] border border-white/70 bg-white p-5 shadow-[0_24px_80px_rgba(15,23,42,0.24)]">
          <div className="flex items-start justify-between gap-4">
            <div>
              <p className="text-sm font-semibold text-slate-900">Buy more scans</p>
              <p className="mt-1 text-sm leading-6 text-slate-500">
                Start at {defaultPack.scans} scans for ${defaultPack.priceUsd.toFixed(2)} and choose a pack
                for this Google account.
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
              <p className="text-sm font-medium text-slate-700">Scans to buy</p>
              <p className="text-xs font-medium text-slate-500">Total ${selectedPack.priceUsd.toFixed(2)}</p>
            </div>

            <div className="mt-3 grid gap-2 sm:grid-cols-3">
              {scanPacks.map((pack) => {
                const selected = pack.scans === selectedPack.scans;
                return (
                  <button
                    key={pack.scans}
                    type="button"
                    onClick={() => setSelectedScans(pack.scans)}
                    className={`rounded-2xl border px-4 py-3 text-left transition-colors ${
                      selected
                        ? "border-[var(--primary)] bg-white shadow-sm"
                        : "border-slate-200 bg-white text-slate-700 hover:bg-slate-100"
                    }`}
                    aria-pressed={selected}
                  >
                    <span className="block text-sm font-semibold text-slate-900">{pack.scans} scans</span>
                    <span className="mt-1 block text-xs font-medium text-slate-500">
                      ${pack.priceUsd.toFixed(2)}
                    </span>
                  </button>
                );
              })}
            </div>

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
                Payment complete. Scans were added to your account.
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
