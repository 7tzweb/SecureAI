"use client";

import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { useCallback, useEffect, useRef, useState } from "react";
import { Clock3, ExternalLink, Loader2, UserCircle2 } from "lucide-react";
import { PaypalCreditsDialog } from "@/components/billing/paypal-credits-dialog";
import { StartAuditForm } from "@/components/landing/start-audit-form";
import { useAuth } from "@/components/providers/auth-provider";
import { Button } from "@/components/ui/button";
import { dispatchQuotaRefresh, subscribeQuotaRefresh } from "@/lib/quota-events";
import { type ScanQuotaSummary } from "@/lib/types";
import { cn } from "@/lib/utils";

async function fetchJson<T>(url: string, init?: RequestInit) {
  const response = await fetch(url, { cache: "no-store", ...init });
  const payload = (await response.json().catch(() => null)) as
    | T
    | { error?: string; code?: string }
    | null;

  if (!response.ok) {
    const message =
      payload && typeof payload === "object" && "error" in payload && typeof payload.error === "string"
        ? payload.error
        : "Request failed";
    throw new Error(message);
  }

  return payload as T;
}

function stripCheckoutParams(pathname: string, searchParams: URLSearchParams) {
  const nextParams = new URLSearchParams(searchParams.toString());
  nextParams.delete("checkout");
  nextParams.delete("session_id");
  const query = nextParams.toString();
  return query ? `${pathname}?${query}` : pathname;
}

export function SiteHeader() {
  const router = useRouter();
  const pathname = usePathname();
  const {
    user,
    status,
    isConfigured,
    signInWithGoogle,
    ensureServerSession,
    signOut,
  } = useAuth();
  const [quota, setQuota] = useState<ScanQuotaSummary | null>(null);
  const [accountOpen, setAccountOpen] = useState(false);
  const [actionPending, setActionPending] = useState(false);
  const [paypalOpen, setPaypalOpen] = useState(false);
  const [banner, setBanner] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const panelRef = useRef<HTMLDivElement | null>(null);
  const isWorkspacePage = pathname.startsWith("/scans") || pathname.startsWith("/history");

  const refreshQuota = useCallback(async () => {
    const nextQuota = await (async () => {
      if (status !== "signed-in" || !user) {
        return null;
      }

      try {
        await ensureServerSession();
        const payload = await fetchJson<{ quota: ScanQuotaSummary }>("/api/me/usage");
        return payload.quota;
      } catch {
        return null;
      }
    })();

    setQuota(nextQuota);
  }, [ensureServerSession, status, user]);

  useEffect(() => {
    const timer = window.setTimeout(() => {
      void refreshQuota();
    }, 0);

    return () => {
      window.clearTimeout(timer);
    };
  }, [pathname, refreshQuota]);

  useEffect(() => {
    return subscribeQuotaRefresh(() => {
      void refreshQuota();
    });
  }, [refreshQuota]);

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const checkout = params.get("checkout");
    const sessionId = params.get("session_id");

    if (!checkout) {
      return;
    }

    if (checkout === "cancelled") {
      const timer = window.setTimeout(() => {
        setBanner("Checkout was cancelled.");
      }, 0);
      router.replace(stripCheckoutParams(pathname, params), {
        scroll: false,
      });
      return () => {
        window.clearTimeout(timer);
      };
    }

    if (checkout !== "success" || !sessionId || status !== "signed-in") {
      return;
    }

    let cancelled = false;

    const confirmCheckout = async () => {
      try {
        await ensureServerSession();
        await fetchJson<{ ok: true }>("/api/billing/confirm", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({ sessionId }),
        });
        const payload = await fetchJson<{ quota: ScanQuotaSummary }>("/api/me/usage");
        if (!cancelled) {
          setQuota(payload.quota);
          setBanner("Scan credits are now active on your account.");
        }
      } catch (error) {
        if (!cancelled) {
          setBanner(error instanceof Error ? error.message : "Unable to confirm payment.");
        }
      } finally {
        if (!cancelled) {
          router.replace(stripCheckoutParams(pathname, params), { scroll: false });
        }
      }
    };

    void confirmCheckout();

    return () => {
      cancelled = true;
    };
  }, [ensureServerSession, pathname, router, status]);

  useEffect(() => {
    const handlePointerDown = (event: MouseEvent) => {
      if (!panelRef.current?.contains(event.target as Node)) {
        setAccountOpen(false);
      }
    };

    document.addEventListener("mousedown", handlePointerDown);
    return () => {
      document.removeEventListener("mousedown", handlePointerDown);
    };
  }, []);

  const handleUpgrade = async () => {
    setActionError(null);

    if (!isConfigured) {
      setActionError("Google login must be configured before billing can start.");
      return;
    }

    setActionPending(true);
    try {
      if (status === "signed-in" && user) {
        await ensureServerSession();
      } else {
        await signInWithGoogle();
      }

      setPaypalOpen(true);
    } catch (error) {
      setActionError(error instanceof Error ? error.message : "Unable to start checkout.");
    } finally {
      setActionPending(false);
    }
  };

  return (
    <header className="fixed top-0 z-50 w-full border-b border-white/20 bg-white/72 shadow-[0_8px_30px_rgb(0_0_0_/_0.04)] backdrop-blur-[30px]">
      <div
        ref={panelRef}
        className={cn(
          "mx-auto flex h-16 w-full items-center justify-between gap-4",
          isWorkspacePage
            ? "max-w-[1440px] px-4 md:px-6 xl:px-0"
            : "max-w-[1280px] px-4 md:px-8",
        )}
      >
        <div className="flex items-center gap-8">
          <Link href="/" className="text-[2rem] font-semibold tracking-tight text-slate-900">
            CyberAudit
          </Link>

          <nav className="hidden items-center gap-6 md:flex">
            <Link
              href="/"
              className={cn(
                "border-b-2 pb-1 text-sm tracking-tight transition-colors",
                pathname === "/"
                  ? "border-[var(--primary)] text-[var(--primary)]"
                  : "border-transparent text-slate-500 hover:text-slate-900",
              )}
            >
              Home
            </Link>
            <Link
              href="/history"
              className={cn(
                "border-b-2 pb-1 text-sm tracking-tight transition-colors",
                pathname.startsWith("/history")
                  ? "border-[var(--primary)] text-[var(--primary)]"
                  : "border-transparent text-slate-500 hover:text-slate-900",
              )}
            >
              Scans
            </Link>
          </nav>
        </div>

        <div
          id="global-scan-launcher"
          className="relative hidden min-w-0 max-w-[460px] flex-1 px-4 lg:block xl:max-w-[520px]"
        >
          <StartAuditForm variant="header" />
        </div>

        <div className="flex items-center gap-3">
          <div className="relative">
            <button
              type="button"
              onClick={() => {
                setAccountOpen((current) => !current);
              }}
              className="rounded-full p-2 text-slate-600 transition-all hover:bg-white/20"
            >
              <UserCircle2 className="h-5 w-5" />
            </button>

            {accountOpen ? (
              <div className="absolute right-0 top-12 w-[340px] rounded-[1.5rem] border border-white/70 bg-white/95 p-4 shadow-[0_20px_60px_rgba(15,23,42,0.12)]">
                {status === "signed-in" && user ? (
                  <>
                    <div className="flex items-start justify-between gap-3">
                      <div>
                        <p className="text-sm font-semibold text-slate-900">
                          {user.displayName ?? user.email ?? "Signed in"}
                        </p>
                        <p className="mt-1 text-xs text-slate-500">{user.email ?? "Google account"}</p>
                      </div>
                      <button
                        type="button"
                        onClick={() => router.push("/history")}
                        className="rounded-full border border-slate-200 px-3 py-1.5 text-xs font-semibold text-slate-700 transition-colors hover:bg-slate-50"
                      >
                        Scans
                      </button>
                    </div>

                    <div className="mt-4 rounded-[1.25rem] bg-slate-50 p-4">
                      <p className="text-[11px] font-bold uppercase tracking-[0.18em] text-slate-400">
                        Scan credits
                      </p>
                      <p className="mt-2 text-sm text-slate-900">
                        {quota?.hasUnlimitedPlan
                          ? "High-volume scans are active."
                          : quota
                            ? `${quota.remainingScans} scans remaining.`
                            : "Loading your quota..."}
                      </p>
                      <p className="mt-1 text-xs text-slate-500">
                        {quota?.hasUnlimitedPlan
                          ? "Your account can keep launching scans without the standard cap."
                          : `3 free scans are included. Add ${quota?.upgradeScanCredits ?? 20} more credits for $${(quota?.upgradePriceUsd ?? 10).toFixed(2)}.`}
                      </p>
                    </div>

                    {!quota?.hasUnlimitedPlan ? (
                      <Button
                        variant="outline"
                        size="sm"
                        className="mt-4 w-full"
                        disabled={actionPending}
                        onClick={() => void handleUpgrade()}
                      >
                        {actionPending ? (
                          <>
                            <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                            Opening checkout...
                          </>
                        ) : (
                          <>
                            Buy {quota?.upgradeScanCredits ?? 20} credits for ${(quota?.upgradePriceUsd ?? 10).toFixed(2)}
                            <ExternalLink className="ml-2 h-4 w-4" />
                          </>
                        )}
                      </Button>
                    ) : null}
                  </>
                ) : (
                  <div className="space-y-3">
                    <p className="text-sm font-semibold text-slate-900">Google account required</p>
                    <p className="text-sm leading-6 text-slate-500">
                      Sign in to save history, unlock fixes, and keep scan credits tied to your email.
                    </p>
                    <Button
                      size="sm"
                      className="w-full"
                      disabled={!isConfigured || actionPending}
                      onClick={() => void signInWithGoogle()}
                    >
                      Sign in
                    </Button>
                  </div>
                )}
              </div>
            ) : null}
          </div>

          {status === "signed-in" ? (
            <>
              <div className="hidden rounded-full border border-white/70 bg-white/70 px-3 py-2 text-xs font-semibold text-slate-700 shadow-sm sm:block">
                {quota
                  ? quota.hasUnlimitedPlan
                    ? "Scans: unlimited"
                    : `Scans: ${quota.remainingScans}`
                  : "Scans: ..."}
              </div>
              <Button variant="outline" size="sm" onClick={() => void signOut()}>
                Log out
              </Button>
            </>
          ) : (
            <Button
              size="sm"
              disabled={!isConfigured || actionPending}
              onClick={() => void signInWithGoogle()}
            >
              Sign in
            </Button>
          )}
        </div>
      </div>

      {banner || actionError ? (
        <div className="border-t border-white/30 bg-white/80">
          <div
            className={cn(
              "mx-auto flex w-full items-center gap-2 px-4 py-2 text-sm",
              isWorkspacePage
                ? "max-w-[1440px] md:px-6 xl:px-0"
                : "max-w-[1280px] md:px-8",
            )}
          >
            <Clock3 className="h-4 w-4 text-[var(--primary)]" />
            <span className={actionError ? "text-[var(--danger)]" : "text-slate-600"}>
              {actionError ?? banner}
            </span>
          </div>
        </div>
      ) : null}
      <PaypalCreditsDialog
        open={paypalOpen}
        quota={quota}
        onClose={() => setPaypalOpen(false)}
        onApproved={(nextQuota) => {
          setQuota(nextQuota);
          setPaypalOpen(false);
          dispatchQuotaRefresh();
          setBanner("Credits were added to your account.");
        }}
      />
    </header>
  );
}
