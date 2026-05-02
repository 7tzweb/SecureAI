"use client";

import { useRouter } from "next/navigation";
import { useEffect, useState, useTransition } from "react";
import { ArrowRight, ExternalLink, Globe, KeyRound, Loader2 } from "lucide-react";
import { PaypalCreditsDialog } from "@/components/billing/paypal-credits-dialog";
import { useAuth } from "@/components/providers/auth-provider";
import { dispatchQuotaRefresh, subscribeQuotaRefresh } from "@/lib/quota-events";
import { type ScanQuotaSummary } from "@/lib/types";
import { cn } from "@/lib/utils";

type StartAuditFormProps = {
  variant?: "hero" | "inline" | "header";
  className?: string;
};

async function fetchJson<T>(url: string, init?: RequestInit) {
  const response = await fetch(url, { cache: "no-store", ...init });
  const payload = (await response.json().catch(() => null)) as
    | T
    | { error?: string; code?: string; details?: unknown }
    | null;

  if (!response.ok) {
    const message =
      payload && typeof payload === "object" && "error" in payload && typeof payload.error === "string"
        ? payload.error
        : "Request failed";

    throw Object.assign(new Error(message), {
      code:
        payload && typeof payload === "object" && "code" in payload ? payload.code : undefined,
      details:
        payload && typeof payload === "object" && "details" in payload ? payload.details : undefined,
    });
  }

  return payload as T;
}

export function StartAuditForm({ variant = "hero", className }: StartAuditFormProps) {
  const router = useRouter();
  const { user, status, isConfigured, signInWithGoogle, ensureServerSession } = useAuth();
  const [target, setTarget] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [errorCode, setErrorCode] = useState<string | null>(null);
  const [quota, setQuota] = useState<ScanQuotaSummary | null>(null);
  const [checkoutPending, setCheckoutPending] = useState(false);
  const [paypalOpen, setPaypalOpen] = useState(false);
  const [showAuthOptions, setShowAuthOptions] = useState(false);
  const [scanMode, setScanMode] = useState<"Fast" | "Deep" | "Authenticated">("Fast");
  const [authCookieHeader, setAuthCookieHeader] = useState("");
  const [secondaryAuthCookieHeader, setSecondaryAuthCookieHeader] = useState("");
  const [authUsername, setAuthUsername] = useState("");
  const [authPassword, setAuthPassword] = useState("");
  const [authRoleLabel, setAuthRoleLabel] = useState("");
  const [secondaryAuthUsername, setSecondaryAuthUsername] = useState("");
  const [secondaryAuthPassword, setSecondaryAuthPassword] = useState("");
  const [secondaryAuthRoleLabel, setSecondaryAuthRoleLabel] = useState("");
  const [isPending, startTransition] = useTransition();

  type FormError = Error & {
    code?: string;
    details?: unknown;
  };

  useEffect(() => {
    let cancelled = false;

    const loadQuota = async () => {
      if (status !== "signed-in" || !user) {
        if (!cancelled) {
          setQuota(null);
        }
        return;
      }

      try {
        await ensureServerSession();
        const payload = await fetchJson<{ quota: ScanQuotaSummary }>("/api/me/usage");
        if (!cancelled) {
          setQuota(payload.quota);
        }
      } catch {
        if (!cancelled) {
          setQuota(null);
        }
      }
    };

    void loadQuota();
    return () => {
      cancelled = true;
    };
  }, [ensureServerSession, status, user]);

  useEffect(() => {
    return subscribeQuotaRefresh(() => {
      if (status !== "signed-in" || !user) {
        setQuota(null);
        return;
      }

      void (async () => {
        try {
          await ensureServerSession();
          const payload = await fetchJson<{ quota: ScanQuotaSummary }>("/api/me/usage");
          setQuota(payload.quota);
        } catch {
          setQuota(null);
        }
      })();
    });
  }, [ensureServerSession, status, user]);

  const handleUpgrade = async () => {
    setError(null);
    setErrorCode(null);

    if (!isConfigured) {
      setError("Google login must be configured before billing can start.");
      return;
    }

    setCheckoutPending(true);
    try {
      if (status === "signed-in" && user) {
        await ensureServerSession();
      } else {
        await signInWithGoogle();
      }

      setPaypalOpen(true);
    } catch (nextError) {
      setError(nextError instanceof Error ? nextError.message : "Unable to start checkout.");
    } finally {
      setCheckoutPending(false);
    }
  };

  const handleSignInToContinue = async () => {
    setError(null);

    if (!isConfigured) {
      setError("Google login must be configured before more scans can start.");
      return;
    }

    setCheckoutPending(true);
    try {
      if (status === "signed-in" && user) {
        await ensureServerSession();
      } else {
        await signInWithGoogle();
      }

      setErrorCode(null);
      dispatchQuotaRefresh();
    } catch (nextError) {
      setError(nextError instanceof Error ? nextError.message : "Unable to sign in with Google.");
    } finally {
      setCheckoutPending(false);
    }
  };

  const handleSubmit = () => {
    const value = target.trim();
    if (!value) {
      setError("Enter a domain to start the scan.");
      setErrorCode(null);
      return;
    }

    setError(null);
    setErrorCode(null);

    startTransition(async () => {
      try {
        if (status === "signed-in" && user) {
          await ensureServerSession();
        }

        const payload = await fetchJson<{ scan: { id: string } }>("/api/scans", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            target: value,
            scanMode:
              scanMode === "Authenticated" ||
              authCookieHeader.trim() ||
              secondaryAuthCookieHeader.trim() ||
              authUsername.trim() ||
              secondaryAuthUsername.trim()
                ? "Authenticated"
                : scanMode,
            authCookieHeader: authCookieHeader.trim() || undefined,
            secondaryAuthCookieHeader: secondaryAuthCookieHeader.trim() || undefined,
            authUsername: authUsername.trim() || undefined,
            authPassword: authPassword.trim() || undefined,
            authRoleLabel: authRoleLabel.trim() || undefined,
            secondaryAuthUsername: secondaryAuthUsername.trim() || undefined,
            secondaryAuthPassword: secondaryAuthPassword.trim() || undefined,
            secondaryAuthRoleLabel: secondaryAuthRoleLabel.trim() || undefined,
          }),
        });

        if (status === "signed-in" && user) {
          dispatchQuotaRefresh();
        }
        router.push(`/scans/${payload.scan.id}`);
      } catch (nextError) {
        const resolvedError = nextError as FormError;
        const nextCode = typeof resolvedError.code === "string" ? resolvedError.code : null;
        setErrorCode(nextCode);

        if (resolvedError.code === "SCAN_QUOTA_EXCEEDED") {
          if (
            resolvedError.details &&
            typeof resolvedError.details === "object"
          ) {
            setQuota(resolvedError.details as ScanQuotaSummary);
            setPaypalOpen(true);
          }
        } else if (resolvedError.code === "ANONYMOUS_SCAN_QUOTA_EXCEEDED") {
          setQuota(null);
        }

        setError(nextError instanceof Error ? nextError.message : "Network error while creating the scan.");
      }
    });
  };

  const showAnonymousLimitCta = errorCode === "ANONYMOUS_SCAN_QUOTA_EXCEEDED";
  const showPaidQuotaCta = Boolean(quota?.requiresUpgrade || errorCode === "SCAN_QUOTA_EXCEEDED");

  return (
    <div className={cn("w-full", variant === "header" && "relative", className)}>
      <div
        className={cn(
          "glass-panel flex w-full flex-col gap-3 shadow-xl ring-1 ring-black/5 md:flex-row md:items-center",
          variant === "hero"
            ? "mx-auto max-w-[580px] rounded-[2rem] p-3 sm:p-2 md:rounded-full"
            : variant === "header"
              ? "rounded-full border border-white/60 bg-white/80 p-1.5 shadow-[0_10px_28px_rgba(15,23,42,0.08)]"
              : "rounded-[1.7rem] p-3",
        )}
      >
        <div
          className={cn(
            "flex items-center gap-4",
            variant === "hero"
              ? "min-w-0 flex-1 px-4 md:pl-6 md:pr-1"
              : variant === "header"
                ? "min-w-0 flex-1 px-4"
                : "px-4 py-1",
          )}
        >
          <Globe className="h-5 w-5 text-[var(--ink-soft)]" />
          <input
            value={target}
            onChange={(event) => setTarget(event.target.value)}
            placeholder="Enter your website URL"
            className={cn(
              "w-full bg-transparent text-sm text-[var(--ink)] outline-none placeholder:text-[var(--ink-soft)]",
              variant === "header" ? "h-10" : "h-12",
            )}
            onKeyDown={(event) => {
              if (event.key === "Enter") {
                event.preventDefault();
                handleSubmit();
              }
            }}
          />
        </div>
        <button
          type="button"
          className={cn(
            "inline-flex h-12 shrink-0 items-center justify-center gap-2 rounded-full bg-[var(--primary)] px-6 text-sm font-semibold !text-white transition-all hover:bg-[#004ca1] active:scale-[0.98]",
            variant === "hero"
              ? "w-full md:w-auto md:px-8"
              : variant === "header"
                ? "h-10 px-5 md:min-w-[140px]"
                : "md:min-w-[180px]",
          )}
          disabled={isPending || checkoutPending}
          onClick={handleSubmit}
        >
          {isPending ? "Creating scan..." : "Scan Site"}
          <ArrowRight className="h-4 w-4 text-white" />
        </button>
      </div>

      {variant !== "header" ? (
        <div className={cn("mt-3", variant === "hero" ? "mx-auto max-w-[580px]" : "")}>
          <button
            type="button"
            onClick={() => setShowAuthOptions((current) => !current)}
            className="inline-flex items-center gap-2 rounded-full border border-slate-200 bg-white/80 px-4 py-2 text-xs font-semibold text-slate-700 shadow-sm transition-colors hover:bg-white"
          >
            <KeyRound className="h-3.5 w-3.5 text-[var(--primary)]" />
            Authenticated scan
          </button>

          {showAuthOptions ? (
            <div className="mt-3 grid gap-3 rounded-[1.3rem] border border-white/70 bg-white/70 p-3 shadow-[0_12px_36px_rgba(15,23,42,0.08)]">
              <div className="grid gap-2 rounded-[1rem] bg-slate-50 p-1 sm:grid-cols-3">
                {(["Fast", "Deep", "Authenticated"] as const).map((mode) => (
                  <button
                    key={mode}
                    type="button"
                    onClick={() => setScanMode(mode)}
                    className={cn(
                      "rounded-[0.8rem] px-3 py-2 text-xs font-bold transition-colors",
                      scanMode === mode
                        ? "bg-white text-[var(--primary)] shadow-sm"
                        : "text-slate-500 hover:text-slate-900",
                    )}
                  >
                    {mode}
                  </button>
                ))}
              </div>
              <div className="grid gap-3 md:grid-cols-3">
                <input
                  value={authUsername}
                  onChange={(event) => setAuthUsername(event.target.value)}
                  placeholder="User A email / username"
                  className="h-11 rounded-[1rem] border border-slate-200 bg-white px-4 text-xs text-slate-700 outline-none transition-colors placeholder:text-slate-400 focus:border-[var(--primary)]"
                />
                <input
                  value={authPassword}
                  onChange={(event) => setAuthPassword(event.target.value)}
                  placeholder="User A password"
                  type="password"
                  className="h-11 rounded-[1rem] border border-slate-200 bg-white px-4 text-xs text-slate-700 outline-none transition-colors placeholder:text-slate-400 focus:border-[var(--primary)]"
                />
                <input
                  value={authRoleLabel}
                  onChange={(event) => setAuthRoleLabel(event.target.value)}
                  placeholder="User A role label"
                  className="h-11 rounded-[1rem] border border-slate-200 bg-white px-4 text-xs text-slate-700 outline-none transition-colors placeholder:text-slate-400 focus:border-[var(--primary)]"
                />
              </div>
              <textarea
                value={authCookieHeader}
                onChange={(event) => setAuthCookieHeader(event.target.value)}
                placeholder="User A cookie header"
                spellCheck={false}
                className="min-h-20 w-full resize-y rounded-[1rem] border border-slate-200 bg-white px-4 py-3 text-xs leading-5 text-slate-700 outline-none transition-colors placeholder:text-slate-400 focus:border-[var(--primary)]"
              />
              <div className="grid gap-3 md:grid-cols-3">
                <input
                  value={secondaryAuthUsername}
                  onChange={(event) => setSecondaryAuthUsername(event.target.value)}
                  placeholder="User B email / username"
                  className="h-11 rounded-[1rem] border border-slate-200 bg-white px-4 text-xs text-slate-700 outline-none transition-colors placeholder:text-slate-400 focus:border-[var(--primary)]"
                />
                <input
                  value={secondaryAuthPassword}
                  onChange={(event) => setSecondaryAuthPassword(event.target.value)}
                  placeholder="User B password"
                  type="password"
                  className="h-11 rounded-[1rem] border border-slate-200 bg-white px-4 text-xs text-slate-700 outline-none transition-colors placeholder:text-slate-400 focus:border-[var(--primary)]"
                />
                <input
                  value={secondaryAuthRoleLabel}
                  onChange={(event) => setSecondaryAuthRoleLabel(event.target.value)}
                  placeholder="User B role label"
                  className="h-11 rounded-[1rem] border border-slate-200 bg-white px-4 text-xs text-slate-700 outline-none transition-colors placeholder:text-slate-400 focus:border-[var(--primary)]"
                />
              </div>
              <textarea
                value={secondaryAuthCookieHeader}
                onChange={(event) => setSecondaryAuthCookieHeader(event.target.value)}
                placeholder="User B cookie header"
                spellCheck={false}
                className="min-h-20 w-full resize-y rounded-[1rem] border border-slate-200 bg-white px-4 py-3 text-xs leading-5 text-slate-700 outline-none transition-colors placeholder:text-slate-400 focus:border-[var(--primary)]"
              />
            </div>
          ) : null}
        </div>
      ) : null}

      {variant === "header" ? (
        error || quota?.requiresUpgrade ? (
          <div className="absolute left-0 top-[calc(100%+0.65rem)] z-50 w-full max-w-[520px] rounded-[1.2rem] border border-white/70 bg-white/95 p-4 shadow-[0_18px_48px_rgba(15,23,42,0.12)]">
            {error ? <p className="text-sm font-medium text-[var(--danger)]">{error}</p> : null}
            {quota?.requiresUpgrade ? (
              <div className={cn("flex flex-col gap-3", error ? "mt-3" : "")}>
                <p className="text-sm text-slate-600">
                  {quota.usedScans} of {quota.totalScanAllowance} available scans are already used on this Google account.
                </p>
                <button
                  type="button"
                  onClick={() => void handleUpgrade()}
                  disabled={checkoutPending}
                  className="inline-flex items-center gap-2 self-start rounded-full border border-slate-200 bg-white px-5 py-2.5 text-sm font-semibold text-slate-800 shadow-sm transition-colors hover:bg-slate-50 disabled:cursor-not-allowed disabled:opacity-60"
                >
                  {checkoutPending ? (
                    <>
                      <Loader2 className="h-4 w-4 animate-spin" />
                      Opening checkout...
                    </>
                  ) : (
                    <>
                      Buy {quota.upgradeScanCredits} credits for ${quota.upgradePriceUsd.toFixed(2)}
                      <ExternalLink className="h-4 w-4" />
                    </>
                  )}
                </button>
              </div>
            ) : null}
            {showAnonymousLimitCta ? (
              <button
                type="button"
                onClick={() => void handleSignInToContinue()}
                disabled={!isConfigured || checkoutPending}
                className="mt-3 inline-flex items-center gap-2 self-start rounded-full border border-slate-200 bg-white px-5 py-2.5 text-sm font-semibold text-slate-800 shadow-sm transition-colors hover:bg-slate-50 disabled:cursor-not-allowed disabled:opacity-60"
              >
                {checkoutPending ? (
                  <>
                    <Loader2 className="h-4 w-4 animate-spin" />
                    Opening Google...
                  </>
                ) : (
                  "Sign in with Google to continue"
                )}
              </button>
            ) : null}
          </div>
        ) : null
      ) : (
        <div className={cn("mt-4 flex flex-col gap-3", variant === "hero" ? "items-center" : "items-start")}>
          {quota ? (
            <p className="text-sm text-slate-500">
              {quota.hasUnlimitedPlan
                ? "High-volume scans are active on this account."
                : `${quota.remainingScans} scans remaining on this account.`}
            </p>
          ) : (
            <p className="text-sm text-slate-500">
              Scan now. Google sign-in is only needed to unlock fix guidance.
            </p>
          )}

          {error ? <p className="text-sm font-medium text-[var(--danger)]">{error}</p> : null}

          {showAnonymousLimitCta ? (
            <button
              type="button"
              onClick={() => void handleSignInToContinue()}
              disabled={!isConfigured || checkoutPending}
              className="inline-flex items-center gap-2 rounded-full border border-slate-200 bg-white px-5 py-2.5 text-sm font-semibold text-slate-800 shadow-sm transition-colors hover:bg-slate-50 disabled:cursor-not-allowed disabled:opacity-60"
            >
              {checkoutPending ? (
                <>
                  <Loader2 className="h-4 w-4 animate-spin" />
                  Opening Google...
                </>
              ) : (
                "Sign in with Google to continue"
              )}
            </button>
          ) : showPaidQuotaCta ? (
            <button
              type="button"
              onClick={() => void handleUpgrade()}
              disabled={checkoutPending}
              className="inline-flex items-center gap-2 rounded-full border border-slate-200 bg-white px-5 py-2.5 text-sm font-semibold text-slate-800 shadow-sm transition-colors hover:bg-slate-50 disabled:cursor-not-allowed disabled:opacity-60"
            >
              {checkoutPending ? (
                <>
                  <Loader2 className="h-4 w-4 animate-spin" />
                  Opening checkout...
                </>
              ) : (
                <>
                  Buy {quota?.upgradeScanCredits ?? 20} credits for ${(quota?.upgradePriceUsd ?? 10).toFixed(2)}
                  <ExternalLink className="h-4 w-4" />
                </>
              )}
            </button>
          ) : null}
        </div>
      )}
      <PaypalCreditsDialog
        open={paypalOpen}
        quota={quota}
        onClose={() => setPaypalOpen(false)}
        onApproved={(nextQuota) => {
          setQuota(nextQuota);
          setError(null);
          setPaypalOpen(false);
          dispatchQuotaRefresh();
        }}
      />
    </div>
  );
}
