"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import {
  Clock3,
  FolderClock,
  History,
  Shield,
} from "lucide-react";
import { useAuth } from "@/components/providers/auth-provider";
import { type ScanRecord } from "@/lib/types";
import { formatDateTime, formatRelative, formatScore } from "@/lib/utils";

export function HistoryClient() {
  const router = useRouter();
  const { user, isConfigured, signInWithGoogle, status } = useAuth();
  const [scans, setScans] = useState<ScanRecord[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    let cancelled = false;

    const loadHistory = async () => {
      if (!user) {
        if (!cancelled) {
          setScans([]);
        }
        return;
      }

      if (!cancelled) {
        setLoading(true);
        setError(null);
      }

      try {
        const response = await fetch("/api/me/scans", { cache: "no-store" });
        const payload = (await response.json().catch(() => null)) as
          | { scans?: ScanRecord[]; error?: string }
          | null;

        if (!response.ok) {
          throw new Error(payload?.error ?? "Unable to load scan history.");
        }

        if (!cancelled) {
          setScans(payload?.scans ?? []);
        }
      } catch (nextError) {
        if (!cancelled) {
          setError(nextError instanceof Error ? nextError.message : "Unable to load scan history.");
        }
      } finally {
        if (!cancelled) {
          setLoading(false);
        }
      }
    };

    void loadHistory();
    return () => {
      cancelled = true;
    };
  }, [user]);

  return (
    <div className="workspace-gradient min-h-screen text-[var(--ink)]">
      <div className="mx-auto flex max-w-[1440px] pt-16">
        <aside className="hidden h-[calc(100vh-64px)] w-72 shrink-0 border-r border-white/20 bg-white/40 px-6 py-8 shadow-[10px_0_40px_rgba(0,0,0,0.02)] backdrop-blur-[30px] lg:block">
          <div className="mb-8">
            <h3 className="text-lg font-black text-blue-600">CyberAudit</h3>
            <p className="mt-1 text-xs font-medium text-slate-500">Saved reports workspace</p>
          </div>
          <div className="space-y-2">
            <button
              type="button"
              onClick={() => router.push("/")}
              className="flex w-full items-center gap-3 rounded-full px-4 py-3 text-slate-600 transition-all hover:bg-white/40"
            >
              <Shield className="h-4 w-4" />
              <span className="text-sm font-medium">Dashboard</span>
            </button>
            <div className="flex items-center gap-3 rounded-full bg-blue-600 px-4 py-3 text-white shadow-[0_4px_12px_rgba(0,122,255,0.3)]">
              <History className="h-4 w-4" />
              <span className="text-sm font-semibold">History</span>
            </div>
          </div>
          <button
            type="button"
            onClick={() => router.push("/#scan-launch")}
            className="mt-8 w-full rounded-full bg-[var(--primary)] px-5 py-4 text-sm font-bold text-white shadow-lg shadow-[var(--primary)]/20 transition-all active:scale-[0.98]"
          >
            New Scan
          </button>
        </aside>

        <main className="min-w-0 flex-1 px-5 py-8 md:px-10 md:py-12">
          <div className="glass-panel rounded-[2rem] p-8">
            <p className="text-xs font-bold uppercase tracking-[0.22em] text-[var(--primary)]">
              Saved activity
            </p>
            <h1 className="mt-3 text-4xl font-semibold tracking-[-0.03em] text-slate-900">
              Scan history
            </h1>
            <p className="mt-3 max-w-[720px] text-sm leading-7 text-slate-500">
              Reopen previous scans, compare scores, and keep Google-linked reports attached to the account that claimed them.
            </p>
          </div>

          {!isConfigured ? (
            <div className="glass-panel mt-8 rounded-[2rem] p-8">
              <p className="text-sm font-semibold text-[var(--warning)]">
                Firebase is not configured yet.
              </p>
              <p className="mt-3 text-sm leading-7 text-slate-500">
                Add the Firebase client and Admin credentials from `.env.example` to enable Google login and persistent per-user history.
              </p>
            </div>
          ) : !user || status !== "signed-in" ? (
            <div className="glass-panel mt-8 rounded-[2rem] p-8">
              <p className="text-lg font-semibold text-slate-900">Sign in to access saved scans.</p>
              <p className="mt-3 text-sm leading-7 text-slate-500">
                Anonymous users can only see the current live report. Persistent history requires a verified Google session.
              </p>
              <button
                type="button"
                onClick={() => void signInWithGoogle()}
                className="mt-6 rounded-full bg-[var(--primary)] px-6 py-3 text-sm font-semibold text-white transition-all hover:bg-[#004ca1]"
              >
                Continue with Google
              </button>
            </div>
          ) : (
            <div className="mt-8">
              {error ? <p className="mb-4 text-sm font-medium text-[var(--danger)]">{error}</p> : null}
              {loading ? (
                <div className="space-y-4">
                  <div className="h-28 animate-pulse rounded-[2rem] bg-white/60" />
                  <div className="h-28 animate-pulse rounded-[2rem] bg-white/60" />
                </div>
              ) : scans.length ? (
                <div className="space-y-4">
                  {scans.map((scan) => (
                    <button
                      key={scan.id}
                      type="button"
                      onClick={() => router.push(`/scans/${scan.id}`)}
                      className="glass-panel flex w-full flex-col gap-4 rounded-[2rem] p-6 text-left transition-all hover:shadow-[0_12px_40px_rgba(0,0,0,0.05)] md:flex-row md:items-center md:justify-between"
                    >
                      <div>
                        <div className="flex items-center gap-3">
                          <FolderClock className="h-5 w-5 text-[var(--primary)]" />
                          <h2 className="text-xl font-semibold tracking-[-0.02em] text-slate-900">
                            {scan.targetHostname}
                          </h2>
                        </div>
                        <div className="mt-3 flex flex-wrap items-center gap-4 text-sm text-slate-500">
                          <span className="inline-flex items-center gap-2">
                            <Clock3 className="h-4 w-4" />
                            {formatDateTime(scan.createdAt)}
                          </span>
                          <span className="capitalize">{scan.status}</span>
                          <span>{scan.isAnonymous ? "Link-only report" : "Saved to account"}</span>
                          <span>Updated {formatRelative(scan.updatedAt)}</span>
                        </div>
                      </div>
                      <div className="flex items-center gap-6">
                        <div className="text-right">
                          <p className="text-xs font-bold uppercase tracking-[0.18em] text-slate-400">
                            Overall score
                          </p>
                          <p className="mt-1 text-3xl font-semibold text-slate-900">
                            {formatScore(scan.overallScore)}
                          </p>
                        </div>
                        <span className="rounded-full bg-white px-5 py-2.5 text-sm font-semibold text-[var(--primary)] shadow-sm">
                          Open report
                        </span>
                      </div>
                    </button>
                  ))}
                </div>
              ) : (
                <div className="glass-panel rounded-[2rem] p-8">
                  <p className="text-lg font-semibold text-slate-900">No saved scans yet.</p>
                  <p className="mt-3 text-sm leading-7 text-slate-500">
                    Once you claim or start authenticated scans, they will appear here for quick reopening.
                  </p>
                </div>
              )}
            </div>
          )}
        </main>
      </div>
    </div>
  );
}
