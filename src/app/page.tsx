import {
  Activity,
  CheckCircle2,
  ChevronRight,
  CircleCheckBig,
  SearchCode,
  ShieldCheck,
  Zap,
} from "lucide-react";
import { StartAuditForm } from "@/components/landing/start-audit-form";

const featureCards = [
  {
    icon: ShieldCheck,
    title: "Live Website Scan",
    description:
      "Live checks that find website risks, SEO issues, and performance problems in seconds.",
  },
  {
    icon: SearchCode,
    title: "Security Insights",
    description:
      "Clear analysis of headers, exposed risks, cookies, metadata, and heavy assets.",
  },
  {
    icon: Activity,
    title: "AI Risk Insights",
    description:
      "AI-powered context for security risks, SEO health, and speed bottlenecks.",
  },
];

export default function HomePage() {
  return (
    <div className="min-h-screen bg-[var(--page-bg)] text-[var(--ink)]">
      <main id="home" className="overflow-x-hidden">
        <section
          id="scan-launch"
          className="hero-gradient relative flex min-h-[820px] flex-col items-center justify-center px-5 pb-24 pt-32 text-center md:px-16"
        >
          <div className="w-full max-w-[800px]">
            <span className="mb-3 block text-xs font-semibold uppercase tracking-[0.24em] text-[var(--primary)]">
              AI WEBSITE SECURITY
            </span>
            <h1 className="mx-auto max-w-[760px] text-balance text-5xl font-semibold leading-[1.08] tracking-[-0.03em] text-[var(--ink)] md:text-6xl">
              Scan your website for security risks.
            </h1>
            <p className="mx-auto mb-12 mt-6 max-w-[600px] text-balance text-lg leading-8 text-[var(--ink-muted)]">
              AI-powered scans for security, SEO, and performance. See live findings and clear guidance to fix each issue.
            </p>

            <StartAuditForm variant="hero" />

            <div className="mt-12 flex flex-col items-center justify-center gap-4 text-[var(--ink-soft)] md:flex-row md:gap-8">
              <div className="flex items-center gap-2 text-sm">
                <CircleCheckBig className="h-4 w-4 text-[var(--primary)]" />
                <span>Safe security checks</span>
              </div>
              <div className="flex items-center gap-2 text-sm">
                <Zap className="h-4 w-4 text-[var(--primary)]" />
                <span>Live site analysis</span>
              </div>
            </div>
          </div>
        </section>

        <section id="features" className="mx-auto max-w-[1200px] px-6 py-16 md:px-8">
          <div className="grid grid-cols-1 gap-6 md:grid-cols-12">
            <div className="glass-panel group relative overflow-hidden rounded-[2rem] p-10 md:col-span-8">
              <div className="relative z-10">
                <span className="mb-3 block text-xs font-semibold uppercase tracking-[0.22em] text-[var(--primary)]">
                  Observability
                </span>
                <h3 className="text-3xl font-semibold tracking-[-0.02em] text-[var(--ink)]">
                  Live Website Scan
                </h3>
                <p className="mt-4 max-w-[420px] text-sm leading-7 text-[var(--ink-muted)]">
                  Live checks that find website risks, SEO issues, and performance problems in seconds.
                </p>
              </div>
              <div className="mt-12 flex justify-end">
                <div className="rounded-[2rem] bg-slate-900/95 p-6 text-left text-white shadow-2xl transition-transform duration-700 group-hover:scale-[1.02]">
                  <div className="mb-4 flex items-center justify-between text-sm text-white/70">
                    <span>Live report</span>
                    <span>72%</span>
                  </div>
                  <div className="space-y-3">
                    {[
                      { label: "Security", value: "92" },
                      { label: "SEO", value: "81" },
                      { label: "Performance", value: "76" },
                    ].map((item) => (
                      <div key={item.label} className="rounded-2xl bg-white/10 px-4 py-3">
                        <div className="flex items-center justify-between">
                          <span className="text-sm font-medium">{item.label}</span>
                          <span className="text-xl font-semibold">{item.value}</span>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </div>

            <div className="glass-panel rounded-[2rem] p-8 md:col-span-4">
              <SearchCode className="mb-8 h-10 w-10 text-[var(--primary)]" />
              <h3 className="text-2xl font-semibold tracking-[-0.02em] text-slate-950">100+ checks in seconds</h3>
              <p className="mt-3 text-sm leading-7 text-slate-600">
                fixnx runs more than 100 website checks in seconds across security, SEO, speed, headers, cookies, metadata, and heavy assets.
              </p>
              <button className="mt-10 rounded-full bg-[var(--primary)] px-5 py-3 text-sm font-semibold !text-white shadow-sm transition-all hover:bg-[#004ca1]">
                Run site checks
              </button>
            </div>

            <div className="glass-panel rounded-[2rem] p-8 text-center md:col-span-5">
              <div className="relative mx-auto mb-6 flex h-32 w-32 items-center justify-center rounded-full bg-[var(--surface-muted)]">
                <svg className="absolute inset-0 h-full w-full -rotate-90" viewBox="0 0 128 128">
                  <circle cx="64" cy="64" r="56" fill="transparent" stroke="rgba(193,198,215,0.7)" strokeWidth="8" />
                  <circle
                    cx="64"
                    cy="64"
                    r="56"
                    fill="transparent"
                    stroke="var(--primary)"
                    strokeDasharray="351.86"
                    strokeDashoffset="10"
                    strokeWidth="8"
                  />
                </svg>
                <span className="relative z-10 text-4xl font-semibold text-[var(--primary)]">98</span>
              </div>
              <h3 className="text-2xl font-semibold tracking-[-0.02em] text-[var(--ink)]">
                Website Health Score
              </h3>
              <p className="mt-3 text-sm leading-7 text-[var(--ink-muted)]">
                Clear scores based on security, SEO, speed, headers, and website structure checks.
              </p>
            </div>

            <div className="glass-panel overflow-hidden rounded-[2rem] md:col-span-7">
              <div className="grid min-h-[260px] md:grid-cols-2">
                <div className="p-8">
                  <h3 className="text-2xl font-semibold tracking-[-0.02em] text-[var(--ink)]">
                    AI Website Analysis
                  </h3>
                  <ul className="mt-6 space-y-4 text-sm leading-7 text-[var(--ink-muted)]">
                    {[
                      "AI checks for public security risks",
                      "Security, SEO, and speed in one scan",
                      "Clear fix guidance after sign-in",
                    ].map((item) => (
                      <li key={item} className="flex items-center gap-3">
                        <CheckCircle2 className="h-4 w-4 text-[var(--primary)]" />
                        <span>{item}</span>
                      </li>
                    ))}
                  </ul>
                </div>
                <div className="bg-[var(--surface-muted)] p-8">
                  <div className="flex h-full min-h-[180px] flex-col justify-between rounded-[1.5rem] bg-white/70 p-6 shadow-[0_8px_32px_rgba(0,0,0,0.03)]">
                    <div className="space-y-3">
                      {featureCards.map(({ icon: Icon, title, description }) => (
                        <div key={title} className="rounded-2xl bg-[var(--surface-muted)] p-4">
                          <div className="flex items-center gap-3">
                            <Icon className="h-5 w-5 text-[var(--primary)]" />
                            <span className="text-sm font-semibold text-[var(--ink)]">{title}</span>
                          </div>
                          <p className="mt-2 text-xs leading-6 text-[var(--ink-muted)]">{description}</p>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </section>

        <section
          id="threats-panel"
          className="mx-auto grid max-w-[1200px] grid-cols-2 gap-6 px-6 py-8 text-center md:grid-cols-4 md:px-8"
        >
          {[
            ["500K+", "CHECKS RUN"],
            ["FAST", "SCAN SPEED"],
            ["AI", "POWERED"],
            ["24/7", "SITE CHECKS"],
          ].map(([value, label]) => (
            <div key={label}>
              <div className="text-4xl font-semibold tracking-[-0.03em] text-[var(--primary)]">{value}</div>
              <div className="mt-2 text-xs font-semibold uppercase tracking-[0.22em] text-[var(--ink-soft)]">
                {label}
              </div>
            </div>
          ))}
        </section>

        <section className="mx-auto max-w-[1200px] px-6 py-20 md:px-8">
          <div className="glass-panel relative overflow-hidden rounded-[2rem] p-12 text-center">
            <div className="absolute inset-0 opacity-20">
              <div className="absolute inset-0 bg-[radial-gradient(circle_at_30%_20%,#0070eb,transparent_40%)]" />
              <div className="absolute inset-0 bg-[radial-gradient(circle_at_70%_80%,#6664e4,transparent_40%)]" />
            </div>
            <div className="relative z-10">
              <h2 className="text-4xl font-semibold tracking-[-0.03em] text-slate-950">Ready to scan your website?</h2>
              <p className="mx-auto mt-5 max-w-[600px] text-lg leading-8 text-slate-600">
                Run an AI-powered website scan, review live findings, and get clear guidance to fix each issue.
              </p>
              <div className="mt-8 flex flex-col items-center justify-center gap-4 sm:flex-row">
                <a
                  href="#home"
                  className="inline-flex items-center gap-2 rounded-full bg-[var(--primary)] px-6 py-3 text-sm font-semibold !text-white transition-all hover:bg-[#004ca1]"
                >
                  Scan Site
                  <ChevronRight className="h-4 w-4 text-white" />
                </a>
                <a
                  href="/history"
                  className="inline-flex items-center gap-2 rounded-full border border-slate-200 bg-white/80 px-6 py-3 text-sm font-semibold text-slate-700 shadow-sm backdrop-blur-md transition-all hover:bg-white"
                >
                  Open Scans
                </a>
              </div>
            </div>
          </div>
        </section>
      </main>
    </div>
  );
}
