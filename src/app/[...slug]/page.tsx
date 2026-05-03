import type { Metadata } from "next";
import Link from "next/link";
import { notFound } from "next/navigation";
import { ArrowRight, CheckCircle2, ShieldCheck } from "lucide-react";
import { StartAuditForm } from "@/components/landing/start-audit-form";
import { marketingPages, pageBySlug, pagesBySection } from "@/lib/marketing-pages";

type PageParams = {
  slug: string[];
};

export function generateStaticParams() {
  return marketingPages.map((page) => ({
    slug: page.href.replace(/^\//, "").split("/"),
  }));
}

export async function generateMetadata({
  params,
}: {
  params: Promise<PageParams>;
}): Promise<Metadata> {
  const { slug } = await params;
  const page = pageBySlug(slug);

  if (!page) {
    return {};
  }

  return {
    title: page.metaTitle,
    description: page.metaDescription,
    alternates: {
      canonical: page.href,
    },
    openGraph: {
      title: page.metaTitle,
      description: page.metaDescription,
      url: page.href,
      type: "article",
      siteName: "fixnx",
    },
  };
}

function relatedPagesFor(pageHref: string, section: Parameters<typeof pagesBySection>[0]) {
  return pagesBySection(section)
    .filter((page) => page.href !== pageHref)
    .slice(0, 3);
}

export default async function MarketingPage({
  params,
}: {
  params: Promise<PageParams>;
}) {
  const { slug } = await params;
  const page = pageBySlug(slug);

  if (!page) {
    notFound();
  }

  const relatedPages = relatedPagesFor(page.href, page.section);

  return (
    <main className="min-h-screen bg-[var(--page-bg)] pt-24 text-[var(--ink)]">
      <section className="hero-gradient px-6 pb-16 pt-16 md:px-8 md:pb-20 md:pt-20">
        <div className="mx-auto grid max-w-[1200px] gap-10 lg:grid-cols-[1.05fr_0.95fr] lg:items-center">
          <div>
            <p className="text-xs font-bold uppercase tracking-[0.24em] text-[var(--primary)]">
              {page.kicker}
            </p>
            <h1 className="mt-5 max-w-[780px] text-balance text-5xl font-semibold leading-[1.06] tracking-[-0.04em] text-[var(--ink)] md:text-6xl">
              {page.title}
            </h1>
            <p className="mt-6 max-w-[680px] text-lg leading-8 text-[var(--ink-muted)]">
              {page.lead}
            </p>
            <div className="mt-8 flex flex-col gap-3 sm:flex-row">
              <Link
                href="/#scan-launch"
                className="inline-flex items-center justify-center gap-2 rounded-full bg-[var(--primary)] px-6 py-3 text-sm font-semibold text-white shadow-sm transition-colors hover:bg-[#004ca1]"
              >
                Run a scan
                <ArrowRight className="h-4 w-4" />
              </Link>
              <Link
                href="/history"
                className="inline-flex items-center justify-center rounded-full border border-[var(--line)] bg-white/75 px-6 py-3 text-sm font-semibold text-[var(--ink)] shadow-sm backdrop-blur-xl transition-colors hover:bg-white"
              >
                Open reports
              </Link>
            </div>
          </div>

          <div className="rounded-[2rem] border border-white/70 bg-white/70 p-5 shadow-[0_18px_60px_rgba(15,23,42,0.08)] backdrop-blur-2xl">
            <div className="rounded-[1.4rem] bg-slate-950 p-5 text-white">
              <div className="mb-5 flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <ShieldCheck className="h-5 w-5 text-blue-300" />
                  <span className="text-sm font-semibold">Fixnx report</span>
                </div>
                <span className="rounded-full bg-blue-500/15 px-3 py-1 text-xs font-bold text-blue-200">
                  Live scan
                </span>
              </div>
              <div className="space-y-3">
                {page.checks.slice(0, 5).map((check, index) => (
                  <div key={check} className="rounded-[1rem] bg-white/10 px-4 py-3">
                    <div className="flex items-center justify-between gap-4">
                      <span className="text-sm text-white/84">{check}</span>
                      <span className="text-xs font-bold uppercase text-blue-200">
                        {index < 2 ? "high" : "checked"}
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      </section>

      <section className="px-6 py-14 md:px-8">
        <div className="mx-auto grid max-w-[1200px] gap-10 lg:grid-cols-[0.8fr_1.2fr]">
          <aside className="space-y-6">
            <div>
              <h2 className="text-2xl font-semibold tracking-[-0.02em]">Best for</h2>
              <ul className="mt-5 space-y-3">
                {page.bestFor.map((item) => (
                  <li key={item} className="flex items-start gap-3 text-sm leading-7 text-[var(--ink-muted)]">
                    <CheckCircle2 className="mt-1 h-4 w-4 shrink-0 text-[var(--primary)]" />
                    <span>{item}</span>
                  </li>
                ))}
              </ul>
            </div>

            <div>
              <h2 className="text-2xl font-semibold tracking-[-0.02em]">Outcomes</h2>
              <ul className="mt-5 space-y-3">
                {page.outcomes.map((item) => (
                  <li key={item} className="flex items-start gap-3 text-sm leading-7 text-[var(--ink-muted)]">
                    <CheckCircle2 className="mt-1 h-4 w-4 shrink-0 text-[var(--success)]" />
                    <span>{item}</span>
                  </li>
                ))}
              </ul>
            </div>
          </aside>

          <article className="space-y-10">
            <section>
              <h2 className="text-3xl font-semibold tracking-[-0.03em]">
                What this page helps you understand
              </h2>
              <p className="mt-5 text-base leading-8 text-[var(--ink-muted)]">
                {page.intro}
              </p>
            </section>

            <section>
              <h2 className="text-3xl font-semibold tracking-[-0.03em]">
                What Fixnx checks
              </h2>
              <div className="mt-5 grid gap-3 sm:grid-cols-2">
                {page.checks.map((check) => (
                  <div key={check} className="rounded-[1rem] border border-[var(--line)] bg-white/70 px-4 py-3">
                    <p className="text-sm font-semibold text-[var(--ink)]">{check}</p>
                  </div>
                ))}
              </div>
            </section>

            <section>
              <h2 className="text-3xl font-semibold tracking-[-0.03em]">
                {page.articleTitle}
              </h2>
              <div className="mt-5 space-y-5 text-base leading-8 text-[var(--ink-muted)]">
                {page.article.map((paragraph) => (
                  <p key={paragraph}>{paragraph}</p>
                ))}
              </div>
            </section>

            <section className="rounded-[1.5rem] border border-[var(--line)] bg-white/70 p-6">
              <h2 className="text-2xl font-semibold tracking-[-0.02em]">
                Run this check on your site
              </h2>
              <p className="mt-3 text-sm leading-7 text-[var(--ink-muted)]">
                Enter a public URL and get a live Fixnx report with security, SEO, and performance checks.
              </p>
              <div className="mt-5">
                <StartAuditForm variant="inline" />
              </div>
            </section>

            <section>
              <h2 className="text-3xl font-semibold tracking-[-0.03em]">FAQ</h2>
              <div className="mt-5 divide-y divide-[var(--line)] rounded-[1.5rem] border border-[var(--line)] bg-white/70">
                {page.faq.map((item) => (
                  <div key={item.question} className="p-5">
                    <h3 className="text-base font-semibold text-[var(--ink)]">{item.question}</h3>
                    <p className="mt-2 text-sm leading-7 text-[var(--ink-muted)]">{item.answer}</p>
                  </div>
                ))}
              </div>
            </section>
          </article>
        </div>
      </section>

      {relatedPages.length > 0 ? (
        <section className="px-6 pb-20 md:px-8">
          <div className="mx-auto max-w-[1200px]">
            <h2 className="text-3xl font-semibold tracking-[-0.03em]">Related pages</h2>
            <div className="mt-6 grid gap-4 md:grid-cols-3">
              {relatedPages.map((related) => (
                <Link
                  key={related.href}
                  href={related.href}
                  className="rounded-[1.2rem] border border-[var(--line)] bg-white/70 p-5 transition-colors hover:border-blue-200 hover:bg-white"
                >
                  <p className="text-sm font-bold uppercase tracking-[0.16em] text-[var(--primary)]">
                    {related.section}
                  </p>
                  <h3 className="mt-3 text-xl font-semibold tracking-[-0.02em]">{related.title}</h3>
                  <p className="mt-3 text-sm leading-7 text-[var(--ink-muted)]">{related.lead}</p>
                </Link>
              ))}
            </div>
          </div>
        </section>
      ) : null}
    </main>
  );
}
