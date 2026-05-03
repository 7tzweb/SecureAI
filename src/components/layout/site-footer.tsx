import Link from "next/link";
import { footerSections, pagesBySection } from "@/lib/marketing-pages";

function LinkedInIcon() {
  return (
    <svg className="h-5 w-5 fill-current" viewBox="0 0 24 24" aria-hidden="true">
      <path d="M19 0h-14c-2.761 0-5 2.239-5 5v14c0 2.761 2.239 5 5 5h14c2.762 0 5-2.239 5-5v-14c0-2.761-2.238-5-5-5zm-11 19h-3v-11h3v11zm-1.5-12.268c-.966 0-1.75-.79-1.75-1.764s.784-1.764 1.75-1.764 1.75.79 1.75 1.764-.783 1.764-1.75 1.764zm13.5 12.268h-3v-5.604c0-3.368-4-3.113-4 0v5.604h-3v-11h3v1.765c1.396-2.586 7-2.777 7 2.476v6.759z" />
    </svg>
  );
}

function XIcon() {
  return (
    <svg className="h-5 w-5 fill-current" viewBox="0 0 24 24" aria-hidden="true">
      <path d="M18.244 2.25h3.308l-7.227 8.26 8.502 11.24H16.17l-5.214-6.817L4.99 21.75H1.68l7.73-8.835L1.254 2.25H8.08l4.713 6.231zm-1.161 17.52h1.833L7.084 4.126H5.117z" />
    </svg>
  );
}

function InstagramIcon() {
  return (
    <svg className="h-5 w-5 fill-current" viewBox="0 0 24 24" aria-hidden="true">
      <path d="M12 2.163c3.204 0 3.584.012 4.85.07 3.252.148 4.771 1.691 4.919 4.919.058 1.266.069 1.645.069 4.849 0 3.205-.012 3.584-.069 4.849-.149 3.225-1.664 4.771-4.919 4.919-1.266.058-1.644.07-4.85.07-3.204 0-3.584-.012-4.849-.07-3.26-.149-4.771-1.699-4.919-4.92-.058-1.265-.07-1.644-.07-4.849 0-3.204.013-3.583.07-4.849.149-3.227 1.664-4.771 4.919-4.919 1.266-.057 1.645-.069 4.849-.069zm0-2.163c-3.259 0-3.667.014-4.947.072-4.358.2-6.78 2.618-6.98 6.98-.059 1.281-.073 1.689-.073 4.948 0 3.259.014 3.668.072 4.948.2 4.358 2.618 6.78 6.98 6.98 1.281.058 1.689.072 4.948.072 3.259 0 3.668-.014 4.948-.072 4.354-.2 6.782-2.618 6.979-6.98.059-1.28.073-1.689.073-4.948 0-3.259-.014-3.667-.072-4.947-.196-4.354-2.617-6.78-6.979-6.98-1.281-.059-1.69-.073-4.949-.073zm0 5.838c-3.403 0-6.162 2.759-6.162 6.162s2.759 6.163 6.162 6.163 6.162-2.759 6.162-6.163-2.759-6.162-6.162-6.162zm0 10.162c-2.209 0-4-1.79-4-4 0-2.209 1.791-4 4-4s4 1.791 4 4c0 2.21-1.791 4-4 4zm6.406-11.845c-.796 0-1.441.645-1.441 1.44s.645 1.44 1.441 1.44c.795 0 1.439-.645 1.439-1.44s-.644-1.44-1.439-1.44z" />
    </svg>
  );
}

export function SiteFooter() {
  return (
    <footer className="w-full border-t border-[var(--line)] bg-white pt-20 pb-10">
      <div className="mx-auto w-full max-w-[1200px] px-6 md:px-8">
        <div className="mb-14">
          <h2 className="max-w-[760px] text-5xl font-semibold italic leading-[1.04] tracking-[-0.04em] text-[var(--ink)] md:text-6xl">
            Less structure,
            <br />
            more intelligence.
          </h2>
        </div>

        <nav
          aria-label="Footer navigation"
          className="mb-16 grid grid-cols-2 gap-x-6 gap-y-12 md:grid-cols-3 lg:grid-cols-6"
        >
          {footerSections.map((section) => (
            <div key={section}>
              <h3 className="mb-5 text-xs font-bold uppercase tracking-[0.18em] text-[var(--ink)]">
                {section}
              </h3>
              <ul className="space-y-3.5">
                {pagesBySection(section).map((page) => (
                  <li key={page.href}>
                    <Link
                      href={page.href}
                      className="text-sm leading-6 text-[var(--ink-muted)] transition-colors hover:text-[var(--primary)]"
                    >
                      {page.footerLabel}
                    </Link>
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </nav>

        <div className="flex flex-col items-center justify-between gap-6 border-t border-[var(--line)] py-8 md:flex-row">
          <div className="flex items-center gap-6">
            <a className="text-[var(--ink-muted)] transition-colors hover:text-[var(--primary)]" href="https://www.linkedin.com/" aria-label="LinkedIn">
              <LinkedInIcon />
            </a>
            <a className="text-[var(--ink-muted)] transition-colors hover:text-[var(--primary)]" href="https://x.com/" aria-label="X">
              <XIcon />
            </a>
            <a className="text-[var(--ink-muted)] transition-colors hover:text-[var(--primary)]" href="https://www.instagram.com/" aria-label="Instagram">
              <InstagramIcon />
            </a>
          </div>
          <div className="inline-flex items-center gap-2 rounded-full border border-[var(--line)] px-4 py-2 text-sm text-[var(--ink)]">
            <span aria-hidden="true">Language</span>
            <span className="font-semibold">English</span>
          </div>
        </div>

        <div className="flex flex-col items-center justify-between gap-4 pt-6 md:flex-row md:items-end">
          <div className="flex items-baseline gap-2">
            <span className="text-sm text-[var(--ink-muted)]">from</span>
            <span className="text-xl font-bold italic tracking-tight text-[var(--ink)]">Fixnx</span>
          </div>
          <p className="text-xs font-semibold italic text-[var(--ink-soft)]">
            © 2026 Fixnx, Inc.
          </p>
        </div>
      </div>
    </footer>
  );
}
