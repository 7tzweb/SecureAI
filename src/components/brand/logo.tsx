import Link from "next/link";
import { cn } from "@/lib/utils";

export function Logo({ className }: { className?: string }) {
  return (
    <Link href="/" className={cn("inline-flex items-center gap-3", className)}>
      <span className="relative inline-flex h-11 w-11 items-center justify-center rounded-2xl bg-[linear-gradient(135deg,#0f1b2c,#1667d9)] text-white shadow-[0_16px_40px_rgba(15,27,44,0.22)]">
        <span className="absolute inset-[2px] rounded-[0.95rem] border border-white/15" />
        <span className="display-heading relative text-lg font-bold tracking-tight">fx</span>
      </span>
      <span className="flex flex-col leading-none">
        <span className="display-heading text-lg font-bold tracking-tight text-[var(--ink)]">
          fixnx
        </span>
        <span className="text-xs font-medium text-[var(--ink-soft)]">
          Security, SEO and performance
        </span>
      </span>
    </Link>
  );
}
