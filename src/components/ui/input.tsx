import * as React from "react";
import { cn } from "@/lib/utils";

export type InputProps = React.InputHTMLAttributes<HTMLInputElement>;

export const Input = React.forwardRef<HTMLInputElement, InputProps>(({ className, ...props }, ref) => (
  <input
    ref={ref}
    className={cn(
      "h-14 w-full rounded-2xl border border-[var(--line)] bg-white px-4 text-base text-[var(--ink)] shadow-[inset_0_1px_0_rgba(255,255,255,0.4)] outline-none placeholder:text-[var(--ink-soft)] focus:border-sky-400 focus:ring-4 focus:ring-sky-100",
      className,
    )}
    {...props}
  />
));

Input.displayName = "Input";
