"use client";

import * as React from "react";
import { cn } from "@/lib/utils";

type ButtonVariant = "primary" | "secondary" | "outline" | "ghost" | "danger";
type ButtonSize = "sm" | "md" | "lg";

export interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant;
  size?: ButtonSize;
}

const variantClasses: Record<ButtonVariant, string> = {
  primary:
    "bg-[var(--primary)] text-white shadow-[0_18px_40px_rgba(22,103,217,0.24)] hover:bg-[#0f57ba]",
  secondary: "bg-slate-900 text-white hover:bg-slate-800",
  outline:
    "border border-[var(--line-strong)] bg-white text-[var(--ink)] hover:border-slate-400 hover:bg-slate-50",
  ghost: "bg-transparent text-[var(--ink)] hover:bg-white/70",
  danger: "bg-[var(--danger)] text-white hover:opacity-90",
};

const sizeClasses: Record<ButtonSize, string> = {
  sm: "h-10 px-4 text-sm",
  md: "h-12 px-5 text-sm font-semibold",
  lg: "h-14 px-6 text-base font-semibold",
};

export const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant = "primary", size = "md", type = "button", ...props }, ref) => (
    <button
      ref={ref}
      type={type}
      className={cn(
        "inline-flex items-center justify-center rounded-2xl transition-colors duration-200 disabled:cursor-not-allowed disabled:opacity-60",
        variantClasses[variant],
        sizeClasses[size],
        className,
      )}
      {...props}
    />
  ),
);

Button.displayName = "Button";
