import { cn } from "@/lib/utils";

interface ProgressBarProps {
  value: number;
  className?: string;
}

export function ProgressBar({ value, className }: ProgressBarProps) {
  return (
    <div className={cn("h-3 w-full overflow-hidden rounded-full bg-slate-200/80", className)}>
      <div
        className="h-full rounded-full bg-[linear-gradient(90deg,#1667d9,#64a7ff)] transition-all duration-500"
        style={{ width: `${Math.max(0, Math.min(value, 100))}%` }}
      />
    </div>
  );
}
