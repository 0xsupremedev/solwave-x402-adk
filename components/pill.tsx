import { cn } from "@/lib/utils";
import { px } from "./utils";

export const Pill = ({ children, className }: { children: React.ReactNode, className?: string }) => {
  const polyRoundness = 6
  const hypotenuse = polyRoundness * 2
  const hypotenuseHalf = polyRoundness / 2 - 1.5

  // Check if custom colors are provided via className
  const hasCustomColors = className?.includes('bg-') || className?.includes('border-') || className?.includes('text-');
  const defaultBg = hasCustomColors ? '' : 'bg-[#262626]/50';
  const defaultBorder = hasCustomColors ? '' : 'border-border';
  const defaultText = hasCustomColors ? '' : 'text-foreground/50';
  const defaultDot = hasCustomColors ? '' : 'bg-primary';

  return (
    <div
      style={{
        "--poly-roundness": px(polyRoundness),
      } as React.CSSProperties}
      className={cn("transform-gpu font-medium backdrop-blur-xs font-mono text-sm inline-flex items-center justify-center px-3 h-8 border [clip-path:polygon(var(--poly-roundness)_0,calc(100%_-_var(--poly-roundness))_0,100%_var(--poly-roundness),100%_calc(100%_-_var(--poly-roundness)),calc(100%_-_var(--poly-roundness))_100%,var(--poly-roundness)_100%,0_calc(100%_-_var(--poly-roundness)),0_var(--poly-roundness))]", defaultBg, defaultBorder, defaultText, className)}
    >
      <span style={{ "--h": px(hypotenuse), "--hh": px(hypotenuseHalf) } as React.CSSProperties} className={cn("absolute inline-block w-[var(--h)] top-[var(--hh)] left-[var(--hh)] h-[2px] -rotate-45 origin-top -translate-x-1/2", hasCustomColors ? "bg-current opacity-50" : "bg-border")} />
      <span style={{ "--h": px(hypotenuse), "--hh": px(hypotenuseHalf) } as React.CSSProperties} className={cn("absolute w-[var(--h)] top-[var(--hh)] right-[var(--hh)] h-[2px] rotate-45 translate-x-1/2", hasCustomColors ? "bg-current opacity-50" : "bg-border")} />
      <span style={{ "--h": px(hypotenuse), "--hh": px(hypotenuseHalf) } as React.CSSProperties} className={cn("absolute w-[var(--h)] bottom-[var(--hh)] left-[var(--hh)] h-[2px] rotate-45 -translate-x-1/2", hasCustomColors ? "bg-current opacity-50" : "bg-border")} />
      <span style={{ "--h": px(hypotenuse), "--hh": px(hypotenuseHalf) } as React.CSSProperties} className={cn("absolute w-[var(--h)] bottom-[var(--hh)] right-[var(--hh)] h-[2px] -rotate-45 translate-x-1/2", hasCustomColors ? "bg-current opacity-50" : "bg-border")} />

      <span className={cn("inline-block size-2.5 rounded-full mr-2 shadow-glow", defaultDot, hasCustomColors ? "shadow-current/50" : "shadow-primary/50")} />

      {children}
    </div>
  );
};
