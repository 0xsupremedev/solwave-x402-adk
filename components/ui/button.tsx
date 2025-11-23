import * as React from "react"
import { Slot, Slottable } from "@radix-ui/react-slot"
import { cva, type VariantProps } from "class-variance-authority"

import { cn } from "@/lib/utils"

const buttonVariants = cva(
  "inline-flex relative font-mono cursor-pointer items-center font-medium justify-start gap-2 whitespace-normal sm:whitespace-nowrap ease-out transition-all duration-300 disabled:pointer-events-none disabled:opacity-50 [&_svg]:pointer-events-none [&_svg:not([class*='size-'])]:size-4 shrink-0 [&_svg]:shrink-0 outline-none focus-visible:ring-2 focus-visible:ring-blue-400/50 focus-visible:ring-offset-2 focus-visible:ring-offset-blue-950 rounded-full backdrop-blur-md border",
  {
    variants: {
      variant: {
        default: "bg-blue-950/40 border-blue-500/50 text-blue-200 hover:bg-blue-900/50 hover:border-blue-400/70 shadow-lg shadow-blue-500/10 hover:shadow-blue-500/20 [&_svg]:text-blue-300",
      },
      size: {
        default: "h-12 px-6 text-sm",
        sm: "h-10 px-4 text-xs",
        lg: "h-14 px-8 text-base",
      },
    },
    defaultVariants: {
      variant: "default",
      size: "default",
    },
  }
)

function Button({
  className,
  variant,
  size,
  children,
  asChild = false,
  ...props
}: React.ComponentProps<"button"> &
  VariantProps<typeof buttonVariants> & {
    asChild?: boolean
  }) {
  const Comp = asChild ? Slot : "button"

  return (
    <Comp
      data-slot="button"
      className={cn(buttonVariants({ variant, size, className }))}
      {...props}
    >
      {/* Soft neon glow effect */}
      <div className="absolute inset-0 rounded-full bg-gradient-to-r from-blue-500/0 via-blue-400/10 to-blue-500/0 opacity-0 hover:opacity-100 transition-opacity duration-300 pointer-events-none" />
      
      {/* Subtle inner shadow for depth */}
      <div className="absolute inset-[1px] rounded-full bg-gradient-to-b from-white/5 to-transparent pointer-events-none" />

      <Slottable>
        {children}
      </Slottable>
    </Comp>
  )
}

export { Button, buttonVariants }
