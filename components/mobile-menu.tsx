"use client";

import { cn } from "@/lib/utils";
import * as Dialog from "@radix-ui/react-dialog";
import { Menu, X, BookOpen, MessageSquare } from "lucide-react";
import Link from "next/link";
import { useState } from "react";

interface MobileMenuProps {
  className?: string;
}

export const MobileMenu = ({ className }: MobileMenuProps) => {
  const [isOpen, setIsOpen] = useState(false);

  const menuItems = [
    { name: "Docs", href: "/docs", icon: BookOpen },
    { name: "Chats", href: "/chat", icon: MessageSquare },
    { name: "GitHub", href: "https://github.com", icon: null },
    { name: "Telegram", href: "https://telegram.org", icon: null },
    { name: "Contact", href: "#contact", icon: null },
  ];

  const handleLinkClick = () => {
    setIsOpen(false);
  };

  return (
    <Dialog.Root modal={false} open={isOpen} onOpenChange={setIsOpen}>
      <Dialog.Trigger asChild>
        <button
          className={cn(
            "group lg:hidden p-2 text-foreground transition-colors",
            className
          )}
          aria-label="Open menu"
        >
          <Menu className="group-[[data-state=open]]:hidden" size={24} />
          <X className="hidden group-[[data-state=open]]:block" size={24} />
        </button>
      </Dialog.Trigger>

      <Dialog.Portal>
        <div
          data-overlay="true"
          className="fixed z-30 inset-0 bg-black/50 backdrop-blur-sm"
        />

        <Dialog.Content
          onInteractOutside={(e) => {
            if (
              e.target instanceof HTMLElement &&
              e.target.dataset.overlay !== "true"
            ) {
              e.preventDefault();
            }
          }}
          className="fixed top-0 left-0 w-full z-40 py-20 sm:py-28 md:py-40"
        >
          <Dialog.Title className="sr-only">Menu</Dialog.Title>

          <nav className="flex flex-col space-y-6 container mx-auto">
            {menuItems.map((item) => {
              const Icon = item.icon;
              return (
                <Link
                  key={item.name}
                  href={item.href}
                  onClick={handleLinkClick}
                  className="flex items-center gap-3 text-xl font-mono uppercase text-blue-300 transition-colors ease-out duration-150 hover:text-blue-200 py-2"
                >
                  {Icon && <Icon className="w-5 h-5" />}
                  {item.name}
                </Link>
              );
            })}

            <div className="mt-6">
              <Link
                href="/#sign-in"
                onClick={handleLinkClick}
                className="inline-block text-xl font-mono uppercase text-primary transition-colors ease-out duration-150 hover:text-primary/80 py-2"
              >
                Sign In
              </Link>
            </div>
          </nav>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
};
