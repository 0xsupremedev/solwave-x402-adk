import Link from "next/link";
import { Logo } from "./logo";
import { MobileMenu } from "./mobile-menu";
import { BookOpen, MessageSquare } from "lucide-react";

export const Header = () => {
  const navItems = [
    { name: "Docs", href: "/docs", icon: BookOpen },
    { name: "Chats", href: "/chat", icon: MessageSquare },
  ];

  return (
    <div className="fixed z-50 pt-4 sm:pt-8 md:pt-14 top-0 left-0 w-full">
      <header className="flex items-center justify-between container">
        <Link href="/">
          <Logo className="w-[110px] sm:w-[140px] md:w-[160px]" />
        </Link>
        <nav className="flex max-lg:hidden absolute left-1/2 -translate-x-1/2 items-center justify-center gap-x-10">
          {navItems.map((item) => {
            const Icon = item.icon;
            return (
              <Link
                className="flex items-center gap-2 uppercase font-mono text-blue-300 hover:text-blue-200 duration-150 transition-colors ease-out"
                href={item.href}
                key={item.name}
              >
                <Icon className="w-4 h-4" />
                {item.name}
              </Link>
            );
          })}
          {["GitHub", "Telegram", "Contact"].map((item) => (
            <Link
              className="uppercase inline-block font-mono text-blue-300 hover:text-blue-200 duration-150 transition-colors ease-out"
              href={item === "GitHub" ? "https://github.com" : item === "Telegram" ? "https://telegram.org" : `#${item.toLowerCase()}`}
              key={item}
            >
              {item}
            </Link>
          ))}
        </nav>
        <Link className="uppercase max-lg:hidden transition-colors ease-out duration-150 font-mono text-primary hover:text-primary/80" href="/#sign-in">
          Sign In
        </Link>
        <MobileMenu />
      </header>
    </div>
  );
};
