"use client";

import Link from "next/link";
import { 
  BookOpen, 
  Github, 
  MessageSquare, 
  Twitter, 
  Linkedin, 
  Youtube,
  FileText,
  Code,
  Rocket,
  MessageCircle
} from "lucide-react";

export function Footer() {
  const links = {
    product: [
      { name: "Documentation", href: "/docs", icon: BookOpen },
      { name: "GitHub", href: "https://github.com", icon: Github },
      { name: "Features", href: "/#features", icon: Rocket },
    ],
    resources: [
      { name: "API Reference", href: "/docs", icon: Code },
      { name: "Quickstart Guide", href: "/docs/quickstart", icon: Rocket },
      { name: "Examples", href: "/docs", icon: FileText },
    ],
    legal: [
      { name: "Privacy Policy", href: "/privacy" },
      { name: "Terms of Service", href: "/terms" },
      { name: "Cookie Policy", href: "/cookies" },
    ],
    community: [
      { name: "Discord", href: "https://discord.gg", icon: MessageCircle },
      { name: "Telegram", href: "https://telegram.org", icon: MessageSquare },
      { name: "GitHub Discussions", href: "https://github.com", icon: Github },
    ],
  };

  const socialLinks = [
    { name: "GitHub", href: "https://github.com", icon: Github },
    { name: "Twitter", href: "https://twitter.com", icon: Twitter },
    { name: "LinkedIn", href: "https://linkedin.com", icon: Linkedin },
    { name: "Discord", href: "https://discord.gg", icon: MessageCircle },
    { name: "Telegram", href: "https://telegram.org", icon: MessageSquare },
    { name: "YouTube", href: "https://youtube.com", icon: Youtube },
  ];

  return (
    <footer className="relative z-10 py-12 sm:py-16 container">
      {/* Main Footer Content */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-8 sm:gap-12 mb-8 sm:mb-12">
        {/* Brand Section */}
        <div className="sm:col-span-2 lg:col-span-1">
          <h3 className="font-sentient text-xl sm:text-2xl mb-3 sm:mb-4 text-white">SolWave</h3>
          <p className="font-mono text-xs sm:text-sm text-blue-200 mb-4">
            Autonomous Payments for the Next Internet.
          </p>
        </div>

        {/* Product Section */}
        <div>
          <h4 className="font-mono uppercase text-xs sm:text-sm mb-4 text-blue-100 font-semibold">Product</h4>
          <ul className="space-y-2">
            {links.product.map((link) => {
              const Icon = link.icon;
              return (
                <li key={link.name}>
                  <Link
                    href={link.href}
                    className="font-mono text-xs sm:text-sm text-blue-200 hover:text-blue-100 transition-colors flex items-center gap-2"
                  >
                    {Icon && <Icon className="w-3 h-3 sm:w-4 sm:h-4 text-blue-300" />}
                    {link.name}
                  </Link>
                </li>
              );
            })}
          </ul>
        </div>

        {/* Resources Section */}
        <div>
          <h4 className="font-mono uppercase text-xs sm:text-sm mb-4 text-blue-100 font-semibold">Resources</h4>
          <ul className="space-y-2">
            {links.resources.map((link) => {
              const Icon = link.icon;
              return (
                <li key={link.name}>
                  <Link
                    href={link.href}
                    className="font-mono text-xs sm:text-sm text-blue-200 hover:text-blue-100 transition-colors flex items-center gap-2"
                  >
                    {Icon && <Icon className="w-3 h-3 sm:w-4 sm:h-4 text-blue-300" />}
                    {link.name}
                  </Link>
                </li>
              );
            })}
          </ul>
        </div>

        {/* Legal Section */}
        <div>
          <h4 className="font-mono uppercase text-xs sm:text-sm mb-4 text-blue-100 font-semibold">Legal</h4>
          <ul className="space-y-2">
            {links.legal.map((link) => (
              <li key={link.name}>
                <Link
                  href={link.href}
                  className="font-mono text-xs sm:text-sm text-blue-200 hover:text-blue-100 transition-colors"
                >
                  {link.name}
                </Link>
              </li>
            ))}
          </ul>
        </div>

        {/* Community Section */}
        <div>
          <h4 className="font-mono uppercase text-xs sm:text-sm mb-4 text-blue-100 font-semibold">Community</h4>
          <ul className="space-y-2">
            {links.community.map((link) => {
              const Icon = link.icon;
              return (
                <li key={link.name}>
                  <Link
                    href={link.href}
                    className="font-mono text-xs sm:text-sm text-blue-200 hover:text-blue-100 transition-colors flex items-center gap-2"
                  >
                    {Icon && <Icon className="w-3 h-3 sm:w-4 sm:h-4 text-blue-300" />}
                    {link.name}
                  </Link>
                </li>
              );
            })}
          </ul>
        </div>
      </div>

      {/* Social Media Icons Section */}
      <div className="pt-6 sm:pt-8 mb-6 sm:mb-8">
        <div className="flex flex-col items-center gap-4">
          <h4 className="font-mono uppercase text-xs sm:text-sm text-blue-100 font-semibold">Follow Us</h4>
          <div className="flex items-center justify-center gap-3 sm:gap-4 flex-wrap">
            {socialLinks.map((social) => {
              const Icon = social.icon;
              return (
                <Link
                  key={social.name}
                  href={social.href}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="w-10 h-10 sm:w-12 sm:h-12 rounded-full bg-blue-900/60 border-2 border-blue-400/60 flex items-center justify-center text-blue-200 hover:text-white hover:bg-blue-800/70 hover:border-blue-300/80 transition-all duration-300 hover:scale-110 shadow-lg shadow-blue-500/20 hover:shadow-blue-400/40"
                  aria-label={social.name}
                >
                  <Icon className="w-5 h-5 sm:w-6 sm:h-6" />
                </Link>
              );
            })}
          </div>
        </div>
      </div>

      {/* Copyright Section */}
      <div className="pt-6 sm:pt-8 flex flex-col md:flex-row justify-between items-center gap-4">
        <p className="font-mono text-xs sm:text-sm text-blue-200/80 text-center md:text-left">
          © {new Date().getFullYear()} SolWave. All rights reserved.
        </p>
        <div className="flex items-center gap-2 sm:gap-4 text-xs sm:text-sm font-mono text-blue-200/80">
          <Link href="/privacy" className="hover:text-blue-100 transition-colors">
            Privacy
          </Link>
          <span className="text-blue-400/60">•</span>
          <Link href="/terms" className="hover:text-blue-100 transition-colors">
            Terms
          </Link>
          <span className="text-blue-400/60">•</span>
          <Link href="/cookies" className="hover:text-blue-100 transition-colors">
            Cookies
          </Link>
        </div>
      </div>
    </footer>
  );
}

