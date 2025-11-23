"use client";

import { useState, useEffect, useMemo } from "react";
import {
  CommandDialog,
  CommandInput,
  CommandList,
  CommandEmpty,
  CommandGroup,
  CommandItem,
} from "@/components/ui/command";
import { Search } from "lucide-react";

interface DocSection {
  id: string;
  title: string;
  href: string;
  keywords: string[];
  description?: string;
}

const docSections: DocSection[] = [
  {
    id: "overview",
    title: "Overview",
    href: "/docs#overview",
    keywords: ["overview", "introduction", "starter kit", "x402"],
    description: "Introduction to x402 AI Starter Kit",
  },
  {
    id: "quickstart",
    title: "Quick Start (NPM SDK)",
    href: "/docs/quickstart",
    keywords: ["quickstart", "npm", "sdk", "install", "getting started"],
    description: "Get started with the NPM SDK in minutes",
  },
  {
    id: "architecture",
    title: "Architecture & Components",
    href: "/docs#architecture",
    keywords: ["architecture", "components", "structure", "system"],
    description: "System architecture and component overview",
  },
  {
    id: "prerequisites",
    title: "Prerequisites",
    href: "/docs#prerequisites",
    keywords: ["prerequisites", "requirements", "setup", "install"],
    description: "Required tools and dependencies",
  },
  {
    id: "getting-started",
    title: "Getting Started — Local Development",
    href: "/docs#getting-started",
    keywords: ["getting started", "local", "development", "setup"],
    description: "Local development setup guide",
  },
  {
    id: "configuration",
    title: "Configuration & Environment Variables",
    href: "/docs#configuration",
    keywords: ["configuration", "env", "environment", "variables", "settings"],
    description: "Environment configuration guide",
  },
  {
    id: "solana",
    title: "Solana Integration & Wallet Flow",
    href: "/docs#solana",
    keywords: ["solana", "wallet", "phantom", "solflare", "integration"],
    description: "Solana blockchain integration",
  },
  {
    id: "x402",
    title: "x402 Payment Protocol Explained",
    href: "/docs#x402",
    keywords: ["x402", "payment", "protocol", "payment request"],
    description: "Understanding the x402 payment protocol",
  },
  {
    id: "mcp",
    title: "MCP Server & Agent Integration",
    href: "/docs#mcp",
    keywords: ["mcp", "server", "agent", "integration"],
    description: "MCP server setup and agent integration",
  },
  {
    id: "api",
    title: "API Reference",
    href: "/docs#api",
    keywords: ["api", "reference", "endpoints", "rest"],
    description: "Complete API documentation",
  },
  {
    id: "examples",
    title: "Example Flows / Walkthroughs",
    href: "/docs#examples",
    keywords: ["examples", "walkthrough", "tutorial", "flow"],
    description: "Step-by-step examples and tutorials",
  },
  {
    id: "testing",
    title: "Testing & Debugging",
    href: "/docs#testing",
    keywords: ["testing", "debug", "debugging", "test"],
    description: "Testing and debugging guide",
  },
  {
    id: "security",
    title: "Security Considerations",
    href: "/docs#security",
    keywords: ["security", "safety", "best practices"],
    description: "Security best practices",
  },
  {
    id: "deployment",
    title: "Deployment",
    href: "/docs#deployment",
    keywords: ["deployment", "vercel", "production", "deploy"],
    description: "Deployment instructions",
  },
];

export function DocsSearch() {
  const [open, setOpen] = useState(false);

  useEffect(() => {
    const down = (e: KeyboardEvent) => {
      if (e.key === "k" && (e.metaKey || e.ctrlKey)) {
        e.preventDefault();
        setOpen((open) => !open);
      }
    };

    document.addEventListener("keydown", down);
    return () => document.removeEventListener("keydown", down);
  }, []);

  return (
    <>
      <button
        onClick={() => setOpen(true)}
        className="w-full sm:w-auto flex items-center gap-2 px-4 py-2 rounded-full bg-blue-950/40 border border-blue-500/50 text-blue-200 hover:bg-blue-900/50 hover:border-blue-400/70 transition-all font-mono text-sm"
      >
        <Search className="w-4 h-4" />
        <span>Search docs...</span>
        <kbd className="hidden sm:inline-flex h-5 select-none items-center gap-1 rounded border border-blue-500/50 bg-blue-950/40 px-1.5 font-mono text-[10px] font-medium text-blue-300">
          <span className="text-xs">⌘</span>K
        </kbd>
      </button>

      <CommandDialog 
        open={open} 
        onOpenChange={setOpen}
        title="Search Documentation"
        className="bg-blue-950 border-blue-500/50"
      >
        <CommandInput 
          placeholder="Search documentation..." 
          className="text-blue-200 placeholder:text-blue-400/50"
        />
        <CommandList className="max-h-[400px]">
          <CommandEmpty className="text-blue-300 py-6">No results found.</CommandEmpty>
          <CommandGroup heading="Documentation Sections" className="text-blue-200 [&_[cmdk-group-heading]]:text-blue-100">
            {docSections.map((section) => (
              <CommandItem
                key={section.id}
                value={`${section.title} ${section.description || ""} ${section.keywords.join(" ")}`}
                onSelect={() => {
                  window.location.href = section.href;
                  setOpen(false);
                }}
                className="cursor-pointer text-blue-200 hover:bg-blue-900/50 data-[selected=true]:bg-blue-900/50 data-[selected=true]:text-blue-100"
              >
                <div className="flex flex-col">
                  <span className="font-medium">{section.title}</span>
                  {section.description && (
                    <span className="text-xs text-blue-400/60">{section.description}</span>
                  )}
                </div>
              </CommandItem>
            ))}
          </CommandGroup>
        </CommandList>
      </CommandDialog>
    </>
  );
}

