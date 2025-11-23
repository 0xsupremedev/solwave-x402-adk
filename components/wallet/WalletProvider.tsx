"use client";

import { ReactNode, useMemo, useEffect, useState } from "react";
import { clusterApiUrl } from "@solana/web3.js";
import { getCluster } from "@/lib/solana/client";

// Dynamic import helper to avoid build-time resolution
// Using webpackIgnore to prevent webpack from trying to resolve these at build time
function safeRequire(moduleName: string): any {
  if (typeof window === 'undefined') {
    // Server-side: return null (wallet adapters are client-only)
    return null;
  } else {
    // Client-side: use dynamic require with webpack ignore
    try {
      // @ts-ignore - webpack will try to resolve this, but we catch the error
      // eslint-disable-next-line @typescript-eslint/no-var-requires
      const module = require(moduleName);
      return module;
    } catch {
      return null;
    }
  }
}

interface WalletProviderProps {
  children: ReactNode;
}

export function WalletProvider({ children }: WalletProviderProps) {
  const [walletModules, setWalletModules] = useState<any>(null);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    // Load wallet adapter modules dynamically on client side
    if (typeof window !== 'undefined') {
      try {
        const walletAdapterReact = safeRequire("@solana/wallet-adapter-react");
        const walletAdapterBase = safeRequire("@solana/wallet-adapter-base");
        const walletAdapterReactUI = safeRequire("@solana/wallet-adapter-react-ui");
        const walletAdapterWallets = safeRequire("@solana/wallet-adapter-wallets");

        if (walletAdapterReact && walletAdapterBase && walletAdapterReactUI && walletAdapterWallets) {
          // Try to load styles
          try {
            safeRequire("@solana/wallet-adapter-react-ui/styles.css");
          } catch {
            // Styles not critical
          }

          setWalletModules({
            ConnectionProvider: walletAdapterReact.ConnectionProvider,
            SolanaWalletProvider: walletAdapterReact.WalletProvider,
            WalletAdapterNetwork: walletAdapterBase.WalletAdapterNetwork,
            WalletModalProvider: walletAdapterReactUI.WalletModalProvider,
            PhantomWalletAdapter: walletAdapterWallets.PhantomWalletAdapter,
            SolflareWalletAdapter: walletAdapterWallets.SolflareWalletAdapter,
            BackpackWalletAdapter: safeRequire("@solana/wallet-adapter-backpack")?.BackpackWalletAdapter,
            GlowWalletAdapter: safeRequire("@solana/wallet-adapter-glow")?.GlowWalletAdapter,
            SlopeWalletAdapter: safeRequire("@solana/wallet-adapter-slope")?.SlopeWalletAdapter,
            LedgerWalletAdapter: safeRequire("@solana/wallet-adapter-ledger")?.LedgerWalletAdapter,
          });
        }
      } catch (error) {
        console.warn("Wallet adapter packages not available:", error);
      } finally {
        setIsLoading(false);
      }
    } else {
      setIsLoading(false);
    }
  }, []);

  // If wallet adapters are not installed, return children without wallet context
  if (!isLoading && !walletModules) {
    return <>{children}</>;
  }

  if (isLoading || !walletModules) {
    return <>{children}</>;
  }

  const {
    ConnectionProvider,
    SolanaWalletProvider,
    WalletAdapterNetwork,
    WalletModalProvider,
    PhantomWalletAdapter,
    SolflareWalletAdapter,
    BackpackWalletAdapter,
    GlowWalletAdapter,
    SlopeWalletAdapter,
    LedgerWalletAdapter,
  } = walletModules;

  // Get network from environment or default to mainnet-beta
  const network = WalletAdapterNetwork 
    ? (process.env.NEXT_PUBLIC_SOLANA_NETWORK as any) || WalletAdapterNetwork.Mainnet
    : "mainnet-beta";
  
  // You can also provide a custom RPC endpoint
  const endpoint = useMemo(() => {
    if (process.env.NEXT_PUBLIC_SOLANA_RPC_URL) {
      return process.env.NEXT_PUBLIC_SOLANA_RPC_URL;
    }
    return clusterApiUrl(network);
  }, [network]);

  // Initialize wallets with priority order
  const wallets = useMemo(() => {
    const walletAdapters: any[] = [];

    if (PhantomWalletAdapter) {
      walletAdapters.push(new PhantomWalletAdapter());
    }
    if (SolflareWalletAdapter) {
      walletAdapters.push(new SolflareWalletAdapter());
    }

    // Add optional wallets if available
    if (BackpackWalletAdapter) {
      walletAdapters.push(new BackpackWalletAdapter());
    }
    if (GlowWalletAdapter) {
      walletAdapters.push(new GlowWalletAdapter());
    }
    if (SlopeWalletAdapter) {
      walletAdapters.push(new SlopeWalletAdapter());
    }
    if (LedgerWalletAdapter) {
      walletAdapters.push(new LedgerWalletAdapter());
    }

    return walletAdapters;
  }, []);

  const content = wallets.length > 0 && WalletModalProvider ? (
    <WalletModalProvider>
      {children}
    </WalletModalProvider>
  ) : (
    children
  );

  return (
    <ConnectionProvider endpoint={endpoint}>
      <SolanaWalletProvider wallets={wallets} autoConnect>
        {content}
      </SolanaWalletProvider>
    </ConnectionProvider>
  );
}

