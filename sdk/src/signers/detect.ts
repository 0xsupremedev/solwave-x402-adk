import { BrowserWalletSigner, SolanaWalletProvider } from './browserWalletSigner';

export interface DetectedWallet {
  id: string;
  label: string;
  provider: SolanaWalletProvider;
  createSigner: () => BrowserWalletSigner;
}

function pushWallet(results: DetectedWallet[], id: string, label: string, provider: SolanaWalletProvider) {
  const exists = results.find((wallet) => wallet.id === id);
  if (exists) return;

  results.push({
    id,
    label,
    provider,
    createSigner: () => new BrowserWalletSigner(provider, label),
  });
}

/**
 * Attempts to detect injected Solana wallet providers in browser environments.
 * Returns an empty array on the server/Node runtimes.
 */
export function detectWalletAdapters(): DetectedWallet[] {
  if (typeof window === 'undefined') {
    return [];
  }

  const results: DetectedWallet[] = [];
  const globalAny = window as unknown as Record<string, any>;

  const addProvider = (provider: SolanaWalletProvider | undefined | null) => {
    if (!provider) return;

    if (provider.isPhantom) {
      pushWallet(results, 'phantom', 'Phantom', provider);
    } else if (provider.isSolflare) {
      pushWallet(results, 'solflare', 'Solflare', provider);
    } else {
      pushWallet(results, 'solana-wallet', 'Solana Wallet', provider);
    }
  };

  const injectedSolana = globalAny.solana;
  if (injectedSolana) {
    addProvider(injectedSolana);
    if (Array.isArray(injectedSolana.providers)) {
      injectedSolana.providers.forEach((provider: SolanaWalletProvider) => addProvider(provider));
    }
  }

  const solflare = globalAny.solflare?.getProvider?.();
  if (solflare) {
    addProvider(solflare);
  }

  return results;
}


