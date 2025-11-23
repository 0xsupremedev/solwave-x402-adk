import { WalletSigner } from './signers';
import { PublicKey } from '@solana/web3.js';

/**
 * Wallet detection and connection utilities
 * This module provides wallet adapter integration helpers
 */

export type WalletName = 'phantom' | 'solflare' | 'backpack' | 'glow' | 'slope' | 'ledger';

/**
 * Wallet priority order (highest to lowest)
 */
export const WALLET_PRIORITY: WalletName[] = [
  'phantom',
  'solflare',
  'backpack',
  'glow',
  'slope',
  'ledger',
];

/**
 * Check if a wallet is installed (browser extension)
 */
export function isWalletInstalled(name: WalletName): boolean {
  if (typeof window === 'undefined') return false;
  
  switch (name) {
    case 'phantom':
      return !!(window as any).solana?.isPhantom;
    case 'solflare':
      return !!(window as any).solflare;
    case 'backpack':
      return !!(window as any).backpack;
    case 'glow':
      return !!(window as any).glow;
    case 'slope':
      return !!(window as any).Slope;
    case 'ledger':
      // Ledger requires hardware connection, check differently
      return false; // Will be handled by wallet adapter
    default:
      return false;
  }
}

/**
 * Detect all installed wallets
 */
export function detectInstalledWallets(): WalletName[] {
  return WALLET_PRIORITY.filter(name => isWalletInstalled(name));
}

/**
 * Get the best available wallet (highest priority)
 */
export function getBestAvailableWallet(): WalletName | null {
  const installed = detectInstalledWallets();
  return installed.length > 0 ? installed[0] : null;
}

/**
 * Convert wallet adapter signer to WalletSigner interface
 */
export function adapterToSigner(adapter: any): WalletSigner | null {
  if (!adapter || !adapter.publicKey) {
    return null;
  }

  return {
    publicKey: adapter.publicKey,
    signTransaction: async (tx) => {
      if (!adapter.signTransaction) {
        throw new Error('Wallet adapter does not support signTransaction');
      }
      return adapter.signTransaction(tx);
    },
    signAllTransactions: adapter.signAllTransactions
      ? async (txs) => adapter.signAllTransactions(txs)
      : undefined,
  };
}

/**
 * Get wallet display name
 */
export function getWalletDisplayName(name: WalletName): string {
  const names: Record<WalletName, string> = {
    phantom: 'Phantom',
    solflare: 'Solflare',
    backpack: 'Backpack',
    glow: 'Glow',
    slope: 'Slope',
    ledger: 'Ledger',
  };
  return names[name] || name;
}

/**
 * Get wallet installation URL
 */
export function getWalletInstallUrl(name: WalletName): string {
  const urls: Record<WalletName, string> = {
    phantom: 'https://phantom.app/',
    solflare: 'https://solflare.com/',
    backpack: 'https://www.backpack.app/',
    glow: 'https://glow.app/',
    slope: 'https://slope.finance/',
    ledger: 'https://www.ledger.com/',
  };
  return urls[name];
}

