"use client";

import { useEffect, useState } from "react";

// Dynamic import helper
function safeRequire(moduleName: string): any {
  if (typeof window === 'undefined') return null;
  try {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    return require(moduleName);
  } catch {
    return null;
  }
}

/**
 * Wallet selection modal component
 * Uses the built-in wallet adapter modal with custom styling
 */
export function WalletModal() {
  const [modalComponents, setModalComponents] = useState<any>(null);

  useEffect(() => {
    if (typeof window !== 'undefined') {
      const walletAdapterReactUI = safeRequire("@solana/wallet-adapter-react-ui");
      if (walletAdapterReactUI) {
        setModalComponents({
          useWalletModal: walletAdapterReactUI.useWalletModal,
          WalletModal: walletAdapterReactUI.WalletModal,
        });
      }
    }
  }, []);

  if (!modalComponents) {
    return null;
  }

  const { useWalletModal, WalletModal: SolanaWalletModal } = modalComponents;
  const { visible, setVisible } = useWalletModal();

  return (
    <SolanaWalletModal 
      className="wallet-adapter-modal"
      onClose={() => setVisible(false)}
    />
  );
}

