# Wallet Integration Setup

## Dependency Installation Note

The wallet adapter packages have been added to `package.json`. However, there may be a dependency conflict with the `infinityauth` package during installation.

### To Install Dependencies:

1. **Try installing all packages:**
   ```bash
   pnpm install
   ```

2. **If you encounter the infinityauth error**, try installing packages individually:
   ```bash
   pnpm add @solana/wallet-adapter-react@latest
   pnpm add @solana/wallet-adapter-react-ui@latest
   pnpm add @solana/wallet-adapter-base@latest
   pnpm add @solana/wallet-adapter-wallets@latest
   pnpm add @solana/wallet-adapter-phantom@latest
   pnpm add @solana/wallet-adapter-solflare@latest
   pnpm add @solana/wallet-adapter-ledger@latest
   ```

3. **Alternative: Use npm or yarn:**
   ```bash
   npm install
   # or
   yarn install
   ```

### Supported Wallets

The implementation supports 6 wallets with priority ranking:
1. **Phantom** - Most popular (primary)
2. **Solflare** - Strong DeFi presence
3. **Backpack** - xNFT ecosystem (optional, deprecated package)
4. **Glow** - Mobile-friendly (optional, deprecated package)
5. **Slope** - Asia markets (optional, deprecated package)
6. **Ledger** - Hardware wallet

### Code Structure

The code is designed to work even if some wallet adapters fail to install:
- `WalletProvider.tsx` uses try-catch blocks for optional adapters
- Core functionality works with Phantom and Solflare (most important)
- Missing adapters are gracefully handled

### Testing

Manual testing is required with actual wallet browser extensions:
1. Install Phantom or Solflare browser extension
2. Connect wallet in the application
3. Test payment flow with real transactions (use devnet for testing)
4. Verify transaction confirmation and agent integration

