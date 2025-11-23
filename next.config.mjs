import path from 'path';
import { fileURLToPath } from 'url';
import { createRequire } from 'module';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const require = createRequire(import.meta.url);

/** @type {import('next').NextConfig} */
const nextConfig = {
  typescript: {
    ignoreBuildErrors: true,
  },
  images: {
    unoptimized: true,
  },
  webpack: (config, { webpack, isServer }) => {
    // Configure webpack to handle optional wallet adapter packages gracefully
    // This allows the app to build even if wallet adapters aren't installed
    if (!isServer) {
      // Add alias that points to a stub if module doesn't exist
      const stubPath = path.resolve(__dirname, 'lib/webpack/wallet-adapter-stub.js');
      
      // Try to resolve each package, if it fails, use stub
      const walletAdapterPackages = [
        '@solana/wallet-adapter-react',
        '@solana/wallet-adapter-react-ui',
        '@solana/wallet-adapter-base',
        '@solana/wallet-adapter-wallets',
        '@solana/wallet-adapter-phantom',
        '@solana/wallet-adapter-solflare',
        '@solana/wallet-adapter-backpack',
        '@solana/wallet-adapter-glow',
        '@solana/wallet-adapter-slope',
        '@solana/wallet-adapter-ledger',
      ];
      
      config.resolve.alias = config.resolve.alias || {};
      walletAdapterPackages.forEach((pkg) => {
        try {
          require.resolve(pkg);
          // Package exists, don't add alias (let webpack handle it normally)
        } catch (e) {
          // Package doesn't exist, use stub
          config.resolve.alias[pkg] = stubPath;
        }
      });
    }
    return config;
  },
}

export default nextConfig
