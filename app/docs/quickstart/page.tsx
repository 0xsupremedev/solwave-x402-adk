import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Code, Wallet, FileText, Eye } from "lucide-react";

export default function QuickstartPage() {
  return (
    <div className="container py-24 max-w-4xl">
      <div className="mb-8">
        <h1 className="text-4xl font-sentient mb-4">Quick Start (NPM SDK)</h1>
        <p className="font-mono text-blue-300">
          Get started with the x402 Solana SDK in minutes
        </p>
      </div>

      <div className="space-y-6">
        <Card className="border-blue-500/50 bg-blue-950/40 backdrop-blur-sm">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-blue-100">
              <Code className="w-5 h-5 text-blue-400" />
              Install SDK
            </CardTitle>
          </CardHeader>
          <CardContent>
            <p className="font-mono text-sm text-blue-200 mb-4">
              Install the x402 Solana SDK package:
            </p>
            <pre className="bg-blue-900/30 border border-blue-500/50 rounded-lg p-4 font-mono text-sm overflow-x-auto text-blue-200">
{`npm install @x402/solana-sdk`}
            </pre>
          </CardContent>
        </Card>

        <Card className="border-blue-500/50 bg-blue-950/40 backdrop-blur-sm">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-blue-100">
              <Wallet className="w-5 h-5 text-blue-400" />
              Connect Wallet
            </CardTitle>
          </CardHeader>
          <CardContent>
            <p className="font-mono text-sm text-blue-200 mb-4">
              The SDK supports 6 wallets: Phantom, Solflare, Backpack, Glow, Slope, and Ledger. Use the wallet adapter:
            </p>
            <pre className="bg-blue-900/30 border border-blue-500/50 rounded-lg p-4 font-mono text-sm overflow-x-auto text-blue-200">
{`import { useWallet } from '@solana/wallet-adapter-react';
import { WalletButton } from '@x402/solana-sdk/components';

function MyComponent() {
  const { publicKey, signTransaction } = useWallet();
  
  if (!publicKey) {
    return <WalletButton />;
  }
  
  return <div>Connected: {publicKey.toBase58()}</div>;
}`}
            </pre>
            <p className="font-mono text-xs text-blue-300 mt-4">
              The wallet adapter automatically detects installed wallets and provides a unified interface.
            </p>
          </CardContent>
        </Card>

        <Card className="border-blue-500/50 bg-blue-950/40 backdrop-blur-sm">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-blue-100">
              <FileText className="w-5 h-5 text-blue-400" />
              Create Invoice
            </CardTitle>
          </CardHeader>
          <CardContent>
            <p className="font-mono text-sm text-blue-200 mb-4">
              Create a payment invoice using createInvoice():
            </p>
            <pre className="bg-blue-900/30 border border-blue-500/50 rounded-lg p-4 font-mono text-sm overflow-x-auto text-blue-200">
{`import { createInvoice } from '@x402/solana-sdk';

const invoice = await createInvoice({
  merchantId: 'merchant-123',
  amount: '1.0',
  token: 'USDC',
  memo: 'Payment for service'
});

console.log('Invoice ID:', invoice.id);
console.log('Amount:', invoice.amount);
console.log('Status:', invoice.status);`}
            </pre>
          </CardContent>
        </Card>

        <Card className="border-blue-500/50 bg-blue-950/40 backdrop-blur-sm">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-blue-100">
              <Eye className="w-5 h-5 text-blue-400" />
              Watch Invoice Status
            </CardTitle>
          </CardHeader>
          <CardContent>
            <p className="font-mono text-sm text-blue-200 mb-4">
              Monitor invoice status changes using watchInvoice():
            </p>
            <pre className="bg-blue-900/30 border border-blue-500/50 rounded-lg p-4 font-mono text-sm overflow-x-auto text-blue-200">
{`import { watchInvoice } from '@x402/solana-sdk';

watchInvoice(invoice.id, (status) => {
  console.log('Invoice status:', status);
  if (status === 'paid') {
    console.log('Payment confirmed!');
  }
});`}
            </pre>
          </CardContent>
        </Card>

        <div className="mt-8 p-6 rounded-lg bg-blue-950/40 border border-blue-500/50">
          <h3 className="font-sentient text-xl mb-4 text-blue-100">Next Steps</h3>
          <ul className="space-y-2 font-mono text-sm text-blue-200">
            <li>• Explore the full <a href="/docs" className="text-blue-400 hover:text-blue-300 underline">documentation</a></li>
            <li>• Check out the <a href="/docs#examples" className="text-blue-400 hover:text-blue-300 underline">example flows</a></li>
            <li>• Review the <a href="/docs#api" className="text-blue-400 hover:text-blue-300 underline">API reference</a></li>
          </ul>
        </div>
      </div>
    </div>
  );
}
