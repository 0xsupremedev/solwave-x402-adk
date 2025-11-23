# Merchant Agent Example

This is an example merchant agent implementation using the x402 Solana ADK platform.

## Usage

```typescript
import { ADKClient } from '@x402/solana-adk';
import { MerchantAgent } from '@x402/solana-adk/agents';

const client = new ADKClient();
const merchantAgent = client.createMerchantAgent(
  'merchant-agent-1',
  'merchant-123',
  'YourSolanaAddressHere'
);

// Create invoice
const result = await merchantAgent.processPaymentRequest('1.0', 'USDC', 'Product description');
console.log('Invoice created:', result.invoice);
```

