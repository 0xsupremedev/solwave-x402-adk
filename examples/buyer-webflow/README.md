# Buyer Webflow Example

This is an example buyer webflow implementation using the x402 Solana ADK platform.

## Usage

```typescript
import { ADKClient } from '@x402/solana-adk';
import { ClientAgent } from '@x402/solana-adk/agents';

const client = new ADKClient();
const buyerAgent = client.createClientAgent('buyer-agent-1', 'user-123');

// Process purchase
const result = await buyerAgent.processPurchase('merchant-123', '1.0', 'USDC');
console.log('Payment request:', result);
```

