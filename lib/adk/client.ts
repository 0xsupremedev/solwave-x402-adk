import { ClientAgent } from './agents/client-agent';
import { MerchantAgent } from './agents/merchant-agent';

export interface ADKClientConfig {
  apiUrl?: string;
}

export class ADKClient {
  private config: ADKClientConfig;

  constructor(config: ADKClientConfig = {}) {
    this.config = {
      apiUrl: config.apiUrl || process.env.NEXT_PUBLIC_API_URL || 'http://localhost:3000',
      ...config,
    };
  }

  createClientAgent(agentId: string, userId?: string): ClientAgent {
    return new ClientAgent({
      agentId,
      userId,
    });
  }

  createMerchantAgent(agentId: string, merchantId: string, receivingAddress: string): MerchantAgent {
    return new MerchantAgent({
      agentId,
      merchantId,
      receivingAddress,
    });
  }

  async createSession(agentId: string, initialData?: any): Promise<string> {
    // Create agent session via API
    const response = await fetch(`${this.config.apiUrl}/api/v1/agents/${agentId}/sessions`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        traceEvents: initialData?.traceEvents || [],
        artifacts: initialData?.artifacts || [],
        state: initialData?.state || null,
      }),
    });

    if (!response.ok) {
      throw new Error('Failed to create session');
    }

    const data = await response.json();
    return data.id;
  }

  async updateSession(sessionId: string, agentId: string, data: any): Promise<void> {
    // Update session would typically be handled by the session management system
    // This is a placeholder for the actual implementation
    console.log('Updating session', sessionId, data);
  }
}

