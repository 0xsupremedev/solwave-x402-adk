import { executeTool } from '../tools';

export interface ClientAgentConfig {
  agentId: string;
  userId?: string;
}

export class ClientAgent {
  private agentId: string;
  private userId?: string;

  constructor(config: ClientAgentConfig) {
    this.agentId = config.agentId;
    this.userId = config.userId;
  }

  async createInvoice(merchantId: string, amount: string, token: string = 'USDC', metadata?: any) {
    return executeTool('create_invoice', {
      merchantId,
      amount,
      token,
      metadata,
    });
  }

  async requestPaymentConfirmation(invoiceId: string, amount: string, token: string) {
    return executeTool('ask_for_confirmation', {
      invoiceId,
      amount,
      token,
    });
  }

  async checkInvoiceStatus(invoiceId: string) {
    return executeTool('poll_invoice_status', {
      invoiceId,
    });
  }

  async verifyPayment(invoiceId: string, txSignature: string) {
    return executeTool('verify_payment', {
      invoiceId,
      txSignature,
    });
  }

  async getExplorerLink(signature: string) {
    return executeTool('show_explorer_link', {
      signature,
    });
  }

  async processPurchase(merchantId: string, amount: string, token: string = 'USDC') {
    // Step 1: Create invoice
    const invoiceResult = await this.createInvoice(merchantId, amount, token);
    if (!invoiceResult.success) {
      return invoiceResult;
    }

    const invoice = invoiceResult.invoice;

    // Step 2: Request confirmation
    const confirmationResult = await this.requestPaymentConfirmation(
      invoice.id,
      invoice.amount,
      invoice.token
    );

    return {
      ...confirmationResult,
      invoice,
    };
  }

  /**
   * Request payment - generates x402 payment request
   * This is called by the client agent when it needs to request payment from user
   */
  async requestPayment(
    merchantId: string,
    amount: string,
    token: string = 'USDC',
    metadata?: Record<string, any>
  ) {
    // Create invoice first
    const invoiceResult = await this.createInvoice(merchantId, amount, token, metadata);
    if (!invoiceResult.success) {
      return invoiceResult;
    }

    const invoice = invoiceResult.invoice;

    // Return x402 payment request format
    return {
      success: true,
      paymentRequest: {
        invoiceId: invoice.id,
        amount: invoice.amount,
        token: invoice.token,
        recipient: metadata?.merchantAddress || merchantId, // Should be merchant's Solana address
        nonce: invoice.nonce,
        expiresAt: invoice.expiresAt,
        metadata: invoice.metadata,
      },
      invoice,
    };
  }

  /**
   * Wait for payment confirmation
   * Polls for payment status until confirmed or expired
   */
  async waitForPayment(invoiceId: string, maxWaitTime: number = 300000): Promise<any> {
    const startTime = Date.now();
    const pollInterval = 2000; // Poll every 2 seconds

    while (Date.now() - startTime < maxWaitTime) {
      const statusResult = await this.checkInvoiceStatus(invoiceId);
      
      if (statusResult.success && statusResult.invoice) {
        const invoice = statusResult.invoice;
        
        if (invoice.status === 'paid' || invoice.status === 'settled') {
          return {
            success: true,
            invoice,
            txSignature: invoice.txSignature,
          };
        }
        
        if (invoice.status === 'expired' || invoice.status === 'cancelled') {
          return {
            success: false,
            error: `Invoice ${invoice.status}`,
            invoice,
          };
        }
      }

      // Wait before next poll
      await new Promise(resolve => setTimeout(resolve, pollInterval));
    }

    return {
      success: false,
      error: 'Payment wait timeout',
    };
  }
}

