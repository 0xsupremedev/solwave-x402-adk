import { executeTool } from '../tools';
import { createX402Invoice } from '../../x402/invoice';

export interface MerchantAgentConfig {
  agentId: string;
  merchantId: string;
  receivingAddress: string;
}

export class MerchantAgent {
  private agentId: string;
  private merchantId: string;
  private receivingAddress: string;

  constructor(config: MerchantAgentConfig) {
    this.agentId = config.agentId;
    this.merchantId = config.merchantId;
    this.receivingAddress = config.receivingAddress;
  }

  async createInvoice(amount: string, token: string = 'USDC', metadata?: any) {
    return createX402Invoice(
      this.merchantId,
      amount,
      token,
      metadata
    );
  }

  async verifyPayment(invoiceId: string, txSignature: string) {
    return executeTool('verify_payment', {
      invoiceId,
      txSignature,
    });
  }

  async checkInvoiceStatus(invoiceId: string) {
    return executeTool('poll_invoice_status', {
      invoiceId,
    });
  }

  async processPaymentRequest(amount: string, token: string = 'USDC', itemDescription?: string) {
    const invoice = await this.createInvoice(amount, token, {
      description: itemDescription,
      merchantAddress: this.receivingAddress,
    });

    return {
      success: true,
      invoice,
      paymentRequest: {
        invoiceId: invoice.id,
        amount: invoice.amount,
        token: invoice.token,
        recipient: this.receivingAddress,
        expiresAt: invoice.expiresAt,
      },
    };
  }

  /**
   * Verify payment on-chain
   * Validates transaction signature and confirms payment
   */
  async verifyPaymentOnChain(invoiceId: string, txSignature: string) {
    // Use the existing verifyPayment tool
    const result = await this.verifyPayment(invoiceId, txSignature);
    
    if (result.success) {
      // Additional on-chain verification can be added here
      return {
        success: true,
        verified: true,
        invoiceId,
        txSignature,
        ...result,
      };
    }

    return result;
  }

  /**
   * Wait for payment to be confirmed
   * Polls invoice status until payment is received or invoice expires
   */
  async waitForPayment(invoiceId: string, maxWaitTime: number = 300000): Promise<any> {
    const startTime = Date.now();
    const pollInterval = 2000; // Poll every 2 seconds

    while (Date.now() - startTime < maxWaitTime) {
      const statusResult = await this.checkInvoiceStatus(invoiceId);
      
      if (statusResult.success && statusResult.invoice) {
        const invoice = statusResult.invoice;
        
        if (invoice.status === 'paid' || invoice.status === 'settled') {
          // Verify payment on-chain if we have a signature
          if (invoice.txSignature) {
            const verifyResult = await this.verifyPaymentOnChain(invoiceId, invoice.txSignature);
            return {
              success: true,
              invoice,
              verified: verifyResult.verified || false,
              txSignature: invoice.txSignature,
            };
          }
          
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

