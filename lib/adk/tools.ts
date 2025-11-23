import { createX402Invoice, getX402Invoice, createX402PaymentRequest } from '../x402/invoice';
import { verifyX402Payment } from '../x402/verification';
import { createPaymentTransaction, getExplorerUrl } from '../solana/transaction';

export interface ADKTool {
  name: string;
  description: string;
  parameters: Record<string, any>;
  handler: (params: any) => Promise<any>;
}

export const adkTools: ADKTool[] = [
  {
    name: 'create_invoice',
    description: 'Create an x402 payment invoice for a purchase',
    parameters: {
      type: 'object',
      properties: {
        merchantId: { type: 'string', description: 'Merchant ID' },
        amount: { type: 'string', description: 'Payment amount' },
        token: { type: 'string', description: 'Token symbol (default: USDC)' },
        metadata: { type: 'object', description: 'Additional metadata' },
      },
      required: ['merchantId', 'amount'],
    },
    handler: async (params: { merchantId: string; amount: string; token?: string; metadata?: any }) => {
      const invoice = await createX402Invoice(
        params.merchantId,
        params.amount,
        params.token || 'USDC',
        params.metadata
      );
      return {
        success: true,
        invoice,
      };
    },
  },
  {
    name: 'ask_for_confirmation',
    description: 'Request user confirmation for a payment',
    parameters: {
      type: 'object',
      properties: {
        invoiceId: { type: 'string', description: 'Invoice ID' },
        amount: { type: 'string', description: 'Payment amount' },
        token: { type: 'string', description: 'Token symbol' },
      },
      required: ['invoiceId', 'amount', 'token'],
    },
    handler: async (params: { invoiceId: string; amount: string; token: string }) => {
      const invoice = await getX402Invoice(params.invoiceId);
      if (!invoice) {
        return { success: false, error: 'Invoice not found' };
      }
      return {
        success: true,
        message: `Please approve payment of ${params.amount} ${params.token} for invoice ${params.invoiceId}`,
        invoice,
      };
    },
  },
  {
    name: 'poll_invoice_status',
    description: 'Check the status of an invoice',
    parameters: {
      type: 'object',
      properties: {
        invoiceId: { type: 'string', description: 'Invoice ID' },
      },
      required: ['invoiceId'],
    },
    handler: async (params: { invoiceId: string }) => {
      const invoice = await getX402Invoice(params.invoiceId);
      if (!invoice) {
        return { success: false, error: 'Invoice not found' };
      }
      return {
        success: true,
        invoice,
        status: invoice.status,
      };
    },
  },
  {
    name: 'verify_payment',
    description: 'Verify a payment transaction',
    parameters: {
      type: 'object',
      properties: {
        invoiceId: { type: 'string', description: 'Invoice ID' },
        txSignature: { type: 'string', description: 'Transaction signature' },
      },
      required: ['invoiceId', 'txSignature'],
    },
    handler: async (params: { invoiceId: string; txSignature: string }) => {
      try {
        const receipt = await verifyX402Payment(params.invoiceId, params.txSignature);
        return {
          success: true,
          receipt,
          explorerUrl: getExplorerUrl(params.txSignature),
        };
      } catch (error) {
        return {
          success: false,
          error: error instanceof Error ? error.message : 'Verification failed',
        };
      }
    },
  },
  {
    name: 'show_explorer_link',
    description: 'Generate a Solana explorer link for a transaction',
    parameters: {
      type: 'object',
      properties: {
        signature: { type: 'string', description: 'Transaction signature' },
      },
      required: ['signature'],
    },
    handler: async (params: { signature: string }) => {
      return {
        success: true,
        url: getExplorerUrl(params.signature),
      };
    },
  },
  {
    name: 'request_payment',
    description: 'Request payment from user - generates x402 payment request',
    parameters: {
      type: 'object',
      properties: {
        merchantId: { type: 'string', description: 'Merchant ID or Solana address' },
        amount: { type: 'string', description: 'Payment amount' },
        token: { type: 'string', description: 'Token symbol (default: USDC)' },
        metadata: { type: 'object', description: 'Additional metadata including merchantAddress' },
      },
      required: ['merchantId', 'amount'],
    },
    handler: async (params: { merchantId: string; amount: string; token?: string; metadata?: any }) => {
      const invoice = await createX402Invoice(
        params.merchantId,
        params.amount,
        params.token || 'USDC',
        params.metadata
      );
      
      const paymentRequest = createX402PaymentRequest(invoice, params.metadata?.merchantAddress || params.merchantId);
      
      return {
        success: true,
        paymentRequest,
        invoice,
      };
    },
  },
  {
    name: 'wait_for_payment',
    description: 'Wait for payment confirmation - polls invoice status until paid or expired',
    parameters: {
      type: 'object',
      properties: {
        invoiceId: { type: 'string', description: 'Invoice ID to wait for' },
        maxWaitTime: { type: 'number', description: 'Maximum wait time in milliseconds (default: 300000)' },
      },
      required: ['invoiceId'],
    },
    handler: async (params: { invoiceId: string; maxWaitTime?: number }) => {
      const maxWait = params.maxWaitTime || 300000;
      const startTime = Date.now();
      const pollInterval = 2000;

      while (Date.now() - startTime < maxWait) {
        const invoice = await getX402Invoice(params.invoiceId);
        
        if (!invoice) {
          return { success: false, error: 'Invoice not found' };
        }

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

        await new Promise(resolve => setTimeout(resolve, pollInterval));
      }

      return {
        success: false,
        error: 'Payment wait timeout',
      };
    },
  },
];

export function getToolByName(name: string): ADKTool | undefined {
  return adkTools.find((tool) => tool.name === name);
}

export async function executeTool(name: string, params: any): Promise<any> {
  const tool = getToolByName(name);
  if (!tool) {
    throw new Error(`Tool ${name} not found`);
  }
  return tool.handler(params);
}

