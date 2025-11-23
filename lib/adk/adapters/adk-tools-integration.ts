/**
 * ADK Tools Integration
 * Connects existing tools to ADK provider with x402 A2A protocol support
 */

import { ADKTool } from "../google/provider";
import { adkTools } from "../tools";
import { getPaymentFlowAdapter } from "./payment-flow";
import { createPaymentRequirements, createSinglePaymentRequiredResponse } from "../x402-tools/invoice-tools";
import { PaymentRequirements } from "../extensions/types";

/**
 * Convert existing ADK tools to new ADK format
 */
export function convertToolsToADKFormat(): ADKTool[] {
  return adkTools.map((tool) => ({
    name: tool.name,
    description: tool.description,
    parameters: tool.parameters,
    handler: tool.handler,
  }));
}

/**
 * Create x402 A2A payment tools
 */
export function createX402ADKTools(): ADKTool[] {
  const paymentFlow = getPaymentFlowAdapter();

  return [
    {
      name: "create_payment_requirement",
      description: "Create a payment requirement for A2A x402 protocol",
      parameters: {
        type: "object",
        properties: {
          price: {
            type: "string",
            description: "Payment price (e.g., '$1.00', '0.5', or token amount)",
          },
          payToAddress: {
            type: "string",
            description: "Solana address to receive payment",
          },
          resource: {
            type: "string",
            description: "Resource identifier (e.g., '/premium-feature')",
          },
          network: {
            type: "string",
            description: "Blockchain network (default: 'solana')",
            enum: ["solana", "base", "ethereum"],
          },
          description: {
            type: "string",
            description: "Human-readable description",
          },
        },
        required: ["price", "payToAddress", "resource"],
      },
      handler: async (params: {
        price: string;
        payToAddress: string;
        resource: string;
        network?: string;
        description?: string;
      }) => {
        const requirement = await createPaymentRequirements(
          params.price,
          params.payToAddress,
          params.resource,
          (params.network as any) || "solana",
          params.description || ""
        );

        return {
          success: true,
          requirement,
        };
      },
    },
    {
      name: "request_x402_payment",
      description: "Request payment using x402 A2A protocol - triggers payment UI",
      parameters: {
        type: "object",
        properties: {
          price: {
            type: "string",
            description: "Payment price",
          },
          payToAddress: {
            type: "string",
            description: "Solana address to receive payment",
          },
          resource: {
            type: "string",
            description: "Resource identifier",
          },
          merchantId: {
            type: "string",
            description: "Merchant ID",
          },
          description: {
            type: "string",
            description: "Payment description",
          },
        },
        required: ["price", "payToAddress", "resource", "merchantId"],
      },
      handler: async (params: {
        price: string;
        payToAddress: string;
        resource: string;
        merchantId: string;
        description?: string;
      }) => {
        // Create payment required response
        const paymentResponse = await createSinglePaymentRequiredResponse(
          params.price,
          params.payToAddress,
          params.resource,
          "solana",
          params.description
        );

        // Handle via payment flow adapter
        const invoice = await paymentFlow.handlePaymentRequired(paymentResponse, params.merchantId);

        return {
          success: true,
          invoice,
          paymentResponse,
          message: "Payment request created. User will be prompted to pay.",
        };
      },
    },
    {
      name: "wait_for_x402_payment",
      description: "Wait for x402 payment to be confirmed",
      parameters: {
        type: "object",
        properties: {
          invoiceId: {
            type: "string",
            description: "Invoice ID to wait for",
          },
          maxWaitTime: {
            type: "number",
            description: "Maximum wait time in milliseconds (default: 300000)",
          },
        },
        required: ["invoiceId"],
      },
      handler: async (params: { invoiceId: string; maxWaitTime?: number }) => {
        // Use existing wait_for_payment tool logic
        const { executeTool } = await import("../tools");
        return await executeTool("wait_for_payment", {
          invoiceId: params.invoiceId,
          maxWaitTime: params.maxWaitTime || 300000,
        });
      },
    },
    {
      name: "verify_x402_payment",
      description: "Verify x402 payment on-chain",
      parameters: {
        type: "object",
        properties: {
          invoiceId: {
            type: "string",
            description: "Invoice ID",
          },
          txSignature: {
            type: "string",
            description: "Transaction signature",
          },
        },
        required: ["invoiceId", "txSignature"],
      },
      handler: async (params: { invoiceId: string; txSignature: string }) => {
        // Use existing verify_payment tool
        const { executeTool } = await import("../tools");
        return await executeTool("verify_payment", {
          invoiceId: params.invoiceId,
          txSignature: params.txSignature,
        });
      },
    },
  ];
}

/**
 * Get all ADK tools (existing + x402 A2A)
 */
export function getAllADKTools(): ADKTool[] {
  return [...convertToolsToADKFormat(), ...createX402ADKTools()];
}

