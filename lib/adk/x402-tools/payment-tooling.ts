/**
 * Payment Tooling for A2A x402 Protocol
 * Ported from Python: x402_a2a/src/x402_a2a/core/protocol.py
 * Integrates with existing lib/sdk/payments/
 */

import {
  PaymentPayload,
  PaymentRequirements,
  VerifyResponse,
  SettleResponse,
} from "../extensions/types";
import { verifyPayment as verifyPaymentOnChain } from "@/lib/solana/verification";
import { Connection, PublicKey } from "@solana/web3.js";
import { getConnection } from "@/lib/solana/client";

/**
 * Facilitator Client Interface
 * For Solana, we'll use direct on-chain verification
 */
export interface FacilitatorClient {
  verify(payload: PaymentPayload, requirements: PaymentRequirements): Promise<VerifyResponse>;
  settle(payload: PaymentPayload, requirements: PaymentRequirements): Promise<SettleResponse>;
}

/**
 * Solana Facilitator Client Implementation
 * Uses direct on-chain verification instead of external facilitator
 */
export class SolanaFacilitatorClient implements FacilitatorClient {
  private connection: Connection;

  constructor(connection?: Connection) {
    this.connection = connection || getConnection();
  }

  /**
   * Verify payment signature and requirements
   * Ported from: core/protocol.py verify_payment
   */
  async verify(
    payload: PaymentPayload,
    requirements: PaymentRequirements
  ): Promise<VerifyResponse> {
    try {
      // For Solana, we need to:
      // 1. Verify the signature
      // 2. Check that the payment matches requirements
      // 3. Verify on-chain transaction if available

      // Extract transaction signature from payload if available
      const txSignature = payload.signature;

      if (txSignature && requirements.network === "solana") {
        // Verify on-chain transaction
        const verified = await verifyPaymentOnChain({
          signature: txSignature,
          expectedAmount: requirements.max_amount_required,
          expectedRecipient: new PublicKey(requirements.pay_to),
          expectedToken: new PublicKey(requirements.asset),
        });

        if (verified) {
          return {
            is_valid: true,
            verified_at: new Date().toISOString(),
          };
        } else {
          return {
            is_valid: false,
            invalid_reason: "Transaction verification failed",
          };
        }
      }

      // Basic validation
      if (payload.payment_requirements.network !== requirements.network) {
        return {
          is_valid: false,
          invalid_reason: "Network mismatch",
        };
      }

      if (payload.payment_requirements.pay_to !== requirements.pay_to) {
        return {
          is_valid: false,
          invalid_reason: "Recipient mismatch",
        };
      }

      // For now, return valid if basic checks pass
      // In production, implement proper signature verification
      return {
        is_valid: true,
        verified_at: new Date().toISOString(),
      };
    } catch (error: any) {
      return {
        is_valid: false,
        invalid_reason: error.message || "Verification error",
      };
    }
  }

  /**
   * Settle payment on blockchain
   * Ported from: core/protocol.py settle_payment
   */
  async settle(
    payload: PaymentPayload,
    requirements: PaymentRequirements
  ): Promise<SettleResponse> {
    try {
      // For Solana, settlement is already done on-chain
      // We just need to verify the transaction exists and is confirmed

      const txSignature = payload.signature;

      if (!txSignature) {
        return {
          success: false,
          error_reason: "No transaction signature provided",
        };
      }

      if (requirements.network === "solana") {
        // Verify transaction exists and is confirmed
        const connection = this.connection;
        const signature = txSignature;

        try {
          const tx = await connection.getTransaction(signature, {
            commitment: "confirmed",
          });

          if (!tx) {
            return {
              success: false,
              error_reason: "Transaction not found",
            };
          }

          if (tx.meta?.err) {
            return {
              success: false,
              error_reason: `Transaction failed: ${JSON.stringify(tx.meta.err)}`,
            };
          }

          return {
            success: true,
            transaction: signature,
            network: requirements.network,
            payer: payload.signer,
            settled_at: new Date().toISOString(),
          };
        } catch (error: any) {
          return {
            success: false,
            error_reason: error.message || "Transaction verification failed",
          };
        }
      }

      return {
        success: false,
        error_reason: "Unsupported network",
      };
    } catch (error: any) {
      return {
        success: false,
        error_reason: error.message || "Settlement error",
      };
    }
  }
}

/**
 * Verify payment using facilitator
 * Ported from: core/protocol.py verify_payment
 */
export async function verifyPayment(
  paymentPayload: PaymentPayload,
  paymentRequirements: PaymentRequirements,
  facilitatorClient?: FacilitatorClient
): Promise<VerifyResponse> {
  const facilitator = facilitatorClient || new SolanaFacilitatorClient();
  return await facilitator.verify(paymentPayload, paymentRequirements);
}

/**
 * Settle payment on blockchain using facilitator
 * Ported from: core/protocol.py settle_payment
 */
export async function settlePayment(
  paymentPayload: PaymentPayload,
  paymentRequirements: PaymentRequirements,
  facilitatorClient?: FacilitatorClient
): Promise<SettleResponse> {
  const facilitator = facilitatorClient || new SolanaFacilitatorClient();
  return await facilitator.settle(paymentPayload, paymentRequirements);
}

