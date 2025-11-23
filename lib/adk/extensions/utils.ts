/**
 * x402 Utilities for A2A Protocol
 * Ported from Python: x402_a2a/src/x402_a2a/core/utils.py
 */

import { A2ATask, A2AMessage, PaymentStatus, X402Metadata, PaymentPayload, X402PaymentRequiredResponse } from "./types";

export class X402Utils {
  /**
   * Get payment status from task metadata
   */
  getPaymentStatus(task: A2ATask): PaymentStatus | null {
    if (!task.message?.metadata) {
      return null;
    }
    const status = task.message.metadata[X402Metadata.STATUS_KEY];
    return status as PaymentStatus || null;
  }

  /**
   * Get payment status from task (checks both task and message)
   */
  getPaymentStatusFromTask(task: A2ATask | null): PaymentStatus | null {
    if (!task) return null;
    return this.getPaymentStatus(task);
  }

  /**
   * Get payment status from message metadata
   */
  getPaymentStatusFromMessage(message: A2AMessage | null): PaymentStatus | null {
    if (!message?.metadata) {
      return null;
    }
    const status = message.metadata[X402Metadata.STATUS_KEY];
    return status as PaymentStatus || null;
  }

  /**
   * Get payment requirements from task
   */
  getPaymentRequirements(task: A2ATask): X402PaymentRequiredResponse | null {
    if (!task.message?.metadata) {
      return null;
    }
    return task.message.metadata[X402Metadata.REQUIRED_KEY] as X402PaymentRequiredResponse || null;
  }

  /**
   * Get payment payload from task
   */
  getPaymentPayload(task: A2ATask): PaymentPayload | null {
    if (!task.message?.metadata) {
      return null;
    }
    return task.message.metadata[X402Metadata.PAYLOAD_KEY] as PaymentPayload || null;
  }

  /**
   * Get payment payload from message
   */
  getPaymentPayloadFromMessage(message: A2AMessage | null): PaymentPayload | null {
    if (!message?.metadata) {
      return null;
    }
    return message.metadata[X402Metadata.PAYLOAD_KEY] as PaymentPayload || null;
  }

  /**
   * Create payment required message
   */
  createPaymentRequiredMessage(
    requirements: X402PaymentRequiredResponse,
    message?: string
  ): A2AMessage {
    return {
      role: "assistant",
      content: message || "Payment required to proceed",
      metadata: {
        [X402Metadata.STATUS_KEY]: PaymentStatus.PAYMENT_REQUIRED,
        [X402Metadata.REQUIRED_KEY]: requirements,
      },
    };
  }

  /**
   * Create payment submitted message
   */
  createPaymentSubmittedMessage(payload: PaymentPayload): A2AMessage {
    return {
      role: "user",
      content: "Payment submitted",
      metadata: {
        [X402Metadata.STATUS_KEY]: PaymentStatus.PAYMENT_SUBMITTED,
        [X402Metadata.PAYLOAD_KEY]: payload,
      },
    };
  }

  /**
   * Create payment completed message
   */
  createPaymentCompletedMessage(receipts: any[]): A2AMessage {
    return {
      role: "assistant",
      content: "Payment completed successfully",
      metadata: {
        [X402Metadata.STATUS_KEY]: PaymentStatus.PAYMENT_COMPLETED,
        [X402Metadata.RECEIPTS_KEY]: receipts,
      },
    };
  }

  /**
   * Create payment failed message
   */
  createPaymentFailedMessage(errorCode: string, reason?: string): A2AMessage {
    return {
      role: "assistant",
      content: reason || "Payment failed",
      metadata: {
        [X402Metadata.STATUS_KEY]: PaymentStatus.PAYMENT_FAILED,
        [X402Metadata.ERROR_KEY]: errorCode,
      },
    };
  }
}

