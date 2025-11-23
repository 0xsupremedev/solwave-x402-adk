/**
 * Message Builders for A2A x402 Protocol
 * Builds A2A-compliant messages with x402 payment metadata
 */

import {
  A2AMessage,
  A2ATask,
  PaymentStatus,
  X402Metadata,
  PaymentPayload,
  X402PaymentRequiredResponse,
  PaymentRequirements,
  SettleResponse,
  TaskState,
} from "./types";

/**
 * Build payment-required task message
 */
export function buildPaymentRequiredTask(
  taskId: string,
  contextId: string,
  requirements: PaymentRequirements[],
  message?: string
): A2ATask {
  const paymentResponse: X402PaymentRequiredResponse = {
    requirements,
    message,
  };

  return {
    id: taskId,
    context_id: contextId,
    state: TaskState.INPUT_REQUIRED,
    message: {
      role: "assistant",
      content: message || "Payment required to proceed",
      metadata: {
        [X402Metadata.STATUS_KEY]: PaymentStatus.PAYMENT_REQUIRED,
        [X402Metadata.REQUIRED_KEY]: paymentResponse,
      },
    },
  };
}

/**
 * Build payment-submitted message
 */
export function buildPaymentSubmittedMessage(
  payload: PaymentPayload,
  taskId: string
): A2AMessage {
  return {
    id: `msg-${Date.now()}`,
    role: "user",
    content: "Payment submitted",
    metadata: {
      [X402Metadata.STATUS_KEY]: PaymentStatus.PAYMENT_SUBMITTED,
      [X402Metadata.PAYLOAD_KEY]: payload,
      taskId, // Include taskId for correlation
    },
  };
}

/**
 * Build payment-completed task
 */
export function buildPaymentCompletedTask(
  taskId: string,
  contextId: string,
  receipts: SettleResponse[],
  result?: any
): A2ATask {
  return {
    id: taskId,
    context_id: contextId,
    state: TaskState.COMPLETED,
    message: {
      role: "assistant",
      content: result || "Payment completed successfully. Service delivered.",
      metadata: {
        [X402Metadata.STATUS_KEY]: PaymentStatus.PAYMENT_COMPLETED,
        [X402Metadata.RECEIPTS_KEY]: receipts,
      },
    },
  };
}

/**
 * Build payment-verified task (intermediate state)
 */
export function buildPaymentVerifiedTask(
  taskId: string,
  contextId: string
): A2ATask {
  return {
    id: taskId,
    context_id: contextId,
    state: TaskState.WORKING,
    message: {
      role: "assistant",
      content: "Payment verified. Processing service...",
      metadata: {
        [X402Metadata.STATUS_KEY]: PaymentStatus.PAYMENT_VERIFIED,
      },
    },
  };
}

/**
 * Build payment-failed task
 */
export function buildPaymentFailedTask(
  taskId: string,
  contextId: string,
  errorCode: string,
  reason?: string
): A2ATask {
  return {
    id: taskId,
    context_id: contextId,
    state: TaskState.FAILED,
    message: {
      role: "assistant",
      content: reason || "Payment processing failed",
      metadata: {
        [X402Metadata.STATUS_KEY]: PaymentStatus.PAYMENT_FAILED,
        [X402Metadata.ERROR_KEY]: errorCode,
      },
    },
  };
}

