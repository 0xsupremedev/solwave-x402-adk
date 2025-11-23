/**
 * Merchant Agent Orchestrator
 * Ported from Python: x402_a2a/src/x402_a2a/executors/server.py
 * Enhances existing merchant-agent.ts with A2A x402 orchestration
 */

import {
  A2ATask,
  PaymentStatus,
  PaymentPayload,
  PaymentRequirements,
  X402PaymentRequiredResponse,
  SettleResponse,
  VerifyResponse,
  TaskState,
} from "../extensions/types";
import { X402Utils } from "../extensions/utils";
import {
  buildPaymentRequiredTask,
  buildPaymentCompletedTask,
  buildPaymentFailedTask,
  buildPaymentVerifiedTask,
} from "../extensions/message-builders";
import { verifyPayment, settlePayment, FacilitatorClient } from "../x402-tools/payment-tooling";
import { SolanaFacilitatorClient } from "../x402-tools/payment-tooling";

/**
 * Merchant Orchestrator Configuration
 */
export interface MerchantOrchestratorConfig {
  facilitatorClient?: FacilitatorClient;
  autoSettle?: boolean; // Automatically settle after verification
  requireVerification?: boolean; // Require verification before settlement
}

/**
 * Merchant Orchestrator
 * Handles payment flow orchestration for merchant agents
 */
export class MerchantOrchestrator {
  private utils: X402Utils;
  private facilitator: FacilitatorClient;
  private config: MerchantOrchestratorConfig;
  private paymentRequirementsStore: Map<string, PaymentRequirements[]> = new Map();

  constructor(config: MerchantOrchestratorConfig = {}) {
    this.utils = new X402Utils();
    this.facilitator = config.facilitatorClient || new SolanaFacilitatorClient();
    this.config = {
      autoSettle: true,
      requireVerification: true,
      ...config,
    };
  }

  /**
   * Store payment requirements for a task
   */
  storePaymentRequirements(taskId: string, requirements: PaymentRequirements[]): void {
    this.paymentRequirementsStore.set(taskId, requirements);
  }

  /**
   * Get payment requirements for a task
   */
  getPaymentRequirements(taskId: string): PaymentRequirements[] | null {
    return this.paymentRequirementsStore.get(taskId) || null;
  }

  /**
   * Create payment required task
   */
  createPaymentRequiredTask(
    taskId: string,
    contextId: string,
    requirements: PaymentRequirements[],
    message?: string
  ): A2ATask {
    // Store requirements for later verification
    this.storePaymentRequirements(taskId, requirements);

    return buildPaymentRequiredTask(taskId, contextId, requirements, message);
  }

  /**
   * Process payment submission
   * Verifies and settles payment, then executes service
   */
  async processPaymentSubmission(
    taskId: string,
    contextId: string,
    payload: PaymentPayload
  ): Promise<A2ATask> {
    // Get stored payment requirements
    const requirementsList = this.getPaymentRequirements(taskId);
    if (!requirementsList || requirementsList.length === 0) {
      return buildPaymentFailedTask(
        taskId,
        contextId,
        "INVALID_TASK",
        "No payment requirements found for this task"
      );
    }

    // Find matching requirement
    const requirement = requirementsList.find(
      (req) => req.network === payload.payment_requirements.network
    );

    if (!requirement) {
      return buildPaymentFailedTask(
        taskId,
        contextId,
        "INVALID_REQUIREMENT",
        "Payment requirement mismatch"
      );
    }

    // Verify payment
    const verifyResult = await verifyPayment(payload, requirement, this.facilitator);

    if (!verifyResult.is_valid) {
      return buildPaymentFailedTask(
        taskId,
        contextId,
        "VERIFICATION_FAILED",
        verifyResult.invalid_reason || "Payment verification failed"
      );
    }

    // Record verification
    const verifiedTask = buildPaymentVerifiedTask(taskId, contextId);

    // Settle payment if auto-settle is enabled
    if (this.config.autoSettle) {
      const settleResult = await settlePayment(payload, requirement, this.facilitator);

      if (!settleResult.success) {
        return buildPaymentFailedTask(
          taskId,
          contextId,
          "SETTLEMENT_FAILED",
          settleResult.error_reason || "Payment settlement failed"
        );
      }

      // Return completed task with receipt
      return buildPaymentCompletedTask(taskId, contextId, [settleResult]);
    }

    // Return verified task (settlement will happen separately)
    return verifiedTask;
  }

  /**
   * Settle payment manually
   */
  async settlePaymentManually(
    taskId: string,
    contextId: string,
    payload: PaymentPayload
  ): Promise<SettleResponse> {
    const requirementsList = this.getPaymentRequirements(taskId);
    if (!requirementsList || requirementsList.length === 0) {
      throw new Error("No payment requirements found for this task");
    }

    const requirement = requirementsList.find(
      (req) => req.network === payload.payment_requirements.network
    );

    if (!requirement) {
      throw new Error("Payment requirement mismatch");
    }

    return await settlePayment(payload, requirement, this.facilitator);
  }

  /**
   * Complete task with service result
   */
  completeTaskWithResult(
    taskId: string,
    contextId: string,
    receipts: SettleResponse[],
    result: any
  ): A2ATask {
    return buildPaymentCompletedTask(taskId, contextId, receipts, result);
  }

  /**
   * Check if payment is required for task
   */
  isPaymentRequired(task: A2ATask): boolean {
    const status = this.utils.getPaymentStatus(task);
    return status === PaymentStatus.PAYMENT_REQUIRED;
  }

  /**
   * Check if payment is submitted
   */
  isPaymentSubmitted(task: A2ATask): boolean {
    const status = this.utils.getPaymentStatus(task);
    return status === PaymentStatus.PAYMENT_SUBMITTED;
  }

  /**
   * Check if payment is completed
   */
  isPaymentCompleted(task: A2ATask): boolean {
    const status = this.utils.getPaymentStatus(task);
    return status === PaymentStatus.PAYMENT_COMPLETED;
  }

  /**
   * Get payment payload from task
   */
  getPaymentPayload(task: A2ATask): PaymentPayload | null {
    return this.utils.getPaymentPayload(task);
  }

  /**
   * Get payment requirements from task
   */
  getPaymentRequirementsFromTask(task: A2ATask): X402PaymentRequiredResponse | null {
    return this.utils.getPaymentRequirements(task);
  }
}

