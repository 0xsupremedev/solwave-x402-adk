/**
 * A2A x402 Protocol Types
 * Ported from Python: x402_a2a/src/x402_a2a/types/
 */

/**
 * Payment Status Enum
 * Ported from: types/state.py
 */
export enum PaymentStatus {
  PAYMENT_REQUIRED = "payment-required",
  PAYMENT_SUBMITTED = "payment-submitted",
  PAYMENT_VERIFIED = "payment-verified",
  PAYMENT_REJECTED = "payment-rejected",
  PAYMENT_COMPLETED = "payment-completed",
  PAYMENT_FAILED = "payment-failed",
}

/**
 * x402 Metadata Keys
 * Ported from: types/state.py
 */
export class X402Metadata {
  static readonly STATUS_KEY = "x402.payment.status";
  static readonly REQUIRED_KEY = "x402.payment.required"; // Contains x402PaymentRequiredResponse
  static readonly PAYLOAD_KEY = "x402.payment.payload"; // Contains PaymentPayload
  static readonly RECEIPTS_KEY = "x402.payment.receipts"; // Contains array of SettleResponse objects
  static readonly ERROR_KEY = "x402.payment.error"; // Error code (when failed)
}

/**
 * Payment Requirements
 * Ported from: x402.types PaymentRequirements
 */
export interface PaymentRequirements {
  scheme: string; // "exact" or other payment schemes
  network: string; // Blockchain network (e.g., "solana", "base")
  asset: string; // Token/asset address
  pay_to: string; // Recipient address
  max_amount_required: string; // Amount in atomic units
  resource: string; // Resource identifier
  description?: string; // Human-readable description
  mime_type?: string; // Expected response content type
  max_timeout_seconds?: number; // Payment validity timeout
  output_schema?: any; // Response schema
  extra?: any; // Additional fields (e.g., EIP712 domain)
}

/**
 * Payment Payload
 * Ported from: x402.types PaymentPayload
 */
export interface PaymentPayload {
  payment_requirements: PaymentRequirements;
  signature: string; // Cryptographic signature
  signer: string; // Signer address
  timestamp?: number; // Timestamp
}

/**
 * x402 Payment Required Response
 * Ported from: x402.types x402PaymentRequiredResponse
 */
export interface X402PaymentRequiredResponse {
  requirements: PaymentRequirements[];
  message?: string; // Optional message to user
}

/**
 * Verify Response
 * Ported from: x402.types VerifyResponse
 */
export interface VerifyResponse {
  is_valid: boolean;
  invalid_reason?: string;
  verified_at?: string;
}

/**
 * Settle Response
 * Ported from: x402.types SettleResponse
 */
export interface SettleResponse {
  success: boolean;
  transaction?: string; // Transaction hash
  network?: string;
  payer?: string;
  error_reason?: string;
  settled_at?: string;
}

/**
 * Supported Networks
 */
export type SupportedNetworks = "solana" | "base" | "ethereum" | "polygon";

/**
 * A2A Task State
 */
export enum TaskState {
  INIT = "init",
  WORKING = "working",
  INPUT_REQUIRED = "input-required",
  COMPLETED = "completed",
  FAILED = "failed",
}

/**
 * A2A Message with x402 metadata
 */
export interface A2AMessage {
  id?: string;
  role?: "user" | "assistant" | "system";
  content?: string;
  metadata?: {
    [X402Metadata.STATUS_KEY]?: PaymentStatus;
    [X402Metadata.REQUIRED_KEY]?: X402PaymentRequiredResponse;
    [X402Metadata.PAYLOAD_KEY]?: PaymentPayload;
    [X402Metadata.RECEIPTS_KEY]?: SettleResponse[];
    [X402Metadata.ERROR_KEY]?: string;
    [key: string]: any;
  };
}

/**
 * A2A Task
 */
export interface A2ATask {
  id: string;
  context_id?: string;
  state: TaskState;
  message?: A2AMessage;
  status?: {
    state: TaskState;
    error?: string;
  };
}

