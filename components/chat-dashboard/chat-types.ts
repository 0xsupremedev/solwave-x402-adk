import { X402PaymentRequest } from "@/lib/x402/types";

export type ChatRole = "user" | "agent" | "system";
export type ChatMessageType = "text" | "payment";
export type PaymentStatus = "pending" | "submitted" | "confirmed" | "failed";

export interface BaseChatMessage {
  id: string;
  role: ChatRole;
  type: ChatMessageType;
  content: string;
  createdAt: string;
}

export interface TextChatMessage extends BaseChatMessage {
  type: "text";
}

export interface PaymentMeta {
  invoice: X402PaymentRequest;
  status: PaymentStatus;
  signature?: string;
  description?: string;
}

export interface PaymentChatMessage extends BaseChatMessage {
  type: "payment";
  payment: PaymentMeta;
}

export type ChatMessage = TextChatMessage | PaymentChatMessage;

