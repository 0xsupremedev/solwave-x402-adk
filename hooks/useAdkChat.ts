import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { ChatMessage, PaymentStatus } from "@/components/chat-dashboard/chat-types";
import { adk } from "@/lib/adk/google";
import { getAllADKTools } from "@/lib/adk/adapters";
import { getPaymentFlowAdapter } from "@/lib/adk/adapters";
import { X402PaymentRequest } from "@/lib/x402/types";

type HistoryItem = { role: string; content: string };

const INITIAL_MESSAGE: ChatMessage = {
  id: "agent-welcome",
  role: "agent",
  type: "text",
  content: "Welcome to SolWave. Ask me to buy something or run a payment workflow on Solana.",
  createdAt: new Date().toISOString(),
};

function buildHistory(messages: ChatMessage[]): HistoryItem[] {
  return messages
    .filter((msg) => msg.type === "text")
    .slice(-10)
    .map((msg) => ({
      role: msg.role,
      content: msg.content,
    }));
}

function createPaymentMessage(invoice: X402PaymentRequest): ChatMessage {
  return {
    id: `invoice-${invoice.invoiceId}`,
    role: "agent",
    type: "payment",
    content: `Payment required: ${invoice.amount} ${invoice.token}`,
    createdAt: new Date().toISOString(),
    payment: {
      invoice,
      status: "pending",
    },
  };
}

export function useAdkChat() {
  const [messages, setMessages] = useState<ChatMessage[]>([INITIAL_MESSAGE]);
  const [isProcessing, setIsProcessing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [isReady, setIsReady] = useState(false);
  const agentRef = useRef<Awaited<ReturnType<typeof adk.initialize>> | null>(null);
  const messagesRef = useRef<ChatMessage[]>([INITIAL_MESSAGE]);
  const paymentFlow = useMemo(() => getPaymentFlowAdapter(), []);

  useEffect(() => {
    messagesRef.current = messages;
  }, [messages]);

  const ensureAgent = useCallback(async () => {
    if (!agentRef.current) {
      const tools = getAllADKTools();
      agentRef.current = await adk.initialize(tools);
      setIsReady(true);
    }
    return agentRef.current;
  }, []);

  useEffect(() => {
    ensureAgent().catch((err) => {
      console.error("Failed to initialize ADK", err);
      setError(err instanceof Error ? err.message : "Unable to initialize agent");
    });
  }, [ensureAgent]);

  useEffect(() => {
    const unsubscribe = paymentFlow.onEvent((event) => {
      if (event.type === "INVOICE_CREATED") {
        setMessages((prev) => {
          const exists = prev.some(
            (msg) =>
              msg.type === "payment" &&
              msg.payment.invoice.invoiceId === event.invoice.invoiceId
          );
          if (exists) return prev;
          return [...prev, createPaymentMessage(event.invoice)];
        });
        return;
      }

      if (event.type === "PAYMENT_CONFIRMED") {
        setMessages((prev) =>
          prev.map((msg) => {
            if (
              msg.type === "payment" &&
              msg.payment.invoice.invoiceId === event.invoiceId
            ) {
              return {
                ...msg,
                payment: {
                  ...msg.payment,
                  status: "confirmed",
                  signature: event.signature,
                },
                content: `Payment confirmed: ${msg.payment.invoice.amount} ${msg.payment.invoice.token}`,
              };
            }
            return msg;
          })
        );

        setMessages((prev) => [
          ...prev,
          {
            id: `receipt-${event.invoiceId}`,
            role: "agent",
            type: "text",
            content: "Payment received. Delivering the requested service.",
            createdAt: new Date().toISOString(),
          },
        ]);
        return;
      }

      if (event.type === "PAYMENT_FAILED") {
        setMessages((prev) =>
          prev.map((msg) => {
            if (
              msg.type === "payment" &&
              (!event.invoiceId ||
                msg.payment.invoice.invoiceId === event.invoiceId)
            ) {
              return {
                ...msg,
                payment: {
                  ...msg.payment,
                  status: "failed",
                },
                content: `Payment failed: ${event.error}`,
              };
            }
            return msg;
          })
        );
        return;
      }
    });

    return unsubscribe;
  }, [paymentFlow]);

  const updatePaymentStatus = useCallback((invoiceId: string, status: PaymentStatus) => {
    setMessages((prev) =>
      prev.map((msg) => {
        if (msg.type === "payment" && msg.payment.invoice.invoiceId === invoiceId) {
          return {
            ...msg,
            payment: {
              ...msg.payment,
              status,
            },
          };
        }
        return msg;
      })
    );
  }, []);

  const sendMessage = useCallback(
    async (text: string) => {
      const trimmed = text.trim();
      if (!trimmed) return;

      const userMessage: ChatMessage = {
        id: `user-${Date.now()}`,
        role: "user",
        type: "text",
        content: trimmed,
        createdAt: new Date().toISOString(),
      };

      setMessages((prev) => [...prev, userMessage]);
      setIsProcessing(true);
      setError(null);

      try {
        const agent = await ensureAgent();
        const history = buildHistory([...messagesRef.current, userMessage]);
        const response = await agent.run(trimmed, { history });

        const agentMessage: ChatMessage = {
          id: `agent-${Date.now()}`,
          role: "agent",
          type: "text",
          content: response,
          createdAt: new Date().toISOString(),
        };

        setMessages((prev) => [...prev, agentMessage]);
      } catch (err: any) {
        console.error("Agent error", err);
        setError(err?.message || "Failed to send message");
        setMessages((prev) => [
          ...prev,
          {
            id: `error-${Date.now()}`,
            role: "system",
            type: "text",
            content: "Agent unavailable. Please try again.",
            createdAt: new Date().toISOString(),
          },
        ]);
      } finally {
        setIsProcessing(false);
      }
    },
    [ensureAgent]
  );

  const handlePaymentSuccess = useCallback(
    (invoiceId: string, signature: string) => {
      paymentFlow.handlePaymentConfirmed(signature, invoiceId);
    },
    [paymentFlow]
  );

  const handlePaymentError = useCallback(
    (invoiceId: string, message: string) => {
      paymentFlow.handlePaymentFailed(message, invoiceId);
    },
    [paymentFlow]
  );

  return {
    messages,
    isProcessing,
    isReady,
    error,
    sendMessage,
    clearError: () => setError(null),
    updatePaymentStatus,
    handlePaymentSuccess,
    handlePaymentError,
  };
}

