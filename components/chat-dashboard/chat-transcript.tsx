import { useMemo } from "react";
import { Bot, User, Loader2 } from "lucide-react";
import type { ChatMessage, PaymentChatMessage, PaymentStatus } from "./chat-types";
import { PaymentCard } from "./payment-card";

interface ChatTranscriptProps {
  messages: ChatMessage[];
  isProcessing: boolean;
  onStatusChange: (invoiceId: string, status: PaymentStatus) => void;
  onPaymentSuccess: (invoiceId: string, signature: string) => void;
  onPaymentError: (invoiceId: string, message: string) => void;
}

function PaymentMessageBlock(props: {
  message: PaymentChatMessage;
  onStatusChange: ChatTranscriptProps["onStatusChange"];
  onPaymentSuccess: ChatTranscriptProps["onPaymentSuccess"];
  onPaymentError: ChatTranscriptProps["onPaymentError"];
}) {
  const { message, onStatusChange, onPaymentSuccess, onPaymentError } = props;
  return (
    <PaymentCard
      message={message}
      onStatusChange={onStatusChange}
      onSuccess={onPaymentSuccess}
      onError={onPaymentError}
    />
  );
}

export function ChatTranscript({
  messages,
  isProcessing,
  onStatusChange,
  onPaymentError,
  onPaymentSuccess,
}: ChatTranscriptProps) {
  const renderedMessages = useMemo(
    () =>
      messages.map((msg) => {
        if (msg.type === "payment") {
          return (
            <div key={msg.id} className="flex gap-3">
              <div className="w-9 h-9 rounded-full bg-primary/20 flex items-center justify-center flex-shrink-0">
                <Bot className="w-4 h-4 text-primary" />
              </div>
              <PaymentMessageBlock
                message={msg}
                onStatusChange={onStatusChange}
                onPaymentError={onPaymentError}
                onPaymentSuccess={onPaymentSuccess}
              />
            </div>
          );
        }

        const isUser = msg.role === "user";
        return (
          <div
            key={msg.id}
            className={`flex gap-3 ${isUser ? "justify-end" : "justify-start"}`}
          >
            {!isUser && (
              <div className="w-9 h-9 rounded-full bg-primary/20 flex items-center justify-center flex-shrink-0">
                <Bot className="w-4 h-4 text-primary" />
              </div>
            )}
            <div
              className={`max-w-[80%] rounded-2xl px-4 py-3 font-mono text-sm leading-relaxed ${
                isUser
                  ? "bg-primary/10 text-primary border border-primary/30"
                  : "bg-blue-950/40 text-blue-100 border border-blue-500/20"
              }`}
            >
              {msg.content}
            </div>
            {isUser && (
              <div className="w-9 h-9 rounded-full bg-blue-900/50 flex items-center justify-center flex-shrink-0">
                <User className="w-4 h-4 text-blue-200" />
              </div>
            )}
          </div>
        );
      }),
    [messages, onPaymentError, onPaymentSuccess, onStatusChange]
  );

  return (
    <div className="rounded-3xl border border-blue-500/30 bg-blue-950/30 backdrop-blur-xl p-6 space-y-4 min-h-[420px] max-h-[520px] overflow-y-auto scroll-smooth">
      {renderedMessages}
      {isProcessing && (
        <div className="flex items-center gap-3 text-blue-300 font-mono text-sm">
          <Loader2 className="w-4 h-4 animate-spin" />
          SolWave is thinking...
        </div>
      )}
    </div>
  );
}

