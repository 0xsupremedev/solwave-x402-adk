"use client";

import { useState, useRef, useEffect } from "react";
import { MessageSquare, Send, Bot, User } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { PaymentMessage } from "./payment-message";

export interface ChatMessage {
  id: string;
  role: "user" | "agent";
  content: string;
  timestamp: Date;
  type?: "text" | "payment";
  paymentData?: {
    invoiceId: string;
    amount: string;
    token: string;
    status: string;
  };
}

interface ChatInterfaceProps {
  agentId?: string;
  onPaymentRequest?: (invoiceId: string) => void;
}

export function ChatInterface({ agentId, onPaymentRequest }: ChatInterfaceProps) {
  const [messages, setMessages] = useState<ChatMessage[]>([
    {
      id: "1",
      role: "agent",
      content: "Hello! I'm an autonomous commerce agent. I can help you make purchases using x402 payments on Solana. What would you like to buy?",
      timestamp: new Date(),
      type: "text",
    },
  ]);
  const [input, setInput] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const messagesEndRef = useRef<HTMLDivElement>(null);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  };

  useEffect(() => {
    scrollToBottom();
  }, [messages]);

  const handleSend = async () => {
    if (!input.trim() || isLoading) return;

    const userMessage: ChatMessage = {
      id: Date.now().toString(),
      role: "user",
      content: input,
      timestamp: new Date(),
      type: "text",
    };

    setMessages((prev) => [...prev, userMessage]);
    setInput("");
    setIsLoading(true);

    // Simulate agent response
    setTimeout(() => {
      let agentResponse: ChatMessage;

      // Check if user wants to buy something
      if (input.toLowerCase().includes("buy") || input.toLowerCase().includes("purchase")) {
        agentResponse = {
          id: (Date.now() + 1).toString(),
          role: "agent",
          content: "I'll create an invoice for your purchase. Please approve the payment to proceed.",
          timestamp: new Date(),
          type: "payment",
          paymentData: {
            invoiceId: `INV-${Date.now()}`,
            amount: "1.0",
            token: "USDC",
            status: "pending",
          },
        };
      } else {
        agentResponse = {
          id: (Date.now() + 1).toString(),
          role: "agent",
          content: "I understand. How can I help you further?",
          timestamp: new Date(),
          type: "text",
        };
      }

      setMessages((prev) => [...prev, agentResponse]);
      setIsLoading(false);

      if (agentResponse.type === "payment" && agentResponse.paymentData && onPaymentRequest) {
        onPaymentRequest(agentResponse.paymentData.invoiceId);
      }
    }, 1000);
  };

  return (
    <Card className="border-border bg-background/50 backdrop-blur-sm h-[600px] flex flex-col">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <MessageSquare className="w-5 h-5" />
          Agent Chat
        </CardTitle>
      </CardHeader>
      <CardContent className="flex-1 flex flex-col space-y-4">
        <div className="flex-1 overflow-y-auto space-y-3 border border-border rounded-lg p-4 bg-background/30">
          {messages.map((msg) => (
            <div
              key={msg.id}
              className={`flex gap-3 ${msg.role === "user" ? "justify-end" : "justify-start"}`}
            >
              {msg.role === "agent" && (
                <div className="w-8 h-8 rounded-full bg-primary/20 flex items-center justify-center flex-shrink-0">
                  <Bot className="w-4 h-4 text-primary" />
                </div>
              )}
              <div className={`max-w-[75%] ${msg.role === "user" ? "order-2" : ""}`}>
                {msg.type === "payment" && msg.paymentData ? (
                  <PaymentMessage
                    invoiceId={msg.paymentData.invoiceId}
                    amount={msg.paymentData.amount}
                    token={msg.paymentData.token}
                    status={msg.paymentData.status}
                  />
                ) : (
                  <div
                    className={`rounded-lg p-3 font-mono text-sm ${
                      msg.role === "user"
                        ? "bg-primary/20 text-primary"
                        : "bg-blue-950/30 text-blue-200"
                    }`}
                  >
                    {msg.content}
                  </div>
                )}
              </div>
              {msg.role === "user" && (
                <div className="w-8 h-8 rounded-full bg-blue-900/30 flex items-center justify-center flex-shrink-0 order-3">
                  <User className="w-4 h-4 text-blue-300" />
                </div>
              )}
            </div>
          ))}
          {isLoading && (
            <div className="flex justify-start gap-3">
              <div className="w-8 h-8 rounded-full bg-primary/20 flex items-center justify-center flex-shrink-0">
                <Bot className="w-4 h-4 text-primary" />
              </div>
              <div className="bg-blue-950/30 rounded-lg p-3">
                <div className="flex gap-1">
                  <div className="w-2 h-2 bg-blue-400 rounded-full animate-bounce" style={{ animationDelay: "0ms" }} />
                  <div className="w-2 h-2 bg-blue-400 rounded-full animate-bounce" style={{ animationDelay: "150ms" }} />
                  <div className="w-2 h-2 bg-blue-400 rounded-full animate-bounce" style={{ animationDelay: "300ms" }} />
                </div>
              </div>
            </div>
          )}
          <div ref={messagesEndRef} />
        </div>
        <div className="flex gap-2">
          <Input
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyPress={(e) => e.key === "Enter" && handleSend()}
            placeholder="Type your message..."
            className="font-mono"
            disabled={isLoading}
          />
          <Button variant="default" onClick={handleSend} disabled={isLoading || !input.trim()}>
            <Send />
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}

