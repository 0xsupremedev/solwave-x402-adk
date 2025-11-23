"use client";

import { useState } from "react";
import { Button } from "./ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "./ui/card";
import { MessageSquare, CheckCircle2, Send, Loader2 } from "lucide-react";

interface Message {
  id: string;
  role: "agent" | "user";
  content: string;
  timestamp: Date;
}

export function LiveDemo() {
  const [messages, setMessages] = useState<Message[]>([]);
  const [isProcessing, setIsProcessing] = useState(false);

  const handleAction = async (action: string) => {
    setIsProcessing(true);
    
    // Simulate agent response
    const userMessage: Message = {
      id: Date.now().toString(),
      role: "user",
      content: action,
      timestamp: new Date(),
    };

    setMessages((prev) => [...prev, userMessage]);

    setTimeout(() => {
      let agentResponse = "";
      if (action === "Say Hello") {
        agentResponse = "Hello! I'm an autonomous commerce agent. I can help you make purchases using x402 payments on Solana. What would you like to buy?";
      } else if (action === "Buy a Banana") {
        agentResponse = "I'll create an invoice for 1 Banana. Amount: 0.1 USDC. Please approve the payment to proceed.";
      } else if (action === "Send Test Invoice") {
        agentResponse = "Invoice created: INV-12345\nAmount: 1.0 USDC\nStatus: Pending\nClick 'Approve Payment' to continue.";
      } else {
        agentResponse = `Processing: ${action}...`;
      }

      const agentMessage: Message = {
        id: (Date.now() + 1).toString(),
        role: "agent",
        content: agentResponse,
        timestamp: new Date(),
      };

      setMessages((prev) => [...prev, agentMessage]);
      setIsProcessing(false);
    }, 1000);
  };

  return (
    <section id="demo" className="py-24 container">
      <div className="text-center mb-16">
        <h2 className="text-3xl sm:text-4xl md:text-5xl font-sentient mb-4">
          Try an <i className="font-light">Autonomous Commerce Agent</i>
        </h2>
        <p className="font-mono text-xs sm:text-sm text-blue-300 text-balance max-w-2xl mx-auto mb-6 sm:mb-8 px-4 sm:px-0">
          Chat with an agent that can: take orders, generate invoices, ask for payment approval, trigger a real Solana transaction, verify confirmation, return receipt & explorer link. This is end-to-end AI-native payments powered by x402.
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-6 sm:gap-8">
        <Card className="border-border bg-background/50 backdrop-blur-sm">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <MessageSquare className="w-5 h-5" />
              Agent Chat
            </CardTitle>
            <CardDescription>Interactive demo of agent-to-agent commerce</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              <div className="h-48 sm:h-64 overflow-y-auto border border-border rounded-lg p-3 sm:p-4 bg-background/30 space-y-2 sm:space-y-3">
                {messages.length === 0 ? (
                  <div className="text-center text-blue-400/60 font-mono text-sm py-8">
                    Start a conversation by clicking an action below
                  </div>
                ) : (
                  messages.map((msg) => (
                    <div
                      key={msg.id}
                      className={`flex ${msg.role === "user" ? "justify-end" : "justify-start"}`}
                    >
                      <div
                        className={`max-w-[80%] rounded-lg p-3 font-mono text-sm ${
                          msg.role === "user"
                            ? "bg-primary/20 text-primary"
                            : "bg-foreground/5 text-foreground/80"
                        }`}
                      >
                        {msg.content}
                      </div>
                    </div>
                  ))
                )}
                {isProcessing && (
                  <div className="flex justify-start">
                    <div className="bg-foreground/5 rounded-lg p-3 flex items-center gap-2">
                      <Loader2 className="w-4 h-4 animate-spin" />
                      <span className="font-mono text-sm text-foreground/60">Processing...</span>
                    </div>
                  </div>
                )}
              </div>
            </div>
          </CardContent>
        </Card>

        <Card className="border-border bg-background/50 backdrop-blur-sm">
          <CardHeader>
            <CardTitle>Quick Actions</CardTitle>
            <CardDescription>Test the agent with these actions</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-3">
              <Button
                variant="default"
                className="w-full justify-start"
                onClick={() => handleAction("Say Hello")}
                disabled={isProcessing}
              >
                <Send />
                Say Hello
              </Button>
              <Button
                variant="default"
                className="w-full justify-start"
                onClick={() => handleAction("Buy a Banana")}
                disabled={isProcessing}
              >
                <CheckCircle2 />
                Buy a Banana
              </Button>
              <Button
                variant="default"
                className="w-full justify-start"
                onClick={() => handleAction("Send Test Invoice")}
                disabled={isProcessing}
              >
                <Send />
                Send Test Invoice
              </Button>
              <Button
                variant="default"
                className="w-full justify-start"
                onClick={() => handleAction("Generate Random Number")}
                disabled={isProcessing}
              >
                <Send />
                Generate Random Number
              </Button>
              <Button
                variant="default"
                className="w-full justify-start"
                onClick={() => handleAction("Inspect Agent Trace")}
                disabled={isProcessing}
              >
                <MessageSquare />
                Inspect Agent Trace
              </Button>
            </div>
          </CardContent>
        </Card>
      </div>
    </section>
  );
}

