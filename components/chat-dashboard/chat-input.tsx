"use client";

import { useState, useEffect, useRef } from "react";
import { Send, ChevronDown } from "lucide-react";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";

interface ChatInputProps {
  onSend: (message: string) => Promise<void> | void;
  disabled?: boolean;
}

export function ChatInput({ onSend, disabled }: ChatInputProps) {
  const [message, setMessage] = useState("");
  const [selectedModel, setSelectedModel] = useState("GPT 4o");
  const [showCursor, setShowCursor] = useState(true);
  const [isFocused, setIsFocused] = useState(false);
  const [typingText, setTypingText] = useState("");
  const [isTyping, setIsTyping] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  // Sample texts to type
  const sampleTexts = [
    "What would like to know",
    "Ask me anything about x402",
    "Try: Buy a banana",
    "How can I help you?",
  ];

  // Auto-typing animation effect
  useEffect(() => {
    if (!isFocused || message) {
      setIsTyping(false);
      setTypingText("");
      return;
    }

    setIsTyping(true);
    let currentTextIndex = 0;
    let currentCharIndex = 0;
    let isDeleting = false;
    let pauseCount = 0;
    let typeInterval: NodeJS.Timeout;

    const animate = () => {
      const currentText = sampleTexts[currentTextIndex];

      if (!isDeleting && currentCharIndex < currentText.length) {
        // Typing forward
        setTypingText(currentText.slice(0, currentCharIndex + 1));
        currentCharIndex++;
      } else if (!isDeleting && currentCharIndex === currentText.length) {
        // Finished typing, pause before deleting
        pauseCount++;
        if (pauseCount >= 25) { // ~2 seconds at 80ms interval
          isDeleting = true;
          pauseCount = 0;
        }
      } else if (isDeleting && currentCharIndex > 0) {
        // Deleting
        setTypingText(currentText.slice(0, currentCharIndex - 1));
        currentCharIndex--;
      } else if (isDeleting && currentCharIndex === 0) {
        // Finished deleting, move to next text
        isDeleting = false;
        currentTextIndex = (currentTextIndex + 1) % sampleTexts.length;
      }
    };

    typeInterval = setInterval(animate, 80);

    return () => {
      if (typeInterval) clearInterval(typeInterval);
      setIsTyping(false);
      setTypingText("");
    };
  }, [isFocused, message]);

  // Blinking cursor effect
  useEffect(() => {
    const interval = setInterval(() => {
      setShowCursor((prev) => !prev);
    }, 530); // Blink every 530ms for a natural typing cursor effect

    return () => clearInterval(interval);
  }, []);

  // Auto-focus effect when component mounts
  useEffect(() => {
    const timer = setTimeout(() => {
      inputRef.current?.focus();
    }, 100);
    return () => clearTimeout(timer);
  }, []);

  const handleSend = async () => {
    if (!message.trim() || disabled) return;
    const value = message;
    setMessage("");
    await onSend(value);
    setTimeout(() => {
      inputRef.current?.focus();
    }, 50);
  };

  return (
    <div className="bg-blue-950/60 backdrop-blur-md border-t border-blue-500/50 shadow-2xl shadow-blue-500/20">
      <div className="container py-3 sm:py-4">
        <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-2 sm:gap-3 max-w-6xl mx-auto">
          {/* Model Selector */}
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button
                variant="default"
                className="bg-blue-900/30 border border-blue-500/50 text-blue-200 hover:bg-blue-800/40 font-mono text-xs sm:text-sm px-2 sm:px-3 h-9 sm:h-10"
              >
                {selectedModel}
                <ChevronDown className="w-3 h-3 ml-1" />
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent className="bg-blue-950 border-blue-500/50">
              <DropdownMenuItem
                className="text-blue-200 hover:bg-blue-900/50"
                onClick={() => setSelectedModel("GPT 4o")}
              >
                GPT 4o
              </DropdownMenuItem>
              <DropdownMenuItem
                className="text-blue-200 hover:bg-blue-900/50"
                onClick={() => setSelectedModel("GPT 3.5")}
              >
                GPT 3.5
              </DropdownMenuItem>
              <DropdownMenuItem
                className="text-blue-200 hover:bg-blue-900/50"
                onClick={() => setSelectedModel("Claude")}
              >
                Claude
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>

          <div className="text-xs font-mono text-blue-400/60 hidden sm:block">(model selector)</div>

          {/* Chat Input */}
          <div className="flex-1 relative min-w-0">
            <div className="relative">
              <Input
                ref={inputRef}
                value={message || typingText}
                onChange={(e) => {
                  setMessage(e.target.value);
                  setIsTyping(false);
                  setTypingText("");
                }}
                onKeyPress={(e) => {
                  if (e.key === "Enter") {
                    handleSend();
                  } else {
                    setIsTyping(false);
                    setTypingText("");
                  }
                }}
                onFocus={() => setIsFocused(true)}
                onBlur={() => {
                  setIsFocused(false);
                  setIsTyping(false);
                  setTypingText("");
                }}
                placeholder={!isFocused ? "What would like to know" : ""}
                className="bg-blue-900/30 border-blue-500/50 text-blue-200 placeholder:text-blue-400/40 font-mono text-xs sm:text-sm h-10 sm:h-12 pr-10 sm:pr-12 focus:border-blue-400/70 focus:ring-2 focus:ring-blue-500/30 shadow-lg shadow-blue-500/20"
                readOnly={(isTyping && !message) || disabled}
                disabled={disabled}
              />
              {/* Auto-typer cursor effect - shows blinking cursor when typing animation is active */}
              {isFocused && (isTyping || (!message && !typingText)) && (
                <div
                  className={`absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none ${
                    showCursor ? "opacity-100" : "opacity-0"
                  } transition-opacity duration-300`}
                  style={{
                    marginLeft: `${(typingText || message || "What would like to know").length * 0.45}rem`,
                  }}
                >
                  <span className="text-blue-400 font-mono text-lg leading-none">|</span>
                </div>
              )}
            </div>
            <Button
              variant="default"
              size="sm"
              onClick={handleSend}
              disabled={!message.trim() || disabled}
              className="absolute right-2 top-1/2 -translate-y-1/2 h-8 w-8 p-0"
            >
              <Send />
            </Button>
          </div>
        </div>
      </div>
    </div>
  );
}

