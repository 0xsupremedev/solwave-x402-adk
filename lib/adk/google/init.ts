/**
 * ADK Initialization
 * Creates singleton ADK instance with environment configuration
 */

import { ADKProvider, ADKTool } from "./provider";
import { ToolRegistry } from "./tool-registry";

let adkInstance: ADKProvider | null = null;
let toolRegistry: ToolRegistry | null = null;

/**
 * Get or create singleton ADK instance
 */
export async function getADKInstance(): Promise<ADKProvider> {
  if (!adkInstance) {
    const model = process.env.GOOGLE_ADK_MODEL || "gemini-2.0-flash-exp";
    const sessionId = process.env.GOOGLE_ADK_SESSION_ID || `session-${Date.now()}`;
    
    adkInstance = new ADKProvider({
      model,
      name: "solwave-agent",
      instruction: getDefaultInstruction(),
      description: "SolWave AI Agent with x402 payment capabilities",
      sessionId,
    });

    await adkInstance.initialize();
  }

  return adkInstance;
}

/**
 * Get or create tool registry
 */
export function getToolRegistry(): ToolRegistry {
  if (!toolRegistry) {
    toolRegistry = new ToolRegistry();
  }
  return toolRegistry;
}

/**
 * Register x402 tools with ADK
 */
export async function registerX402Tools(tools: ADKTool[]): Promise<void> {
  const adk = await getADKInstance();
  const registry = getToolRegistry();

  tools.forEach((tool) => {
    registry.register(tool);
    adk.registerTool(tool);
  });
}

/**
 * Get default agent instruction
 */
function getDefaultInstruction(): string {
  return `
You are SolWave, an AI agent that helps users with Solana blockchain payments using the x402 protocol.

Your capabilities include:
- Creating payment invoices
- Verifying payments on-chain
- Processing payment requests
- Managing payment workflows

When a user requests a payment:
1. Create an invoice using the create_invoice tool
2. Wait for payment confirmation using wait_for_payment
3. Verify the payment on-chain
4. Complete the transaction

Always be helpful, clear, and transparent about payment requirements.
`;
}

/**
 * Initialize ADK with all tools
 */
export async function initializeADK(tools: ADKTool[] = []): Promise<ADKProvider> {
  const adk = await getADKInstance();
  
  if (tools.length > 0) {
    await registerX402Tools(tools);
  }

  return adk;
}

/**
 * Export singleton instance getter
 */
export const adk = {
  getInstance: getADKInstance,
  getRegistry: getToolRegistry,
  registerTools: registerX402Tools,
  initialize: initializeADK,
};

