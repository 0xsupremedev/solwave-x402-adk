/**
 * Payment Required Extension for A2A x402 Protocol
 * Ported from Python: x402_a2a/src/x402_a2a/extension.py
 */

export const X402_EXTENSION_URI = "https://github.com/google-a2a/a2a-x402/v0.1";

export interface ExtensionDeclaration {
  uri: string;
  description: string;
  required: boolean;
}

/**
 * Creates extension declaration for AgentCard
 */
export function getExtensionDeclaration(
  description: string = "Supports x402 payments",
  required: boolean = true
): ExtensionDeclaration {
  return {
    uri: X402_EXTENSION_URI,
    description,
    required,
  };
}

/**
 * Check if x402 extension is activated via HTTP headers
 */
export function checkExtensionActivation(requestHeaders: Record<string, string>): boolean {
  const extensions = requestHeaders["X-A2A-Extensions"] || "";
  return extensions.includes(X402_EXTENSION_URI);
}

/**
 * Echo extension URI in response header to confirm activation
 */
export function addExtensionActivationHeader(
  responseHeaders: Record<string, string>
): Record<string, string> {
  responseHeaders["X-A2A-Extensions"] = X402_EXTENSION_URI;
  return responseHeaders;
}

