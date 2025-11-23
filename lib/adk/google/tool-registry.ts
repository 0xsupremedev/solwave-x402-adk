/**
 * Tool Registry for ADK
 * Maps tool names to handlers with validation
 */

import { ADKTool } from "./provider";

export interface ToolValidationResult {
  valid: boolean;
  error?: string;
}

/**
 * Tool Registry
 * Manages tool registration, validation, and execution
 */
export class ToolRegistry {
  private tools: Map<string, ADKTool> = new Map();
  private validators: Map<string, (params: any) => ToolValidationResult> = new Map();

  /**
   * Register a tool
   */
  register(tool: ADKTool, validator?: (params: any) => ToolValidationResult): void {
    this.tools.set(tool.name, tool);
    if (validator) {
      this.validators.set(tool.name, validator);
    }
  }

  /**
   * Register multiple tools
   */
  registerMany(tools: ADKTool[]): void {
    tools.forEach((tool) => this.register(tool));
  }

  /**
   * Get a tool by name
   */
  get(name: string): ADKTool | undefined {
    return this.tools.get(name);
  }

  /**
   * Get all tools
   */
  getAll(): ADKTool[] {
    return Array.from(this.tools.values());
  }

  /**
   * Remove a tool
   */
  remove(name: string): boolean {
    this.tools.delete(name);
    this.validators.delete(name);
    return true;
  }

  /**
   * Validate tool parameters
   */
  validate(name: string, params: any): ToolValidationResult {
    const validator = this.validators.get(name);
    if (!validator) {
      return { valid: true }; // No validator means always valid
    }

    try {
      return validator(params);
    } catch (error: any) {
      return {
        valid: false,
        error: error.message || "Validation error",
      };
    }
  }

  /**
   * Execute a tool
   */
  async execute(name: string, params: any): Promise<any> {
    const tool = this.tools.get(name);
    if (!tool) {
      throw new Error(`Tool ${name} not found`);
    }

    // Validate parameters
    const validation = this.validate(name, params);
    if (!validation.valid) {
      throw new Error(`Tool validation failed: ${validation.error}`);
    }

    // Execute tool handler
    try {
      return await tool.handler(params);
    } catch (error: any) {
      throw new Error(`Tool execution failed: ${error.message}`);
    }
  }

  /**
   * Check if tool exists
   */
  has(name: string): boolean {
    return this.tools.has(name);
  }

  /**
   * Get tool count
   */
  size(): number {
    return this.tools.size;
  }
}

/**
 * Default tool validators
 */
export const defaultValidators = {
  /**
   * Validate payment tool parameters
   */
  validatePayment: (params: any): ToolValidationResult => {
    if (!params.amount || typeof params.amount !== "string") {
      return { valid: false, error: "Amount is required and must be a string" };
    }
    if (!params.recipient || typeof params.recipient !== "string") {
      return { valid: false, error: "Recipient is required and must be a string" };
    }
    return { valid: true };
  },

  /**
   * Validate invoice tool parameters
   */
  validateInvoice: (params: any): ToolValidationResult => {
    if (!params.invoiceId || typeof params.invoiceId !== "string") {
      return { valid: false, error: "Invoice ID is required and must be a string" };
    }
    return { valid: true };
  },
};

