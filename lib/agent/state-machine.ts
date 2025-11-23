/**
 * Payment State Machine
 * Manages payment workflow states and transitions
 */

export enum PaymentState {
  INIT = "INIT",
  INVOICE_REQUESTED = "INVOICE_REQUESTED",
  WAITING_PAYMENT = "WAITING_PAYMENT",
  PAYMENT_CONFIRMED = "PAYMENT_CONFIRMED",
  COMPLETED = "COMPLETED",
  FAILED = "FAILED",
  EXPIRED = "EXPIRED",
  CANCELLED = "CANCELLED",
}

export interface PaymentStateData {
  state: PaymentState;
  invoiceId?: string;
  txSignature?: string;
  error?: string;
  timestamp: number;
  metadata?: Record<string, any>;
}

export type StateTransition = {
  from: PaymentState;
  to: PaymentState;
  condition?: (data: PaymentStateData) => boolean;
};

/**
 * Payment State Machine
 */
export class PaymentStateMachine {
  private currentState: PaymentState;
  private stateData: PaymentStateData;
  private transitions: Map<PaymentState, PaymentState[]> = new Map();

  constructor(initialState: PaymentState = PaymentState.INIT) {
    this.currentState = initialState;
    this.stateData = {
      state: initialState,
      timestamp: Date.now(),
    };

    // Define valid state transitions
    this.transitions.set(PaymentState.INIT, [
      PaymentState.INVOICE_REQUESTED,
      PaymentState.FAILED,
      PaymentState.CANCELLED,
    ]);

    this.transitions.set(PaymentState.INVOICE_REQUESTED, [
      PaymentState.WAITING_PAYMENT,
      PaymentState.EXPIRED,
      PaymentState.CANCELLED,
      PaymentState.FAILED,
    ]);

    this.transitions.set(PaymentState.WAITING_PAYMENT, [
      PaymentState.PAYMENT_CONFIRMED,
      PaymentState.EXPIRED,
      PaymentState.FAILED,
      PaymentState.CANCELLED,
    ]);

    this.transitions.set(PaymentState.PAYMENT_CONFIRMED, [
      PaymentState.COMPLETED,
      PaymentState.FAILED,
    ]);

    this.transitions.set(PaymentState.COMPLETED, []); // Terminal state
    this.transitions.set(PaymentState.FAILED, []); // Terminal state
    this.transitions.set(PaymentState.EXPIRED, []); // Terminal state
    this.transitions.set(PaymentState.CANCELLED, []); // Terminal state
  }

  /**
   * Get current state
   */
  getState(): PaymentState {
    return this.currentState;
  }

  /**
   * Get state data
   */
  getStateData(): PaymentStateData {
    return { ...this.stateData };
  }

  /**
   * Check if transition is valid
   */
  canTransition(to: PaymentState): boolean {
    const validTransitions = this.transitions.get(this.currentState);
    return validTransitions?.includes(to) ?? false;
  }

  /**
   * Transition to new state
   */
  transition(to: PaymentState, data?: Partial<PaymentStateData>): boolean {
    if (!this.canTransition(to)) {
      console.error(
        `Invalid transition from ${this.currentState} to ${to}`
      );
      return false;
    }

    this.currentState = to;
    this.stateData = {
      ...this.stateData,
      ...data,
      state: to,
      timestamp: Date.now(),
    };

    return true;
  }

  /**
   * Request invoice
   */
  requestInvoice(invoiceId: string): boolean {
    return this.transition(PaymentState.INVOICE_REQUESTED, { invoiceId });
  }

  /**
   * Start waiting for payment
   */
  waitForPayment(): boolean {
    return this.transition(PaymentState.WAITING_PAYMENT);
  }

  /**
   * Confirm payment
   */
  confirmPayment(txSignature: string): boolean {
    return this.transition(PaymentState.PAYMENT_CONFIRMED, { txSignature });
  }

  /**
   * Complete payment
   */
  complete(): boolean {
    return this.transition(PaymentState.COMPLETED);
  }

  /**
   * Fail payment
   */
  fail(error: string): boolean {
    return this.transition(PaymentState.FAILED, { error });
  }

  /**
   * Expire payment
   */
  expire(): boolean {
    return this.transition(PaymentState.EXPIRED);
  }

  /**
   * Cancel payment
   */
  cancel(): boolean {
    return this.transition(PaymentState.CANCELLED);
  }

  /**
   * Check if state is terminal
   */
  isTerminal(): boolean {
    return [
      PaymentState.COMPLETED,
      PaymentState.FAILED,
      PaymentState.EXPIRED,
      PaymentState.CANCELLED,
    ].includes(this.currentState);
  }

  /**
   * Reset state machine
   */
  reset(): void {
    this.currentState = PaymentState.INIT;
    this.stateData = {
      state: PaymentState.INIT,
      timestamp: Date.now(),
    };
  }

  /**
   * Validate state data
   */
  validateStateData(): { valid: boolean; error?: string } {
    if (this.currentState === PaymentState.INVOICE_REQUESTED && !this.stateData.invoiceId) {
      return { valid: false, error: "Invoice ID required for INVOICE_REQUESTED state" };
    }

    if (this.currentState === PaymentState.PAYMENT_CONFIRMED && !this.stateData.txSignature) {
      return { valid: false, error: "Transaction signature required for PAYMENT_CONFIRMED state" };
    }

    return { valid: true };
  }
}

/**
 * State persistence interface
 */
export interface StatePersistence {
  save(state: PaymentStateData): Promise<void>;
  load(id: string): Promise<PaymentStateData | null>;
  delete(id: string): Promise<void>;
}

/**
 * In-memory state persistence (for development)
 */
export class InMemoryStatePersistence implements StatePersistence {
  private storage: Map<string, PaymentStateData> = new Map();

  async save(state: PaymentStateData): Promise<void> {
    const id = state.invoiceId || `state-${Date.now()}`;
    this.storage.set(id, state);
  }

  async load(id: string): Promise<PaymentStateData | null> {
    return this.storage.get(id) || null;
  }

  async delete(id: string): Promise<void> {
    this.storage.delete(id);
  }
}

