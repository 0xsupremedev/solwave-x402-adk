export interface RetryOptions {
  maxAttempts: number;
  delayMs: number;
  backoffFactor: number;
}

export const DEFAULT_RETRY_OPTIONS: RetryOptions = {
  maxAttempts: 3,
  delayMs: 500,
  backoffFactor: 2,
};

export async function withRetry<T>(
  operation: (attempt: number) => Promise<T>,
  options: RetryOptions = DEFAULT_RETRY_OPTIONS,
  onRetry?: (error: unknown, attempt: number) => void
): Promise<T> {
  let attempt = 0;
  let delay = options.delayMs;
  // eslint-disable-next-line no-constant-condition
  while (true) {
    attempt += 1;
    try {
      return await operation(attempt);
    } catch (error) {
      if (attempt >= options.maxAttempts) {
        throw error;
      }
      if (onRetry) {
        onRetry(error, attempt);
      }
      await new Promise((resolve) => setTimeout(resolve, delay));
      delay *= options.backoffFactor;
    }
  }
}


