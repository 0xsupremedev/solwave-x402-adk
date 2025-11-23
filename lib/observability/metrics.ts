interface PaymentMetrics {
  totalPayments: number;
  successfulPayments: number;
  failedPayments: number;
  averageConfirmationTime: number;
  paymentsPerSecond: number;
}

class MetricsCollector {
  private paymentHistory: Array<{
    timestamp: Date;
    success: boolean;
    confirmationTime?: number;
  }> = [];

  recordPayment(success: boolean, confirmationTime?: number) {
    this.paymentHistory.push({
      timestamp: new Date(),
      success,
      confirmationTime,
    });

    // Keep only last hour of metrics
    const oneHourAgo = new Date(Date.now() - 60 * 60 * 1000);
    this.paymentHistory = this.paymentHistory.filter(
      (entry) => entry.timestamp > oneHourAgo
    );
  }

  getMetrics(): PaymentMetrics {
    const now = new Date();
    const oneMinuteAgo = new Date(now.getTime() - 60 * 1000);

    const recentPayments = this.paymentHistory.filter(
      (entry) => entry.timestamp > oneMinuteAgo
    );

    const successful = this.paymentHistory.filter((entry) => entry.success);
    const failed = this.paymentHistory.filter((entry) => !entry.success);

    const confirmationTimes = this.paymentHistory
      .filter((entry) => entry.confirmationTime !== undefined)
      .map((entry) => entry.confirmationTime!);

    const avgConfirmationTime =
      confirmationTimes.length > 0
        ? confirmationTimes.reduce((a, b) => a + b, 0) / confirmationTimes.length
        : 0;

    return {
      totalPayments: this.paymentHistory.length,
      successfulPayments: successful.length,
      failedPayments: failed.length,
      averageConfirmationTime: avgConfirmationTime,
      paymentsPerSecond: recentPayments.length / 60,
    };
  }
}

export const metrics = new MetricsCollector();

