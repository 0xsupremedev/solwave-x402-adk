export default function PrivacyPage() {
  return (
    <div className="container py-24 max-w-4xl">
      <h1 className="text-4xl font-sentient mb-8">Privacy Policy</h1>
      <div className="space-y-6 font-mono text-foreground/80">
        <section>
          <h2 className="text-2xl font-sentient mb-4">Information We Collect</h2>
          <p className="mb-4">
            We collect information that you provide directly to us, including email addresses, wallet addresses, and transaction data when using our services.
          </p>
        </section>
        <section>
          <h2 className="text-2xl font-sentient mb-4">How We Use Your Information</h2>
          <p className="mb-4">
            We use the information we collect to provide, maintain, and improve our services, process transactions, and communicate with you.
          </p>
        </section>
        <section>
          <h2 className="text-2xl font-sentient mb-4">Data Security</h2>
          <p className="mb-4">
            We implement appropriate security measures to protect your personal information. We never store your private keys server-side.
          </p>
        </section>
        <section>
          <h2 className="text-2xl font-sentient mb-4">Contact Us</h2>
          <p>
            If you have questions about this Privacy Policy, please contact us at privacy@x402platform.com
          </p>
        </section>
      </div>
    </div>
  );
}

