export default function TermsPage() {
  return (
    <div className="container py-24 max-w-4xl">
      <h1 className="text-4xl font-sentient mb-8">Terms of Service</h1>
      <div className="space-y-6 font-mono text-foreground/80">
        <section>
          <h2 className="text-2xl font-sentient mb-4">Acceptance of Terms</h2>
          <p className="mb-4">
            By accessing and using this platform, you accept and agree to be bound by the terms and provision of this agreement.
          </p>
        </section>
        <section>
          <h2 className="text-2xl font-sentient mb-4">Use License</h2>
          <p className="mb-4">
            Permission is granted to temporarily use the platform for personal, non-commercial transitory viewing only.
          </p>
        </section>
        <section>
          <h2 className="text-2xl font-sentient mb-4">Disclaimer</h2>
          <p className="mb-4">
            The materials on this platform are provided on an 'as is' basis. We make no warranties, expressed or implied.
          </p>
        </section>
        <section>
          <h2 className="text-2xl font-sentient mb-4">Limitations</h2>
          <p>
            In no event shall we be liable for any damages arising out of the use or inability to use the materials on this platform.
          </p>
        </section>
      </div>
    </div>
  );
}

