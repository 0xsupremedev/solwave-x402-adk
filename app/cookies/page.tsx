export default function CookiesPage() {
  return (
    <div className="container py-24 max-w-4xl">
      <h1 className="text-4xl font-sentient mb-8">Cookie Policy</h1>
      <div className="space-y-6 font-mono text-foreground/80">
        <section>
          <h2 className="text-2xl font-sentient mb-4">What Are Cookies</h2>
          <p className="mb-4">
            Cookies are small text files that are placed on your computer or mobile device when you visit a website.
          </p>
        </section>
        <section>
          <h2 className="text-2xl font-sentient mb-4">How We Use Cookies</h2>
          <p className="mb-4">
            We use cookies to authenticate users, remember your preferences, and analyze how you use our platform.
          </p>
        </section>
        <section>
          <h2 className="text-2xl font-sentient mb-4">Managing Cookies</h2>
          <p>
            You can control and manage cookies through your browser settings. However, disabling cookies may affect the functionality of our platform.
          </p>
        </section>
      </div>
    </div>
  );
}

