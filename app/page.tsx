'use client'

import { Hero } from "@/components/hero";
import { FeaturePanels } from "@/components/feature-panels";
import { LiveDemo } from "@/components/live-demo";
import { HowItWorks } from "@/components/how-it-works";
import { DeveloperSection } from "@/components/developer-section";
import { TelegramSection } from "@/components/telegram-section";
import { Footer } from "@/components/footer";
import { Leva } from "leva";

export default function Home() {
  return (
    <>
      <Hero />
      <FeaturePanels />
      <LiveDemo />
      <HowItWorks />
      <DeveloperSection />
      <TelegramSection />
      <Footer />
      <Leva hidden />
    </>
  );
}
