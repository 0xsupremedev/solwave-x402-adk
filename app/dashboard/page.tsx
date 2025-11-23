"use client";

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Wallet, Key, Settings } from "lucide-react";
import Link from "next/link";

export default function DashboardPage() {
  return (
    <div className="container py-24">
      <h1 className="text-4xl font-sentient mb-8">Dashboard</h1>
      
      <div className="grid md:grid-cols-3 gap-6">
        <Link href="/dashboard/profile">
          <Card className="border-border bg-background/50 backdrop-blur-sm hover:border-primary transition-colors">
            <CardHeader>
              <div className="flex items-center gap-3">
                <div className="w-12 h-12 rounded-lg bg-primary/10 flex items-center justify-center">
                  <Settings className="w-6 h-6 text-primary" />
                </div>
                <div>
                  <CardTitle className="font-sentient">Profile</CardTitle>
                  <CardDescription className="font-mono">Manage your profile</CardDescription>
                </div>
              </div>
            </CardHeader>
          </Card>
        </Link>

        <Link href="/dashboard/api-keys">
          <Card className="border-border bg-background/50 backdrop-blur-sm hover:border-primary transition-colors">
            <CardHeader>
              <div className="flex items-center gap-3">
                <div className="w-12 h-12 rounded-lg bg-primary/10 flex items-center justify-center">
                  <Key className="w-6 h-6 text-primary" />
                </div>
                <div>
                  <CardTitle className="font-sentient">API Keys</CardTitle>
                  <CardDescription className="font-mono">Manage API keys</CardDescription>
                </div>
              </div>
            </CardHeader>
          </Card>
        </Link>

        <Link href="/dashboard/wallets">
          <Card className="border-border bg-background/50 backdrop-blur-sm hover:border-primary transition-colors">
            <CardHeader>
              <div className="flex items-center gap-3">
                <div className="w-12 h-12 rounded-lg bg-primary/10 flex items-center justify-center">
                  <Wallet className="w-6 h-6 text-primary" />
                </div>
                <div>
                  <CardTitle className="font-sentient">Wallets</CardTitle>
                  <CardDescription className="font-mono">Manage wallets</CardDescription>
                </div>
              </div>
            </CardHeader>
          </Card>
        </Link>
      </div>
    </div>
  );
}

