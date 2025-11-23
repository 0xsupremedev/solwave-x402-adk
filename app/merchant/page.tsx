"use client";

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Settings, FileText, Activity } from "lucide-react";
import Link from "next/link";

export default function MerchantPage() {
  return (
    <div className="container py-24">
      <h1 className="text-4xl font-sentient mb-8">Merchant Dashboard</h1>
      
      <div className="grid md:grid-cols-3 gap-6">
        <Link href="/merchant/settings">
          <Card className="border-border bg-background/50 backdrop-blur-sm hover:border-primary transition-colors">
            <CardHeader>
              <div className="flex items-center gap-3">
                <div className="w-12 h-12 rounded-lg bg-primary/10 flex items-center justify-center">
                  <Settings className="w-6 h-6 text-primary" />
                </div>
                <div>
                  <CardTitle className="font-sentient">Settings</CardTitle>
                  <CardDescription className="font-mono">Configure merchant settings</CardDescription>
                </div>
              </div>
            </CardHeader>
          </Card>
        </Link>

        <Link href="/merchant/invoices">
          <Card className="border-border bg-background/50 backdrop-blur-sm hover:border-primary transition-colors">
            <CardHeader>
              <div className="flex items-center gap-3">
                <div className="w-12 h-12 rounded-lg bg-primary/10 flex items-center justify-center">
                  <FileText className="w-6 h-6 text-primary" />
                </div>
                <div>
                  <CardTitle className="font-sentient">Invoices</CardTitle>
                  <CardDescription className="font-mono">View invoice history</CardDescription>
                </div>
              </div>
            </CardHeader>
          </Card>
        </Link>

        <Link href="/merchant/transactions">
          <Card className="border-border bg-background/50 backdrop-blur-sm hover:border-primary transition-colors">
            <CardHeader>
              <div className="flex items-center gap-3">
                <div className="w-12 h-12 rounded-lg bg-primary/10 flex items-center justify-center">
                  <Activity className="w-6 h-6 text-primary" />
                </div>
                <div>
                  <CardTitle className="font-sentient">Transactions</CardTitle>
                  <CardDescription className="font-mono">Transaction logs</CardDescription>
                </div>
              </div>
            </CardHeader>
          </Card>
        </Link>
      </div>
    </div>
  );
}

