"use client";

import { useState } from "react";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { FileCode, Activity, Database, Package } from "lucide-react";

interface SessionInspectorProps {
  sessionId?: string;
  traceEvents?: any[];
  state?: any;
  artifacts?: any[];
}

export function SessionInspector({
  sessionId,
  traceEvents = [],
  state = null,
  artifacts = [],
}: SessionInspectorProps) {
  return (
    <Card className="border-border bg-background/50 backdrop-blur-sm">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <FileCode className="w-5 h-5" />
          Session Inspector
        </CardTitle>
        <CardDescription className="font-mono">
          Debug and inspect agent sessions
        </CardDescription>
      </CardHeader>
      <CardContent>
        <Tabs defaultValue="trace" className="w-full">
          <TabsList className="grid w-full grid-cols-4">
            <TabsTrigger value="trace" className="flex items-center gap-2">
              <Activity className="w-4 h-4" />
              Trace
            </TabsTrigger>
            <TabsTrigger value="events" className="flex items-center gap-2">
              <Activity className="w-4 h-4" />
              Events
            </TabsTrigger>
            <TabsTrigger value="state" className="flex items-center gap-2">
              <Database className="w-4 h-4" />
              State
            </TabsTrigger>
            <TabsTrigger value="artifacts" className="flex items-center gap-2">
              <Package className="w-4 h-4" />
              Artifacts
            </TabsTrigger>
          </TabsList>

          <TabsContent value="trace" className="mt-4">
            <div className="border border-border rounded-lg p-4 bg-background/30 max-h-96 overflow-y-auto">
              {traceEvents.length > 0 ? (
                <div className="space-y-2 font-mono text-xs">
                  {traceEvents.map((event, idx) => (
                    <div key={idx} className="border-l-2 border-primary pl-3 py-2">
                      <div className="text-primary font-semibold">{event.type || "Event"}</div>
                      <pre className="text-foreground/60 mt-1 whitespace-pre-wrap">
                        {JSON.stringify(event, null, 2)}
                      </pre>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="text-center text-foreground/40 font-mono text-sm py-8">
                  No trace events available
                </div>
              )}
            </div>
          </TabsContent>

          <TabsContent value="events" className="mt-4">
            <div className="border border-border rounded-lg p-4 bg-background/30 max-h-96 overflow-y-auto">
              {traceEvents.length > 0 ? (
                <div className="space-y-2 font-mono text-xs">
                  {traceEvents.map((event, idx) => (
                    <div key={idx} className="border border-border rounded p-2">
                      <div className="text-foreground/80">{event.type || "Event"}</div>
                      <div className="text-foreground/60 text-xs mt-1">
                        {new Date(event.timestamp || Date.now()).toLocaleString()}
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="text-center text-foreground/40 font-mono text-sm py-8">
                  No events available
                </div>
              )}
            </div>
          </TabsContent>

          <TabsContent value="state" className="mt-4">
            <div className="border border-border rounded-lg p-4 bg-background/30 max-h-96 overflow-y-auto">
              {state ? (
                <pre className="font-mono text-xs text-foreground/80 whitespace-pre-wrap">
                  {JSON.stringify(state, null, 2)}
                </pre>
              ) : (
                <div className="text-center text-foreground/40 font-mono text-sm py-8">
                  No state available
                </div>
              )}
            </div>
          </TabsContent>

          <TabsContent value="artifacts" className="mt-4">
            <div className="border border-border rounded-lg p-4 bg-background/30 max-h-96 overflow-y-auto">
              {artifacts.length > 0 ? (
                <div className="space-y-2">
                  {artifacts.map((artifact, idx) => (
                    <div key={idx} className="border border-border rounded p-3">
                      <div className="font-mono text-sm text-foreground/80">{artifact.name || `Artifact ${idx + 1}`}</div>
                      <div className="font-mono text-xs text-foreground/60 mt-1">
                        {artifact.type || "Unknown type"}
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="text-center text-foreground/40 font-mono text-sm py-8">
                  No artifacts available
                </div>
              )}
            </div>
          </TabsContent>
        </Tabs>
      </CardContent>
    </Card>
  );
}

