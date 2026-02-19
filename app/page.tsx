"use client";

import { useState } from "react";
import { CSVUpload } from "@/components/csv-upload";
import { GraphVisualization } from "@/components/graph-visualization";
import { SummaryStats } from "@/components/summary-stats";
import { FraudRingTable } from "@/components/fraud-ring-table";
import { SuspiciousAccountsTable } from "@/components/suspicious-accounts-table";
import { JSONDownload } from "@/components/json-download";
import type { AnalysisResult } from "@/lib/graph-engine";
import { Shield, RotateCcw } from "lucide-react";
import { Button } from "@/components/ui/button";

export default function Home() {
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [isLoading, setIsLoading] = useState(false);

  const handleReset = () => {
    setResult(null);
  };

  return (
    <main className="min-h-screen bg-background">
      {/* Header */}
      <header className="border-b border-border bg-card">
        <div className="mx-auto flex max-w-7xl items-center justify-between px-4 py-4 lg:px-8">
          <div className="flex items-center gap-3">
            <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-primary/10">
              <Shield className="h-5 w-5 text-primary" />
            </div>
            <div>
              <h1 className="text-lg font-bold text-foreground tracking-tight">ForensicGraph</h1>
              <p className="text-xs text-muted-foreground">Financial Crime Detection Engine</p>
            </div>
          </div>
          <div className="flex items-center gap-3">
            {result && (
              <>
                <JSONDownload data={result} />
                <Button
                  variant="outline"
                  size="sm"
                  onClick={handleReset}
                  className="gap-2 border-border text-muted-foreground hover:text-foreground"
                >
                  <RotateCcw className="h-4 w-4" />
                  New Analysis
                </Button>
              </>
            )}
          </div>
        </div>
      </header>

      <div className="mx-auto max-w-7xl px-4 py-8 lg:px-8">
        {!result ? (
          /* Upload State */
          <div className="flex flex-col items-center justify-center py-24">
            <div className="mb-8 text-center">
              <h2 className="text-3xl font-bold tracking-tight text-foreground text-balance">
                Detect Money Muling Networks
              </h2>
              <p className="mt-3 max-w-lg text-muted-foreground text-pretty leading-relaxed">
                Upload transaction data to identify circular fund routing, smurfing patterns,
                and layered shell networks using graph-based analysis.
              </p>
            </div>
            <CSVUpload
              onAnalysisComplete={(data) => setResult(data as AnalysisResult)}
              isLoading={isLoading}
              setIsLoading={setIsLoading}
            />

            {/* Algorithm Info */}
            <div className="mt-16 grid max-w-3xl grid-cols-1 gap-6 md:grid-cols-3">
              <div className="rounded-lg border border-border bg-card p-5">
                <h3 className="text-sm font-semibold text-foreground">Cycle Detection</h3>
                <p className="mt-2 text-xs text-muted-foreground leading-relaxed">
                  Identifies circular fund routing where money flows in loops
                  (A to B to C to A) across 3-5 account hops.
                </p>
              </div>
              <div className="rounded-lg border border-border bg-card p-5">
                <h3 className="text-sm font-semibold text-foreground">Smurfing Analysis</h3>
                <p className="mt-2 text-xs text-muted-foreground leading-relaxed">
                  Detects fan-in/fan-out patterns where many small deposits aggregate into one
                  account, then disperse rapidly.
                </p>
              </div>
              <div className="rounded-lg border border-border bg-card p-5">
                <h3 className="text-sm font-semibold text-foreground">Shell Networks</h3>
                <p className="mt-2 text-xs text-muted-foreground leading-relaxed">
                  Finds layered chains of 3+ intermediate accounts with minimal transaction
                  history, typical of shell entities.
                </p>
              </div>
            </div>
          </div>
        ) : (
          /* Results State */
          <div className="flex flex-col gap-8">
            {/* Summary Statistics */}
            <SummaryStats summary={result.summary} />

            {/* Graph Visualization */}
            <section>
              <div className="mb-4 flex items-center justify-between">
                <div>
                  <h2 className="text-lg font-semibold text-foreground">Transaction Network Graph</h2>
                  <p className="text-sm text-muted-foreground">
                    {result.nodes.length} accounts, {result.edges.length} transactions.
                    Suspicious nodes are highlighted by ring color.
                  </p>
                </div>
              </div>
              <GraphVisualization nodes={result.nodes} edges={result.edges} />
            </section>

            {/* Fraud Ring Summary Table */}
            <section>
              <div className="mb-4">
                <h2 className="text-lg font-semibold text-foreground">Fraud Ring Summary</h2>
                <p className="text-sm text-muted-foreground">
                  {result.fraud_rings.length} rings detected across cycle, smurfing, and shell network patterns.
                </p>
              </div>
              <FraudRingTable rings={result.fraud_rings} />
            </section>

            {/* Suspicious Accounts Table */}
            <section>
              <div className="mb-4">
                <h2 className="text-lg font-semibold text-foreground">Suspicious Accounts</h2>
                <p className="text-sm text-muted-foreground">
                  {result.suspicious_accounts.length} accounts flagged, sorted by suspicion score (descending).
                </p>
              </div>
              <SuspiciousAccountsTable accounts={result.suspicious_accounts} />
            </section>
          </div>
        )}
      </div>
    </main>
  );
}
