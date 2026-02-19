"use client";

import type { SuspiciousAccount } from "@/lib/graph-engine";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";

interface SuspiciousAccountsTableProps {
  accounts: SuspiciousAccount[];
}

function getScoreColor(score: number): string {
  if (score >= 70) return "bg-destructive/15 text-destructive";
  if (score >= 40) return "bg-warning/15 text-warning";
  return "bg-muted text-muted-foreground";
}

export function SuspiciousAccountsTable({ accounts }: SuspiciousAccountsTableProps) {
  if (accounts.length === 0) {
    return (
      <div className="rounded-lg border border-border bg-card p-8 text-center">
        <p className="text-muted-foreground">No suspicious accounts detected</p>
      </div>
    );
  }

  return (
    <div className="rounded-lg border border-border bg-card overflow-hidden">
      <div className="overflow-x-auto">
        <Table>
          <TableHeader>
            <TableRow className="border-border hover:bg-transparent">
              <TableHead className="text-muted-foreground font-medium">Account ID</TableHead>
              <TableHead className="text-muted-foreground font-medium text-right">Suspicion Score</TableHead>
              <TableHead className="text-muted-foreground font-medium">Detected Patterns</TableHead>
              <TableHead className="text-muted-foreground font-medium">Ring ID</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {accounts.slice(0, 50).map((account) => (
              <TableRow key={account.account_id} className="border-border hover:bg-secondary/50">
                <TableCell className="font-mono text-sm text-foreground">{account.account_id}</TableCell>
                <TableCell className="text-right">
                  <span
                    className={`inline-flex items-center rounded-md px-2 py-0.5 text-xs font-bold font-mono ${getScoreColor(
                      account.suspicion_score
                    )}`}
                  >
                    {account.suspicion_score}
                  </span>
                </TableCell>
                <TableCell>
                  <div className="flex flex-wrap gap-1">
                    {account.detected_patterns.map((p) => (
                      <span
                        key={p}
                        className="inline-block rounded bg-secondary px-1.5 py-0.5 text-[10px] font-mono text-muted-foreground"
                      >
                        {p}
                      </span>
                    ))}
                  </div>
                </TableCell>
                <TableCell className="font-mono text-xs text-muted-foreground">{account.ring_id}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </div>
      {accounts.length > 50 && (
        <div className="border-t border-border px-4 py-2 text-xs text-muted-foreground">
          Showing 50 of {accounts.length} suspicious accounts
        </div>
      )}
    </div>
  );
}
