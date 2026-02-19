"use client";

import type { FraudRing } from "@/lib/graph-engine";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";

interface FraudRingTableProps {
  rings: FraudRing[];
}

function getPatternLabel(type: string): string {
  switch (type) {
    case "cycle":
      return "Circular Routing";
    case "fan_in":
      return "Fan-In (Smurfing)";
    case "fan_out":
      return "Fan-Out (Smurfing)";
    case "shell_network":
      return "Shell Network";
    default:
      return type;
  }
}

function getRiskColor(score: number): string {
  if (score >= 80) return "text-destructive";
  if (score >= 60) return "text-warning";
  return "text-foreground";
}

function getRiskBadge(score: number): string {
  if (score >= 80) return "bg-destructive/15 text-destructive";
  if (score >= 60) return "bg-warning/15 text-warning";
  return "bg-muted text-muted-foreground";
}

export function FraudRingTable({ rings }: FraudRingTableProps) {
  if (rings.length === 0) {
    return (
      <div className="rounded-lg border border-border bg-card p-8 text-center">
        <p className="text-muted-foreground">No fraud rings detected</p>
      </div>
    );
  }

  return (
    <div className="rounded-lg border border-border bg-card overflow-hidden">
      <div className="overflow-x-auto">
        <Table>
          <TableHeader>
            <TableRow className="border-border hover:bg-transparent">
              <TableHead className="text-muted-foreground font-medium">Ring ID</TableHead>
              <TableHead className="text-muted-foreground font-medium">Pattern Type</TableHead>
              <TableHead className="text-muted-foreground font-medium text-center">Members</TableHead>
              <TableHead className="text-muted-foreground font-medium text-right">Risk Score</TableHead>
              <TableHead className="text-muted-foreground font-medium">Member Account IDs</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {rings.map((ring) => (
              <TableRow key={ring.ring_id} className="border-border hover:bg-secondary/50">
                <TableCell className="font-mono text-sm text-foreground">{ring.ring_id}</TableCell>
                <TableCell>
                  <span className="inline-flex items-center rounded-md bg-secondary px-2 py-0.5 text-xs font-medium text-foreground">
                    {getPatternLabel(ring.pattern_type)}
                  </span>
                </TableCell>
                <TableCell className="text-center font-mono text-sm text-foreground">
                  {ring.member_accounts.length}
                </TableCell>
                <TableCell className="text-right">
                  <span
                    className={`inline-flex items-center rounded-md px-2 py-0.5 text-xs font-bold font-mono ${getRiskBadge(
                      ring.risk_score
                    )}`}
                  >
                    {ring.risk_score}
                  </span>
                </TableCell>
                <TableCell className="max-w-[400px]">
                  <div className="flex flex-wrap gap-1">
                    {ring.member_accounts.slice(0, 8).map((id) => (
                      <span
                        key={id}
                        className="inline-block rounded bg-secondary px-1.5 py-0.5 text-[10px] font-mono text-muted-foreground"
                      >
                        {id}
                      </span>
                    ))}
                    {ring.member_accounts.length > 8 && (
                      <span className="inline-block rounded bg-secondary px-1.5 py-0.5 text-[10px] font-mono text-muted-foreground">
                        +{ring.member_accounts.length - 8} more
                      </span>
                    )}
                  </div>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </div>
    </div>
  );
}
