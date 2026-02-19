"use client";

import { Activity, AlertTriangle, Network, Clock } from "lucide-react";
import type { AnalysisSummary } from "@/lib/graph-engine";

interface SummaryStatsProps {
  summary: AnalysisSummary;
}

export function SummaryStats({ summary }: SummaryStatsProps) {
  const stats = [
    {
      label: "Accounts Analyzed",
      value: summary.total_accounts_analyzed.toLocaleString(),
      icon: Activity,
      color: "text-primary",
      bgColor: "bg-primary/10",
    },
    {
      label: "Suspicious Accounts",
      value: summary.suspicious_accounts_flagged.toLocaleString(),
      icon: AlertTriangle,
      color: "text-destructive",
      bgColor: "bg-destructive/10",
    },
    {
      label: "Fraud Rings Detected",
      value: summary.fraud_rings_detected.toLocaleString(),
      icon: Network,
      color: "text-warning",
      bgColor: "bg-warning/10",
    },
    {
      label: "Processing Time",
      value: `${summary.processing_time_seconds}s`,
      icon: Clock,
      color: "text-success",
      bgColor: "bg-success/10",
    },
  ];

  return (
    <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
      {stats.map((stat) => (
        <div
          key={stat.label}
          className="flex items-center gap-4 rounded-lg border border-border bg-card p-4"
        >
          <div className={`flex h-10 w-10 shrink-0 items-center justify-center rounded-lg ${stat.bgColor}`}>
            <stat.icon className={`h-5 w-5 ${stat.color}`} />
          </div>
          <div>
            <p className="text-2xl font-bold font-mono text-foreground">{stat.value}</p>
            <p className="text-xs text-muted-foreground">{stat.label}</p>
          </div>
        </div>
      ))}
    </div>
  );
}
