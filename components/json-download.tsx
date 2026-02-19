"use client";

import { Download } from "lucide-react";
import { Button } from "@/components/ui/button";
import type { AnalysisResult } from "@/lib/graph-engine";

interface JSONDownloadProps {
  data: AnalysisResult;
}

export function JSONDownload({ data }: JSONDownloadProps) {
  const handleDownload = () => {
    const output = {
      suspicious_accounts: data.suspicious_accounts,
      fraud_rings: data.fraud_rings,
      summary: data.summary,
    };

    const blob = new Blob([JSON.stringify(output, null, 2)], {
      type: "application/json",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "forensic_analysis_results.json";
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  return (
    <Button onClick={handleDownload} className="gap-2 bg-primary text-primary-foreground hover:bg-primary/90">
      <Download className="h-4 w-4" />
      Download JSON Report
    </Button>
  );
}
