"use client";

import { useCallback, useState } from "react";
import { Upload, FileText, Loader2, AlertCircle } from "lucide-react";
import { Button } from "@/components/ui/button";

interface CSVUploadProps {
  onAnalysisComplete: (data: unknown) => void;
  isLoading: boolean;
  setIsLoading: (loading: boolean) => void;
}

export function CSVUpload({ onAnalysisComplete, isLoading, setIsLoading }: CSVUploadProps) {
  const [dragOver, setDragOver] = useState(false);
  const [fileName, setFileName] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const handleFile = useCallback(
    async (file: File) => {
      if (!file.name.endsWith(".csv")) {
        setError("Please upload a CSV file");
        return;
      }

      setFileName(file.name);
      setError(null);
      setIsLoading(true);

      try {
        const formData = new FormData();
        formData.append("file", file);

        const response = await fetch("/api/analyze", {
          method: "POST",
          body: formData,
        });

        if (!response.ok) {
          const errData = await response.json();
          throw new Error(errData.error || "Analysis failed");
        }

        const result = await response.json();
        onAnalysisComplete(result);
      } catch (err) {
        setError(err instanceof Error ? err.message : "Failed to analyze file");
      } finally {
        setIsLoading(false);
      }
    },
    [onAnalysisComplete, setIsLoading]
  );

  const handleDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault();
      setDragOver(false);
      const file = e.dataTransfer.files[0];
      if (file) handleFile(file);
    },
    [handleFile]
  );

  const handleDragOver = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setDragOver(true);
  }, []);

  const handleDragLeave = useCallback(() => {
    setDragOver(false);
  }, []);

  return (
    <div className="flex flex-col items-center gap-6">
      <div
        onDrop={handleDrop}
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        className={`relative w-full max-w-xl rounded-lg border-2 border-dashed p-12 text-center transition-all ${
          dragOver
            ? "border-primary bg-primary/5"
            : "border-border hover:border-muted-foreground/50"
        } ${isLoading ? "pointer-events-none opacity-60" : "cursor-pointer"}`}
        onClick={() => {
          if (!isLoading) {
            const input = document.createElement("input");
            input.type = "file";
            input.accept = ".csv";
            input.onchange = (e) => {
              const file = (e.target as HTMLInputElement).files?.[0];
              if (file) handleFile(file);
            };
            input.click();
          }
        }}
        role="button"
        tabIndex={0}
        aria-label="Upload CSV file"
      >
        {isLoading ? (
          <div className="flex flex-col items-center gap-4">
            <div className="flex h-16 w-16 items-center justify-center rounded-full bg-primary/10">
              <Loader2 className="h-8 w-8 animate-spin text-primary" />
            </div>
            <div>
              <p className="text-lg font-medium text-foreground">Analyzing transactions...</p>
              <p className="mt-1 text-sm text-muted-foreground">
                Running graph algorithms on {fileName}
              </p>
            </div>
          </div>
        ) : (
          <div className="flex flex-col items-center gap-4">
            <div className="flex h-16 w-16 items-center justify-center rounded-full bg-secondary">
              {fileName ? (
                <FileText className="h-8 w-8 text-primary" />
              ) : (
                <Upload className="h-8 w-8 text-muted-foreground" />
              )}
            </div>
            <div>
              <p className="text-lg font-medium text-foreground">
                {fileName ? fileName : "Drop your CSV file here"}
              </p>
              <p className="mt-1 text-sm text-muted-foreground">
                or click to browse. Accepts transaction CSV files.
              </p>
            </div>
            <div className="flex flex-wrap items-center justify-center gap-2 text-xs text-muted-foreground font-mono">
              <span className="rounded bg-secondary px-2 py-1">transaction_id</span>
              <span className="rounded bg-secondary px-2 py-1">sender_id</span>
              <span className="rounded bg-secondary px-2 py-1">receiver_id</span>
              <span className="rounded bg-secondary px-2 py-1">amount</span>
              <span className="rounded bg-secondary px-2 py-1">timestamp</span>
            </div>
          </div>
        )}
      </div>

      {error && (
        <div className="flex items-center gap-2 rounded-md bg-destructive/10 px-4 py-3 text-sm text-destructive">
          <AlertCircle className="h-4 w-4 shrink-0" />
          {error}
        </div>
      )}
    </div>
  );
}
