import { NextRequest, NextResponse } from "next/server";
import { analyzeTransactions, type Transaction } from "@/lib/graph-engine";

function parseCSV(csvText: string): Transaction[] {
  const lines = csvText.trim().split("\n");
  if (lines.length < 2) throw new Error("CSV must have a header and at least one data row");

  const header = lines[0].split(",").map(h => h.trim().toLowerCase());
  const requiredColumns = ["transaction_id", "sender_id", "receiver_id", "amount", "timestamp"];

  for (const col of requiredColumns) {
    if (!header.includes(col)) {
      throw new Error(`Missing required column: ${col}`);
    }
  }

  const colIdx = {
    transaction_id: header.indexOf("transaction_id"),
    sender_id: header.indexOf("sender_id"),
    receiver_id: header.indexOf("receiver_id"),
    amount: header.indexOf("amount"),
    timestamp: header.indexOf("timestamp"),
  };

  const transactions: Transaction[] = [];

  for (let i = 1; i < lines.length; i++) {
    const line = lines[i].trim();
    if (!line) continue;

    const values = line.split(",").map(v => v.trim());

    const amount = parseFloat(values[colIdx.amount]);
    if (isNaN(amount)) continue;

    transactions.push({
      transaction_id: values[colIdx.transaction_id],
      sender_id: values[colIdx.sender_id],
      receiver_id: values[colIdx.receiver_id],
      amount,
      timestamp: values[colIdx.timestamp],
    });
  }

  return transactions;
}

export async function POST(request: NextRequest) {
  try {
    const formData = await request.formData();
    const file = formData.get("file") as File | null;

    if (!file) {
      return NextResponse.json({ error: "No file provided" }, { status: 400 });
    }

    const csvText = await file.text();
    const transactions = parseCSV(csvText);

    if (transactions.length === 0) {
      return NextResponse.json({ error: "No valid transactions found in CSV" }, { status: 400 });
    }

    const result = analyzeTransactions(transactions);

    return NextResponse.json(result);
  } catch (error) {
    const message = error instanceof Error ? error.message : "Unknown error";
    return NextResponse.json({ error: message }, { status: 500 });
  }
}
