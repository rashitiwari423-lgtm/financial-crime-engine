// =====================================================
// Financial Crime Graph Analysis Engine
// Detects money muling patterns: cycles, smurfing, shell networks
// =====================================================

export interface Transaction {
  transaction_id: string;
  sender_id: string;
  receiver_id: string;
  amount: number;
  timestamp: string;
}

export interface SuspiciousAccount {
  account_id: string;
  suspicion_score: number;
  detected_patterns: string[];
  ring_id: string;
}

export interface FraudRing {
  ring_id: string;
  member_accounts: string[];
  pattern_type: string;
  risk_score: number;
}

export interface AnalysisSummary {
  total_accounts_analyzed: number;
  suspicious_accounts_flagged: number;
  fraud_rings_detected: number;
  processing_time_seconds: number;
}

export interface AnalysisResult {
  suspicious_accounts: SuspiciousAccount[];
  fraud_rings: FraudRing[];
  summary: AnalysisSummary;
  nodes: GraphNode[];
  edges: GraphEdge[];
}

export interface GraphNode {
  id: string;
  suspicious: boolean;
  ring_ids: string[];
  patterns: string[];
  total_sent: number;
  total_received: number;
  transaction_count: number;
  suspicion_score: number;
}

export interface GraphEdge {
  source: string;
  target: string;
  amount: number;
  timestamp: string;
  transaction_id: string;
}

// Build adjacency list from transactions
function buildAdjacencyList(transactions: Transaction[]): Map<string, Map<string, Transaction[]>> {
  const adj = new Map<string, Map<string, Transaction[]>>();
  for (const tx of transactions) {
    if (!adj.has(tx.sender_id)) adj.set(tx.sender_id, new Map());
    const senderMap = adj.get(tx.sender_id)!;
    if (!senderMap.has(tx.receiver_id)) senderMap.set(tx.receiver_id, []);
    senderMap.get(tx.receiver_id)!.push(tx);
  }
  return adj;
}

// Get all unique accounts
function getAllAccounts(transactions: Transaction[]): Set<string> {
  const accounts = new Set<string>();
  for (const tx of transactions) {
    accounts.add(tx.sender_id);
    accounts.add(tx.receiver_id);
  }
  return accounts;
}

// Compute per-account statistics
function computeAccountStats(transactions: Transaction[]) {
  const stats = new Map<string, {
    totalSent: number;
    totalReceived: number;
    sendCount: number;
    receiveCount: number;
    senders: Set<string>;
    receivers: Set<string>;
    transactionTimestamps: number[];
    totalTransactions: number;
  }>();

  function getOrCreate(id: string) {
    if (!stats.has(id)) {
      stats.set(id, {
        totalSent: 0,
        totalReceived: 0,
        sendCount: 0,
        receiveCount: 0,
        senders: new Set(),
        receivers: new Set(),
        transactionTimestamps: [],
        totalTransactions: 0,
      });
    }
    return stats.get(id)!;
  }

  for (const tx of transactions) {
    const sender = getOrCreate(tx.sender_id);
    const receiver = getOrCreate(tx.receiver_id);
    const ts = new Date(tx.timestamp).getTime();

    sender.totalSent += tx.amount;
    sender.sendCount++;
    sender.receivers.add(tx.receiver_id);
    sender.transactionTimestamps.push(ts);
    sender.totalTransactions++;

    receiver.totalReceived += tx.amount;
    receiver.receiveCount++;
    receiver.senders.add(tx.sender_id);
    receiver.transactionTimestamps.push(ts);
    receiver.totalTransactions++;
  }

  return stats;
}

// =====================================================
// Normalize a set of members + pattern into a dedup key
// Sort member accounts alphabetically and combine with pattern type
// =====================================================
function makeRingDeduplicationKey(members: string[], patternType: string): string {
  const sorted = [...members].sort();
  return `${patternType}::${sorted.join(",")}`;
}

// =====================================================
// Pattern 1: Circular Fund Routing (Cycles of length 3-5)
// Uses DFS-based cycle detection
// =====================================================
function detectCycles(
  adj: Map<string, Map<string, Transaction[]>>,
  allAccounts: Set<string>
): string[][] {
  const cycles: string[][] = [];
  const allNodes = Array.from(allAccounts);

  for (const startNode of allNodes) {
    const visited = new Set<string>();
    const path: string[] = [];

    function dfs(current: string, depth: number) {
      if (depth > 5) return;
      path.push(current);
      visited.add(current);

      const neighbors = adj.get(current);
      if (neighbors) {
        for (const [neighbor] of neighbors) {
          if (neighbor === startNode && depth >= 3) {
            cycles.push([...path]);
          } else if (!visited.has(neighbor) && depth < 5) {
            dfs(neighbor, depth + 1);
          }
        }
      }

      path.pop();
      visited.delete(current);
    }

    dfs(startNode, 1);
  }

  // Deduplicate cycles (same cycle found starting from different nodes)
  const uniqueCycles: string[][] = [];
  const seen = new Set<string>();

  for (const cycle of cycles) {
    // Normalize: rotate so smallest element is first
    const minIdx = cycle.indexOf(
      cycle.reduce((a, b) => (a < b ? a : b))
    );
    const normalized = [...cycle.slice(minIdx), ...cycle.slice(0, minIdx)];
    const key = normalized.join("|");
    if (!seen.has(key)) {
      seen.add(key);
      uniqueCycles.push(normalized);
    }
  }

  return uniqueCycles;
}

// =====================================================
// Pattern 2: Smurfing (Fan-in / Fan-out)
// Fan-in: 10+ senders -> 1 receiver within 72h window
// Fan-out: 1 sender -> 10+ receivers within 72h window
// =====================================================
function detectSmurfing(transactions: Transaction[]) {
  const WINDOW_MS = 72 * 60 * 60 * 1000; // 72 hours
  const MIN_CONNECTIONS = 10;

  const fanInAccounts: Map<string, { senders: string[]; temporal: boolean }> = new Map();
  const fanOutAccounts: Map<string, { receivers: string[]; temporal: boolean }> = new Map();

  const byReceiver = new Map<string, Transaction[]>();
  const bySender = new Map<string, Transaction[]>();

  for (const tx of transactions) {
    if (!byReceiver.has(tx.receiver_id)) byReceiver.set(tx.receiver_id, []);
    byReceiver.get(tx.receiver_id)!.push(tx);
    if (!bySender.has(tx.sender_id)) bySender.set(tx.sender_id, []);
    bySender.get(tx.sender_id)!.push(tx);
  }

  // Fan-in detection
  for (const [receiverId, txs] of byReceiver) {
    const uniqueSenders = new Set(txs.map(t => t.sender_id));
    if (uniqueSenders.size >= MIN_CONNECTIONS) {
      const timestamps = txs.map(t => new Date(t.timestamp).getTime()).sort((a, b) => a - b);
      let temporalCluster = false;
      for (let i = 0; i < timestamps.length; i++) {
        const windowEnd = timestamps[i] + WINDOW_MS;
        const sendersInWindow = new Set(
          txs
            .filter(t => {
              const ts = new Date(t.timestamp).getTime();
              return ts >= timestamps[i] && ts <= windowEnd;
            })
            .map(t => t.sender_id)
        );
        if (sendersInWindow.size >= MIN_CONNECTIONS) {
          temporalCluster = true;
          break;
        }
      }
      fanInAccounts.set(receiverId, {
        senders: Array.from(uniqueSenders),
        temporal: temporalCluster,
      });
    }
  }

  // Fan-out detection
  for (const [senderId, txs] of bySender) {
    const uniqueReceivers = new Set(txs.map(t => t.receiver_id));
    if (uniqueReceivers.size >= MIN_CONNECTIONS) {
      const timestamps = txs.map(t => new Date(t.timestamp).getTime()).sort((a, b) => a - b);
      let temporalCluster = false;
      for (let i = 0; i < timestamps.length; i++) {
        const windowEnd = timestamps[i] + WINDOW_MS;
        const receiversInWindow = new Set(
          txs
            .filter(t => {
              const ts = new Date(t.timestamp).getTime();
              return ts >= timestamps[i] && ts <= windowEnd;
            })
            .map(t => t.receiver_id)
        );
        if (receiversInWindow.size >= MIN_CONNECTIONS) {
          temporalCluster = true;
          break;
        }
      }
      fanOutAccounts.set(senderId, {
        receivers: Array.from(uniqueReceivers),
        temporal: temporalCluster,
      });
    }
  }

  return { fanInAccounts, fanOutAccounts };
}

// =====================================================
// Pattern 3: Layered Shell Networks
// Chains of 3+ hops where intermediate nodes have low tx degree (2-3)
// Final destination is always included even if not suspicious
// Cycle nodes are excluded from shell classification
// =====================================================
function detectShellNetworks(
  adj: Map<string, Map<string, Transaction[]>>,
  accountStats: ReturnType<typeof computeAccountStats>,
  cycleNodes: Set<string>
): string[][] {
  const chains: string[][] = [];
  const allNodes = Array.from(adj.keys());

  for (const startNode of allNodes) {
    // Skip if start node is part of a cycle
    if (cycleNodes.has(startNode)) continue;

    const visited = new Set<string>();
    const path: string[] = [startNode];
    visited.add(startNode);

    function dfs(current: string) {
      const neighbors = adj.get(current);
      if (!neighbors) return;

      for (const [neighbor] of neighbors) {
        if (visited.has(neighbor)) continue;
        // Skip cycle nodes to avoid misclassification
        if (cycleNodes.has(neighbor)) continue;

        const stats = accountStats.get(neighbor);
        const totalTx = stats ? stats.totalTransactions : 0;

        // Intermediate nodes should have low transaction counts (2-3)
        if (totalTx >= 2 && totalTx <= 3) {
          path.push(neighbor);
          visited.add(neighbor);

          // Check if there is a next hop (the final destination)
          const nextNeighbors = adj.get(neighbor);
          if (nextNeighbors) {
            for (const [nn] of nextNeighbors) {
              if (!visited.has(nn) && !cycleNodes.has(nn)) {
                const nnStats = accountStats.get(nn);
                const nnTx = nnStats ? nnStats.totalTransactions : 0;

                if (nnTx >= 2 && nnTx <= 3) {
                  // Continue the chain through another shell node
                  // Will be explored on next dfs call
                } else {
                  // This is the final destination - include it in the chain
                  // even if it doesn't have low tx count
                  if (path.length >= 2) {
                    // path has start + intermediaries, add final dest
                    chains.push([...path, nn]);
                  }
                }
              }
            }
          }

          // Record current chain if it's 3+ hops (path already has 3+ nodes)
          if (path.length >= 3) {
            chains.push([...path]);
          }

          dfs(neighbor);

          path.pop();
          visited.delete(neighbor);
        }
      }
    }

    dfs(startNode);
  }

  // Deduplicate: keep longest chains, remove subsets
  const sortedChains = chains.sort((a, b) => b.length - a.length);
  const uniqueChains: string[][] = [];

  for (const chain of sortedChains) {
    const chainSet = new Set(chain);
    let isSubset = false;
    for (const existing of uniqueChains) {
      const existingSet = new Set(existing);
      if (chain.every(node => existingSet.has(node))) {
        isSubset = true;
        break;
      }
    }
    if (!isSubset) {
      uniqueChains.push(chain);
    }
  }

  return uniqueChains;
}

// =====================================================
// Suspicion Score Calculation
// Returns a float between 0.0 and 100.0
// =====================================================
function calculateSuspicionScore(
  accountId: string,
  patterns: string[],
  accountStats: ReturnType<typeof computeAccountStats>,
  cycleCount: number,
  isSmurfHub: boolean,
  isShellNode: boolean,
  temporalFlag: boolean
): number {
  let score = 0.0;

  // Base pattern scores
  if (patterns.some(p => p.startsWith("cycle_length_"))) {
    score += 35.0;
    score += Math.min(cycleCount - 1, 3) * 10.0;
  }

  if (patterns.includes("fan_in")) score += 25.0;
  if (patterns.includes("fan_out")) score += 25.0;
  if (patterns.includes("shell_network")) score += 20.0;

  // Temporal analysis bonus
  if (temporalFlag) score += 15.0;

  // Transaction pattern analysis
  const stats = accountStats.get(accountId);
  if (stats) {
    const totalFlow = stats.totalSent + stats.totalReceived;
    if (totalFlow > 0) {
      const maxFlow = Math.max(stats.totalSent, stats.totalReceived);
      if (maxFlow > 0) {
        const flowRatio = Math.min(stats.totalSent, stats.totalReceived) / maxFlow;
        if (flowRatio > 0.7 && flowRatio < 1.0) {
          score += 10.0; // Near-equal in/out suggests pass-through
        }
      }
    }
  }

  // Ensure float and cap at 100.0
  const capped = Math.min(score, 100.0);
  // Round to 1 decimal place, ensure float format
  return Math.round(capped * 10) / 10;
}

// =====================================================
// Main Analysis Function
// =====================================================
export function analyzeTransactions(transactions: Transaction[]): AnalysisResult {
  const startTime = performance.now();

  const allAccounts = getAllAccounts(transactions);
  const adj = buildAdjacencyList(transactions);
  const accountStats = computeAccountStats(transactions);

  // Track patterns per account
  const accountPatterns = new Map<string, Set<string>>();
  const accountRings = new Map<string, Set<string>>();
  const fraudRings: FraudRing[] = [];

  // Ring deduplication set: normalized key -> true
  const ringDeduplicationSet = new Set<string>();

  function addPattern(accountId: string, pattern: string) {
    if (!accountPatterns.has(accountId)) accountPatterns.set(accountId, new Set());
    accountPatterns.get(accountId)!.add(pattern);
  }

  function addRing(accountId: string, ringId: string) {
    if (!accountRings.has(accountId)) accountRings.set(accountId, new Set());
    accountRings.get(accountId)!.add(ringId);
  }

  let ringCounter = 1;

  // Helper to generate sequential ring IDs
  function nextRingId(): string {
    const id = `RING_${String(ringCounter).padStart(3, "0")}`;
    ringCounter++;
    return id;
  }

  // ---- Detect Cycles ----
  const cycles = detectCycles(adj, allAccounts);
  const accountCycleCounts = new Map<string, number>();

  // Collect all nodes in cycles for shell network exclusion
  const cycleNodes = new Set<string>();

  for (const cycle of cycles) {
    // Deduplication: check if this set of members + pattern already exists
    const dedupKey = makeRingDeduplicationKey(cycle, "cycle");
    if (ringDeduplicationSet.has(dedupKey)) continue;
    ringDeduplicationSet.add(dedupKey);

    const ringId = nextRingId();

    for (const account of cycle) {
      addPattern(account, `cycle_length_${cycle.length}`);
      addRing(account, ringId);
      accountCycleCounts.set(account, (accountCycleCounts.get(account) || 0) + 1);
      cycleNodes.add(account);
    }

    const riskScore = Math.min(70.0 + cycle.length * 5.0, 100.0);
    fraudRings.push({
      ring_id: ringId,
      member_accounts: [...cycle],
      pattern_type: "cycle",
      risk_score: Math.round(riskScore * 10) / 10,
    });
  }

  // ---- Detect Smurfing ----
  const { fanInAccounts, fanOutAccounts } = detectSmurfing(transactions);

  for (const [accountId, data] of fanInAccounts) {
    const members = [accountId, ...data.senders];

    // Deduplication check
    const dedupKey = makeRingDeduplicationKey(members, "fan_in");
    if (ringDeduplicationSet.has(dedupKey)) continue;
    ringDeduplicationSet.add(dedupKey);

    const ringId = nextRingId();

    addPattern(accountId, "fan_in");
    addRing(accountId, ringId);

    for (const sender of data.senders) {
      addPattern(sender, "fan_in");
      addRing(sender, ringId);
    }

    const riskScore = Math.min(60.0 + (data.temporal ? 25.0 : 10.0) + data.senders.length * 0.5, 100.0);
    fraudRings.push({
      ring_id: ringId,
      member_accounts: members,
      pattern_type: "fan_in",
      risk_score: Math.round(riskScore * 10) / 10,
    });
  }

  for (const [accountId, data] of fanOutAccounts) {
    const members = [accountId, ...data.receivers];

    // Deduplication check
    const dedupKey = makeRingDeduplicationKey(members, "fan_out");
    if (ringDeduplicationSet.has(dedupKey)) continue;
    ringDeduplicationSet.add(dedupKey);

    const ringId = nextRingId();

    addPattern(accountId, "fan_out");
    addRing(accountId, ringId);

    for (const receiver of data.receivers) {
      addPattern(receiver, "fan_out");
      addRing(receiver, ringId);
    }

    const riskScore = Math.min(60.0 + (data.temporal ? 25.0 : 10.0) + data.receivers.length * 0.5, 100.0);
    fraudRings.push({
      ring_id: ringId,
      member_accounts: members,
      pattern_type: "fan_out",
      risk_score: Math.round(riskScore * 10) / 10,
    });
  }

  // ---- Detect Shell Networks ----
  // Pass cycleNodes so shell detection excludes cycle-classified nodes
  const shellChains = detectShellNetworks(adj, accountStats, cycleNodes);

  for (const chain of shellChains) {
    // Deduplication check
    const dedupKey = makeRingDeduplicationKey(chain, "shell_network");
    if (ringDeduplicationSet.has(dedupKey)) continue;
    ringDeduplicationSet.add(dedupKey);

    const ringId = nextRingId();

    for (const account of chain) {
      addPattern(account, "shell_network");
      addRing(account, ringId);
    }

    const riskScore = Math.min(50.0 + chain.length * 8.0, 100.0);
    fraudRings.push({
      ring_id: ringId,
      member_accounts: [...chain],
      pattern_type: "shell_network",
      risk_score: Math.round(riskScore * 10) / 10,
    });
  }

  // ---- Build Suspicious Accounts ----
  const suspiciousAccounts: SuspiciousAccount[] = [];

  for (const [accountId, patterns] of accountPatterns) {
    const rings = accountRings.get(accountId);
    if (!rings || rings.size === 0) continue;

    const isFanIn = fanInAccounts.has(accountId);
    const isFanOut = fanOutAccounts.has(accountId);
    const temporalFlag =
      (isFanIn && fanInAccounts.get(accountId)!.temporal) ||
      (isFanOut && fanOutAccounts.get(accountId)!.temporal);

    const score = calculateSuspicionScore(
      accountId,
      Array.from(patterns),
      accountStats,
      accountCycleCounts.get(accountId) || 0,
      isFanIn || isFanOut,
      patterns.has("shell_network"),
      temporalFlag
    );

    // Use the first ring as primary
    const primaryRing = Array.from(rings)[0];

    suspiciousAccounts.push({
      account_id: accountId,
      suspicion_score: score,
      detected_patterns: Array.from(patterns),
      ring_id: primaryRing,
    });
  }

  // Sort suspicious accounts by suspicion_score descending
  suspiciousAccounts.sort((a, b) => b.suspicion_score - a.suspicion_score);

  // ---- Build Graph Nodes ----
  const suspiciousSet = new Set(suspiciousAccounts.map(a => a.account_id));
  const nodes: GraphNode[] = [];

  for (const accountId of allAccounts) {
    const stats = accountStats.get(accountId);
    const rings = accountRings.get(accountId);
    const patterns = accountPatterns.get(accountId);
    const sa = suspiciousAccounts.find(a => a.account_id === accountId);

    nodes.push({
      id: accountId,
      suspicious: suspiciousSet.has(accountId),
      ring_ids: rings ? Array.from(rings) : [],
      patterns: patterns ? Array.from(patterns) : [],
      total_sent: stats?.totalSent || 0,
      total_received: stats?.totalReceived || 0,
      transaction_count: stats?.totalTransactions || 0,
      suspicion_score: sa?.suspicion_score || 0.0,
    });
  }

  // ---- Build Graph Edges ----
  const edges: GraphEdge[] = transactions.map(tx => ({
    source: tx.sender_id,
    target: tx.receiver_id,
    amount: tx.amount,
    timestamp: tx.timestamp,
    transaction_id: tx.transaction_id,
  }));

  // ---- Compute processing time properly ----
  const endTime = performance.now();
  const processingTimeSeconds = Math.round(((endTime - startTime) / 1000) * 1000) / 1000;

  // ---- Summary is computed dynamically from actual results ----
  return {
    suspicious_accounts: suspiciousAccounts,
    fraud_rings: fraudRings,
    summary: {
      total_accounts_analyzed: allAccounts.size,
      suspicious_accounts_flagged: suspiciousAccounts.length,
      fraud_rings_detected: fraudRings.length,
      processing_time_seconds: processingTimeSeconds,
    },
    nodes,
    edges,
  };
}
