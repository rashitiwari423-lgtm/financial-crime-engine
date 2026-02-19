"use client";

import { useEffect, useRef, useState, useCallback } from "react";
import type { GraphNode, GraphEdge } from "@/lib/graph-engine";

interface GraphVisualizationProps {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

interface LayoutNode extends GraphNode {
  x: number;
  y: number;
  vx: number;
  vy: number;
}

const RING_COLORS = [
  "#22d3ee", // cyan
  "#ef4444", // red
  "#f97316", // orange
  "#a3e635", // lime
  "#facc15", // yellow
  "#ec4899", // pink
  "#8b5cf6", // violet
  "#14b8a6", // teal
];

function getRingColor(ringId: string, ringMap: Map<string, number>): string {
  if (!ringMap.has(ringId)) {
    ringMap.set(ringId, ringMap.size % RING_COLORS.length);
  }
  return RING_COLORS[ringMap.get(ringId)!];
}

export function GraphVisualization({ nodes, edges }: GraphVisualizationProps) {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const [hoveredNode, setHoveredNode] = useState<LayoutNode | null>(null);
  const [tooltipPos, setTooltipPos] = useState({ x: 0, y: 0 });
  const layoutNodesRef = useRef<LayoutNode[]>([]);
  const animFrameRef = useRef<number>(0);
  const offsetRef = useRef({ x: 0, y: 0 });
  const scaleRef = useRef(1);
  const isDraggingRef = useRef(false);
  const lastMouseRef = useRef({ x: 0, y: 0 });
  const ringMapRef = useRef(new Map<string, number>());

  // Initialize force-directed layout
  useEffect(() => {
    if (nodes.length === 0) return;

    const canvas = canvasRef.current;
    const container = containerRef.current;
    if (!canvas || !container) return;

    const width = container.clientWidth;
    const height = container.clientHeight;
    canvas.width = width * window.devicePixelRatio;
    canvas.height = height * window.devicePixelRatio;
    canvas.style.width = `${width}px`;
    canvas.style.height = `${height}px`;

    const ctx = canvas.getContext("2d")!;
    ctx.scale(window.devicePixelRatio, window.devicePixelRatio);

    // Place nodes in initial positions
    const layoutNodes: LayoutNode[] = nodes.map((node, i) => {
      const angle = (2 * Math.PI * i) / nodes.length;
      const radius = Math.min(width, height) * 0.35;
      return {
        ...node,
        x: width / 2 + radius * Math.cos(angle) + (Math.random() - 0.5) * 50,
        y: height / 2 + radius * Math.sin(angle) + (Math.random() - 0.5) * 50,
        vx: 0,
        vy: 0,
      };
    });

    layoutNodesRef.current = layoutNodes;

    const nodeMap = new Map<string, LayoutNode>();
    for (const n of layoutNodes) nodeMap.set(n.id, n);

    // Center the view
    offsetRef.current = { x: 0, y: 0 };
    scaleRef.current = 1;

    let iteration = 0;
    const maxIterations = 300;

    function simulate() {
      if (iteration < maxIterations) {
        const alpha = Math.max(0.01, 1 - iteration / maxIterations);
        const repulsion = 800;
        const attraction = 0.002;
        const centerGravity = 0.01;

        // Repulsion between all nodes
        for (let i = 0; i < layoutNodes.length; i++) {
          for (let j = i + 1; j < layoutNodes.length; j++) {
            const dx = layoutNodes[j].x - layoutNodes[i].x;
            const dy = layoutNodes[j].y - layoutNodes[i].y;
            const dist = Math.max(Math.sqrt(dx * dx + dy * dy), 1);
            const force = (repulsion * alpha) / (dist * dist);
            const fx = (dx / dist) * force;
            const fy = (dy / dist) * force;
            layoutNodes[i].vx -= fx;
            layoutNodes[i].vy -= fy;
            layoutNodes[j].vx += fx;
            layoutNodes[j].vy += fy;
          }
        }

        // Attraction along edges
        for (const edge of edges) {
          const source = nodeMap.get(edge.source);
          const target = nodeMap.get(edge.target);
          if (!source || !target) continue;
          const dx = target.x - source.x;
          const dy = target.y - source.y;
          const dist = Math.sqrt(dx * dx + dy * dy);
          const force = dist * attraction * alpha;
          const fx = (dx / Math.max(dist, 1)) * force;
          const fy = (dy / Math.max(dist, 1)) * force;
          source.vx += fx;
          source.vy += fy;
          target.vx -= fx;
          target.vy -= fy;
        }

        // Center gravity
        for (const node of layoutNodes) {
          node.vx += (width / 2 - node.x) * centerGravity * alpha;
          node.vy += (height / 2 - node.y) * centerGravity * alpha;
        }

        // Apply velocities with damping
        for (const node of layoutNodes) {
          node.vx *= 0.6;
          node.vy *= 0.6;
          node.x += node.vx;
          node.y += node.vy;
          // Keep in bounds
          node.x = Math.max(30, Math.min(width - 30, node.x));
          node.y = Math.max(30, Math.min(height - 30, node.y));
        }

        iteration++;
      }

      // Draw
      ctx.save();
      ctx.setTransform(
        window.devicePixelRatio * scaleRef.current,
        0,
        0,
        window.devicePixelRatio * scaleRef.current,
        window.devicePixelRatio * offsetRef.current.x,
        window.devicePixelRatio * offsetRef.current.y
      );

      ctx.clearRect(
        -offsetRef.current.x / scaleRef.current,
        -offsetRef.current.y / scaleRef.current,
        width / scaleRef.current + Math.abs(offsetRef.current.x) * 2 / scaleRef.current,
        height / scaleRef.current + Math.abs(offsetRef.current.y) * 2 / scaleRef.current
      );

      // Draw edges
      for (const edge of edges) {
        const source = nodeMap.get(edge.source);
        const target = nodeMap.get(edge.target);
        if (!source || !target) continue;

        const isSuspiciousEdge = source.suspicious && target.suspicious;

        ctx.beginPath();
        ctx.moveTo(source.x, source.y);
        ctx.lineTo(target.x, target.y);
        ctx.strokeStyle = isSuspiciousEdge ? "rgba(239, 68, 68, 0.5)" : "rgba(113, 113, 122, 0.15)";
        ctx.lineWidth = isSuspiciousEdge ? 1.5 : 0.5;
        ctx.stroke();

        // Arrowhead
        const angle = Math.atan2(target.y - source.y, target.x - source.x);
        const nodeRadius = target.suspicious ? 8 : 5;
        const arrowX = target.x - Math.cos(angle) * (nodeRadius + 4);
        const arrowY = target.y - Math.sin(angle) * (nodeRadius + 4);
        const arrowSize = isSuspiciousEdge ? 6 : 4;

        ctx.beginPath();
        ctx.moveTo(arrowX, arrowY);
        ctx.lineTo(
          arrowX - arrowSize * Math.cos(angle - Math.PI / 6),
          arrowY - arrowSize * Math.sin(angle - Math.PI / 6)
        );
        ctx.lineTo(
          arrowX - arrowSize * Math.cos(angle + Math.PI / 6),
          arrowY - arrowSize * Math.sin(angle + Math.PI / 6)
        );
        ctx.closePath();
        ctx.fillStyle = isSuspiciousEdge ? "rgba(239, 68, 68, 0.6)" : "rgba(113, 113, 122, 0.2)";
        ctx.fill();
      }

      // Draw nodes
      for (const node of layoutNodes) {
        const radius = node.suspicious ? 7 + (node.suspicion_score / 100) * 5 : 4;

        if (node.suspicious) {
          // Glow effect
          ctx.beginPath();
          ctx.arc(node.x, node.y, radius + 4, 0, Math.PI * 2);
          const ringColor = node.ring_ids.length > 0 
            ? getRingColor(node.ring_ids[0], ringMapRef.current) 
            : "#ef4444";
          ctx.fillStyle = ringColor + "25";
          ctx.fill();

          // Node
          ctx.beginPath();
          ctx.arc(node.x, node.y, radius, 0, Math.PI * 2);
          ctx.fillStyle = ringColor;
          ctx.fill();
          ctx.strokeStyle = "#09090b";
          ctx.lineWidth = 1.5;
          ctx.stroke();
        } else {
          ctx.beginPath();
          ctx.arc(node.x, node.y, radius, 0, Math.PI * 2);
          ctx.fillStyle = "#3f3f46";
          ctx.fill();
        }
      }

      ctx.restore();
      animFrameRef.current = requestAnimationFrame(simulate);
    }

    simulate();

    return () => {
      cancelAnimationFrame(animFrameRef.current);
    };
  }, [nodes, edges]);

  // Mouse interaction handlers
  const getMousePos = useCallback(
    (e: React.MouseEvent) => {
      const canvas = canvasRef.current;
      if (!canvas) return { x: 0, y: 0 };
      const rect = canvas.getBoundingClientRect();
      return {
        x: (e.clientX - rect.left - offsetRef.current.x) / scaleRef.current,
        y: (e.clientY - rect.top - offsetRef.current.y) / scaleRef.current,
      };
    },
    []
  );

  const handleMouseMove = useCallback(
    (e: React.MouseEvent) => {
      if (isDraggingRef.current) {
        offsetRef.current.x += e.clientX - lastMouseRef.current.x;
        offsetRef.current.y += e.clientY - lastMouseRef.current.y;
        lastMouseRef.current = { x: e.clientX, y: e.clientY };
        return;
      }

      const pos = getMousePos(e);
      const layoutNodes = layoutNodesRef.current;

      let found: LayoutNode | null = null;
      for (const node of layoutNodes) {
        const dx = pos.x - node.x;
        const dy = pos.y - node.y;
        const dist = Math.sqrt(dx * dx + dy * dy);
        const hitRadius = node.suspicious ? 14 : 8;
        if (dist < hitRadius) {
          found = node;
          break;
        }
      }

      setHoveredNode(found);
      if (found) {
        const canvas = canvasRef.current;
        if (canvas) {
          const rect = canvas.getBoundingClientRect();
          setTooltipPos({
            x: e.clientX - rect.left,
            y: e.clientY - rect.top,
          });
        }
      }
    },
    [getMousePos]
  );

  const handleMouseDown = useCallback((e: React.MouseEvent) => {
    isDraggingRef.current = true;
    lastMouseRef.current = { x: e.clientX, y: e.clientY };
  }, []);

  const handleMouseUp = useCallback(() => {
    isDraggingRef.current = false;
  }, []);

  const handleWheel = useCallback((e: React.WheelEvent) => {
    e.preventDefault();
    const delta = e.deltaY > 0 ? 0.9 : 1.1;
    const newScale = Math.max(0.1, Math.min(5, scaleRef.current * delta));

    const canvas = canvasRef.current;
    if (!canvas) return;
    const rect = canvas.getBoundingClientRect();
    const mouseX = e.clientX - rect.left;
    const mouseY = e.clientY - rect.top;

    offsetRef.current.x = mouseX - (mouseX - offsetRef.current.x) * (newScale / scaleRef.current);
    offsetRef.current.y = mouseY - (mouseY - offsetRef.current.y) * (newScale / scaleRef.current);
    scaleRef.current = newScale;
  }, []);

  return (
    <div ref={containerRef} className="relative h-[500px] w-full overflow-hidden rounded-lg border border-border bg-background">
      <canvas
        ref={canvasRef}
        className="h-full w-full cursor-grab active:cursor-grabbing"
        onMouseMove={handleMouseMove}
        onMouseDown={handleMouseDown}
        onMouseUp={handleMouseUp}
        onMouseLeave={handleMouseUp}
        onWheel={handleWheel}
      />
      {/* Legend */}
      <div className="absolute bottom-3 left-3 flex flex-col gap-1.5 rounded-md bg-card/90 px-3 py-2 text-xs backdrop-blur">
        <div className="flex items-center gap-2">
          <span className="inline-block h-3 w-3 rounded-full bg-[#3f3f46]" />
          <span className="text-muted-foreground">Normal account</span>
        </div>
        <div className="flex items-center gap-2">
          <span className="inline-block h-3 w-3 rounded-full bg-[#ef4444]" />
          <span className="text-muted-foreground">Suspicious account</span>
        </div>
        <div className="flex items-center gap-2">
          <span className="inline-block h-1 w-5 bg-[rgba(239,68,68,0.5)]" />
          <span className="text-muted-foreground">Suspicious flow</span>
        </div>
      </div>
      <div className="absolute bottom-3 right-3 rounded-md bg-card/90 px-3 py-2 text-xs text-muted-foreground backdrop-blur">
        Scroll to zoom. Drag to pan.
      </div>
      {/* Tooltip */}
      {hoveredNode && (
        <div
          className="pointer-events-none absolute z-50 min-w-[220px] rounded-lg border border-border bg-card p-3 shadow-lg"
          style={{
            left: tooltipPos.x + 16,
            top: tooltipPos.y - 10,
          }}
        >
          <p className="font-mono text-sm font-semibold text-foreground">{hoveredNode.id}</p>
          <div className="mt-2 flex flex-col gap-1 text-xs">
            <div className="flex justify-between">
              <span className="text-muted-foreground">Total Sent</span>
              <span className="text-foreground font-mono">${hoveredNode.total_sent.toLocaleString()}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-muted-foreground">Total Received</span>
              <span className="text-foreground font-mono">${hoveredNode.total_received.toLocaleString()}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-muted-foreground">Transactions</span>
              <span className="text-foreground font-mono">{hoveredNode.transaction_count}</span>
            </div>
            {hoveredNode.suspicious && (
              <>
                <div className="mt-1 border-t border-border pt-1">
                  <div className="flex justify-between">
                    <span className="text-destructive">Suspicion Score</span>
                    <span className="font-mono font-bold text-destructive">
                      {hoveredNode.suspicion_score}
                    </span>
                  </div>
                </div>
                <div className="flex flex-wrap gap-1 mt-1">
                  {hoveredNode.patterns.map((p) => (
                    <span
                      key={p}
                      className="rounded bg-destructive/15 px-1.5 py-0.5 text-[10px] font-mono text-destructive"
                    >
                      {p}
                    </span>
                  ))}
                </div>
              </>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
