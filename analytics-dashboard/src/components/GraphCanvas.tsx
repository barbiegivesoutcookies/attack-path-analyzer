import { useEffect, useRef } from "react";
import cytoscape, { type Core, type ElementDefinition } from "cytoscape";
import type { GraphResponse } from "../types";

interface GraphCanvasProps {
  /** Full topology fetched from GET /api/graph; null while loading. */
  graph: GraphResponse | null;
  /** Ordered node IDs of the computed critical path; null before analysis. */
  pathNodes: string[] | null;
}

/**
 * Node color mapping by asset type, following the SOC convention:
 * servers/hosts render red, attacker/user-class assets blue, databases
 * purple, subnets zinc, and Active Directory domains amber.
 */
const ASSET_TYPE_COLORS: Record<string, string> = {
  Attacker: "#3b82f6", // blue
  Host: "#ef4444", // red
  Subnet: "#71717a", // zinc
  Database: "#a855f7", // purple
  ActiveDirectoryDomain: "#f59e0b", // amber
};

const DEFAULT_NODE_COLOR: string = "#64748b"; // slate
const CRITICAL_COLOR: string = "#dc2626"; // bright crimson

/**
 * Interactive topology canvas rendered with Cytoscape.js.
 *
 * The container carries explicit CSS dimensions (#cytoscape-canvas in
 * index.css: width 100%, height 600px) because Cytoscape measures its parent
 * at initialization time; a zero-height parent would produce an invisible
 * canvas.
 */
export default function GraphCanvas({
  graph,
  pathNodes,
}: GraphCanvasProps): JSX.Element {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const cyRef = useRef<Core | null>(null);

  // Build / rebuild the Cytoscape instance whenever the topology changes.
  useEffect(() => {
    if (containerRef.current === null || graph === null) {
      return;
    }

    const elements: ElementDefinition[] = [
      ...graph.nodes.map((node) => ({
        data: {
          id: node.id,
          label: node.label,
          color: ASSET_TYPE_COLORS[node.asset_type] ?? DEFAULT_NODE_COLOR,
          isCrownJewel: node.is_crown_jewel,
        },
      })),
      ...graph.edges.map((edge) => ({
        data: {
          id: `${edge.source}->${edge.target}`,
          source: edge.source,
          target: edge.target,
          label: edge.cve_id,
          probability: edge.probability,
        },
      })),
    ];

    const cy: Core = cytoscape({
      container: containerRef.current,
      elements,
      style: [
        {
          selector: "node",
          style: {
            "background-color": "data(color)",
            label: "data(label)",
            color: "#e2e8f0",
            "text-valign": "bottom",
            "text-margin-y": 8,
            "font-size": 11,
            "font-family": "Consolas, monospace",
            width: 28,
            height: 28,
            "border-width": 2,
            "border-color": "#0f172a",
          },
        },
        {
          // Crown jewels receive a distinctive ring so mission-critical
          // assets are identifiable without consulting the legend.
          selector: "node[isCrownJewel]",
          style: {
            "border-width": 3,
            "border-color": "#fbbf24",
            shape: "star",
            width: 34,
            height: 34,
          },
        },
        {
          selector: "edge",
          style: {
            width: 2,
            "line-color": "#475569",
            "target-arrow-color": "#475569",
            "target-arrow-shape": "triangle",
            "curve-style": "bezier",
            label: "data(label)",
            "font-size": 9,
            "font-family": "Consolas, monospace",
            color: "#94a3b8",
            "text-background-color": "#0f172a",
            "text-background-opacity": 0.85,
            "text-background-padding": "2px",
            "transition-property": "line-color target-arrow-color width",
            "transition-duration": 250,
          },
        },
        {
          // Critical-path styling: bright crimson edges and nodes with an
          // emphasized width, applied via the 'critical' class.
          selector: "edge.critical",
          style: {
            width: 5,
            "line-color": CRITICAL_COLOR,
            "target-arrow-color": CRITICAL_COLOR,
            color: "#fca5a5",
            "z-index": 10,
          },
        },
        {
          selector: "node.critical",
          style: {
            "border-width": 4,
            "border-color": CRITICAL_COLOR,
            "z-index": 10,
          },
        },
      ],
      layout: {
        name: "cose",
        animate: true,
        animationDuration: 400,
        nodeOverlap: 20,
        idealEdgeLength: 120,
      },
    });

    cyRef.current = cy;

    return () => {
      cy.destroy();
      cyRef.current = null;
    };
  }, [graph]);

  // Highlight the critical path whenever a new analysis result arrives.
  useEffect(() => {
    const cy: Core | null = cyRef.current;
    if (cy === null) {
      return;
    }

    cy.batch(() => {
      cy.elements().removeClass("critical");
      if (pathNodes === null || pathNodes.length < 2) {
        return;
      }
      for (const nodeId of pathNodes) {
        cy.getElementById(nodeId).addClass("critical");
      }
      for (let i = 0; i < pathNodes.length - 1; i += 1) {
        cy.getElementById(`${pathNodes[i]}->${pathNodes[i + 1]}`).addClass(
          "critical"
        );
      }
    });

    // Pulse animation on the critical edges draws the presenter's and the
    // audience's eye to the active threat route.
    const criticalEdges = cy.edges(".critical");
    if (criticalEdges.length > 0) {
      criticalEdges
        .animate({ style: { width: 8 } as never, duration: 350 })
        .animate({ style: { width: 5 } as never, duration: 350 });
    }
  }, [pathNodes, graph]);

  return (
    <section className="rounded border border-slate-800 bg-slate-900">
      <div className="flex items-center justify-between border-b border-slate-800 px-4 py-3">
        <h2 className="text-sm font-semibold uppercase tracking-wider text-slate-300">
          Network Topology
        </h2>
        <div className="flex items-center gap-4 text-xs text-slate-400">
          <span className="flex items-center gap-1.5">
            <span className="inline-block h-2.5 w-2.5 rounded-full bg-[#ef4444]" />
            Host
          </span>
          <span className="flex items-center gap-1.5">
            <span className="inline-block h-2.5 w-2.5 rounded-full bg-[#3b82f6]" />
            Attacker
          </span>
          <span className="flex items-center gap-1.5">
            <span className="inline-block h-2.5 w-2.5 rounded-full bg-[#a855f7]" />
            Database
          </span>
          <span className="flex items-center gap-1.5">
            <span className="inline-block h-2.5 w-2.5 rounded-full bg-[#f59e0b]" />
            AD Domain
          </span>
          <span className="flex items-center gap-1.5">
            <span className="inline-block h-0.5 w-4 bg-[#dc2626]" />
            Critical Path
          </span>
        </div>
      </div>
      <div id="cytoscape-canvas" ref={containerRef} />
    </section>
  );
}