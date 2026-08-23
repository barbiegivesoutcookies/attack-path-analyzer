import { useCallback, useEffect, useMemo, useState } from "react";
import GraphCanvas from "./components/GraphCanvas";
import RiskMetrics from "./components/RiskMetrics";
import RemediationPanel from "./components/RemediationPanel";
import type {
  AnalysisRequest,
  GraphResponse,
  MetricsResponse,
  RemediationResponse,
  ShortestPathResponse,
} from "./types";

/**
 * Base URL of the FastAPI backend. The origin is explicitly whitelisted in
 * core-engine/main.py's CORS middleware, so direct browser calls are
 * permitted during local development and presentation.
 */
const API_BASE: string = "http://localhost:8000";

/** Dropdown option derived from a graph node. */
interface NodeOption {
  id: string;
  label: string;
}

/**
 * Root component: owns all application state, orchestrates API calls across
 * the CORS boundary to the backend, and lays out the SOC-style dashboard.
 */
export default function App(): JSX.Element {
  const [graph, setGraph] = useState<GraphResponse | null>(null);
  const [metrics, setMetrics] = useState<MetricsResponse | null>(null);
  const [pathResult, setPathResult] = useState<ShortestPathResponse | null>(null);
  const [remediation, setRemediation] = useState<RemediationResponse | null>(null);
  const [sourceId, setSourceId] = useState<string>("");
  const [targetId, setTargetId] = useState<string>("");
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  // Initial load: topology map plus aggregate metrics.
  useEffect(() => {
    let cancelled: boolean = false;

    async function loadInitialData(): Promise<void> {
      try {
        const [graphRes, metricsRes]: [Response, Response] = await Promise.all([
          fetch(`${API_BASE}/api/graph`),
          fetch(`${API_BASE}/api/analytics/metrics`),
        ]);
        if (!graphRes.ok || !metricsRes.ok) {
          throw new Error(
            `Backend responded with ${graphRes.status} / ${metricsRes.status}`
          );
        }
        const graphData: GraphResponse = await graphRes.json();
        const metricsData: MetricsResponse = await metricsRes.json();
        if (cancelled) return;
        setGraph(graphData);
        setMetrics(metricsData);

        // Preselect defaults: first entry point and first crown jewel so
        // the dashboard is immediately usable during a demonstration.
        const entries: NodeOption[] = graphData.nodes.filter(
          (n) => n.is_entry_point || n.asset_type === "Attacker"
        );
        const jewels: NodeOption[] = graphData.nodes.filter((n) => n.is_crown_jewel);
        if (entries.length > 0) setSourceId(entries[0].id);
        if (jewels.length > 0) setTargetId(jewels[0].id);
      } catch (err) {
        if (!cancelled) {
          setError(
            err instanceof Error
              ? `Cannot reach backend (${API_BASE}): ${err.message}`
              : "Unknown error contacting the backend."
          );
        }
      }
    }

    void loadInitialData();
    return () => {
      cancelled = true;
    };
  }, []);

  /** Entry-point options for the attacker-origin dropdown. */
  const entryOptions: NodeOption[] = useMemo(() => {
    if (graph === null) return [];
    return graph.nodes
      .filter((n) => n.is_entry_point || n.asset_type === "Attacker")
      .map((n) => ({ id: n.id, label: n.label }));
  }, [graph]);

  /** Crown-jewel options for the target dropdown. */
  const crownJewelOptions: NodeOption[] = useMemo(() => {
    if (graph === null) return [];
    return graph.nodes
      .filter((n) => n.is_crown_jewel)
      .map((n) => ({ id: n.id, label: n.label }));
  }, [graph]);

  /**
   * Trigger both analyses against the selected endpoints. The critical-path
   * computation and the remediation ranking are independent queries, so they
   * run concurrently.
   */
  const runAnalysis = useCallback(async (): Promise<void> => {
    if (sourceId === "" || targetId === "") {
      setError("Select both an entry point and a crown jewel asset.");
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const payload: AnalysisRequest = { source_id: sourceId, target_id: targetId };
      const [pathRes, remRes]: [Response, Response] = await Promise.all([
        fetch(`${API_BASE}/api/analyze/shortest-path`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload),
        }),
        fetch(`${API_BASE}/api/remediation/suggest`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload),
        }),
      ]);

      if (!pathRes.ok) {
        const detail = await pathRes.json().catch(() => null);
        throw new Error(
          detail && typeof detail.detail === "string"
            ? detail.detail
            : `Path analysis failed (${pathRes.status})`
        );
      }
      if (!remRes.ok) {
        throw new Error(`Remediation analysis failed (${remRes.status})`);
      }

      const pathData: ShortestPathResponse = await pathRes.json();
      const remData: RemediationResponse = await remRes.json();
      setPathResult(pathData);
      setRemediation(remData);
    } catch (err) {
      setPathResult(null);
      setRemediation(null);
      setError(err instanceof Error ? err.message : "Unknown analysis error.");
    } finally {
      setLoading(false);
    }
  }, [sourceId, targetId]);

  return (
    <div className="min-h-screen bg-slate-950 text-slate-200">
      {/* Header */}
      <header className="border-b border-slate-800 bg-slate-900 px-6 py-4">
        <h1 className="text-xl font-semibold tracking-wide text-slate-100">
          Attack Path Analyzer
        </h1>
        <p className="mt-1 text-sm text-slate-400">
          Graph-Theoretic Cyber Attack Path Analysis and Risk Prediction System
        </p>
      </header>

      {/* Control panel */}
      <section className="border-b border-slate-800 bg-slate-900/60 px-6 py-4">
        <div className="flex flex-wrap items-end gap-4">
          <label className="flex flex-col gap-1">
            <span className="text-xs font-medium uppercase tracking-wider text-slate-400">
              Attacker Entry Point
            </span>
            <select
              value={sourceId}
              onChange={(e) => setSourceId(e.target.value)}
              className="w-64 rounded border border-slate-700 bg-slate-800 px-3 py-2 text-sm text-slate-200 focus:border-indigo-500 focus:outline-none"
            >
              <option value="">Select entry point...</option>
              {entryOptions.map((opt) => (
                <option key={opt.id} value={opt.id}>
                  {opt.label}
                </option>
              ))}
            </select>
          </label>

          <label className="flex flex-col gap-1">
            <span className="text-xs font-medium uppercase tracking-wider text-slate-400">
              Crown Jewel Asset
            </span>
            <select
              value={targetId}
              onChange={(e) => setTargetId(e.target.value)}
              className="w-64 rounded border border-slate-700 bg-slate-800 px-3 py-2 text-sm text-slate-200 focus:border-indigo-500 focus:outline-none"
            >
              <option value="">Select crown jewel...</option>
              {crownJewelOptions.map((opt) => (
                <option key={opt.id} value={opt.id}>
                  {opt.label}
                </option>
              ))}
            </select>
          </label>

          <button
            onClick={() => void runAnalysis()}
            disabled={loading}
            className="rounded bg-indigo-600 px-5 py-2 text-sm font-medium text-white transition-colors hover:bg-indigo-500 disabled:cursor-not-allowed disabled:bg-slate-700"
          >
            {loading ? "Analyzing..." : "Analyze Attack Path"}
          </button>

          {error !== null && (
            <p className="max-w-md rounded border border-red-900 bg-red-950/60 px-3 py-2 text-sm text-red-300">
              {error}
            </p>
          )}
        </div>
      </section>

      {/* Main content */}
      <main className="grid grid-cols-1 gap-4 p-6 xl:grid-cols-[minmax(0,2fr)_minmax(0,1fr)]">
        <GraphCanvas graph={graph} pathNodes={pathResult?.path_nodes ?? null} />
        <div className="flex flex-col gap-4">
          <RiskMetrics pathResult={pathResult} metrics={metrics} />
          <RemediationPanel remediation={remediation} />
        </div>
      </main>
    </div>
  );
}