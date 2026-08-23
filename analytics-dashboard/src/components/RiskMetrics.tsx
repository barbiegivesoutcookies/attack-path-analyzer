import type { MetricsResponse, ShortestPathResponse } from "../types";

interface RiskMetricsProps {
  /** Result of POST /api/analyze/shortest-path; null before analysis. */
  pathResult: ShortestPathResponse | null;
  /** Result of GET /api/analytics/metrics; null while loading. */
  metrics: MetricsResponse | null;
}

/** Formats a probability in [0, 1] as a percentage string. */
function formatPercent(value: number): string {
  return `${(value * 100).toFixed(2)}%`;
}

/** Formats a probability as a scientific-notation product for small values. */
function formatProbability(value: number): string {
  if (value >= 0.001) {
    return value.toFixed(6);
  }
  return value.toExponential(4);
}

/**
 * Mathematical risk metrics panel.
 *
 * Displays the cumulative path probability P(Path) = Product(p_i) as a
 * percentage, per-edge probabilities along the critical route, and the
 * aggregate graph statistics returned by the analytics endpoint.
 */
export default function RiskMetrics({
  pathResult,
  metrics,
}: RiskMetricsProps): JSX.Element {
  return (
    <section className="rounded border border-slate-800 bg-slate-900">
      <div className="border-b border-slate-800 px-4 py-3">
        <h2 className="text-sm font-semibold uppercase tracking-wider text-slate-300">
          Risk Metrics
        </h2>
      </div>

      <div className="space-y-4 px-4 py-4">
        {pathResult === null ? (
          <p className="text-sm text-slate-500">
            Run an analysis to compute the critical attack path probability.
          </p>
        ) : (
          <>
            {/* Headline metric: cumulative path exploit probability. */}
            <div className="rounded border border-indigo-900/60 bg-indigo-950/40 px-4 py-3">
              <p className="text-xs uppercase tracking-wider text-indigo-300">
                Path Exploit Probability
              </p>
              <p className="mt-1 font-mono text-3xl font-semibold text-indigo-200">
                {formatPercent(pathResult.path_probability)}
              </p>
              <p className="mt-1 font-mono text-xs text-slate-400">
                P(Path) = Product(p_i) = {formatProbability(pathResult.path_probability)}
              </p>
            </div>

            {/* Path statistics. */}
            <div className="grid grid-cols-2 gap-3">
              <div className="rounded border border-slate-800 bg-slate-950/60 px-3 py-2">
                <p className="text-xs uppercase tracking-wider text-slate-500">
                  Path Length
                </p>
                <p className="mt-0.5 font-mono text-lg text-slate-200">
                  {pathResult.path_length_hops} hops
                </p>
              </div>
              <div className="rounded border border-slate-800 bg-slate-950/60 px-3 py-2">
                <p className="text-xs uppercase tracking-wider text-slate-500">
                  Edges in Path
                </p>
                <p className="mt-0.5 font-mono text-lg text-slate-200">
                  {pathResult.path_edges.length}
                </p>
              </div>
            </div>

            {/* Per-edge breakdown of the critical route. */}
            <div>
              <p className="mb-2 text-xs uppercase tracking-wider text-slate-500">
                Critical Route Breakdown
              </p>
              <ul className="space-y-1.5">
                {pathResult.path_edges.map((edge, index) => (
                  <li
                    key={`${edge.source}->${edge.target}`}
                    className="flex items-center justify-between rounded border border-slate-800 bg-slate-950/60 px-3 py-2 font-mono text-xs"
                  >
                    <span className="text-slate-300">
                      {index + 1}. {edge.source} &rarr; {edge.target}
                    </span>
                    <span className="flex items-center gap-3">
                      <span className="text-slate-500">{edge.cve_id}</span>
                      <span className="text-red-300">
                        p = {edge.probability.toFixed(4)}
                      </span>
                    </span>
                  </li>
                ))}
              </ul>
            </div>
          </>
        )}

        {/* Aggregate graph statistics. */}
        {metrics !== null && (
          <div className="border-t border-slate-800 pt-4">
            <p className="mb-2 text-xs uppercase tracking-wider text-slate-500">
              Aggregate Exposure
            </p>
            <div className="grid grid-cols-2 gap-3">
              <div className="rounded border border-slate-800 bg-slate-950/60 px-3 py-2">
                <p className="text-xs uppercase tracking-wider text-slate-500">
                  Total Attack Paths
                </p>
                <p className="mt-0.5 font-mono text-lg text-slate-200">
                  {metrics.total_attack_paths}
                </p>
              </div>
              <div className="rounded border border-slate-800 bg-slate-950/60 px-3 py-2">
                <p className="text-xs uppercase tracking-wider text-slate-500">
                  Avg Path Length
                </p>
                <p className="mt-0.5 font-mono text-lg text-slate-200">
                  {metrics.average_path_length.toFixed(2)} hops
                </p>
              </div>
            </div>

            <p className="mb-2 mt-4 text-xs uppercase tracking-wider text-slate-500">
              Top Vulnerable Assets
            </p>
            <ul className="space-y-1.5">
              {metrics.top_vulnerable_assets.map((asset) => (
                <li
                  key={asset.asset_id}
                  className="flex items-center justify-between rounded border border-slate-800 bg-slate-950/60 px-3 py-2 font-mono text-xs"
                >
                  <span className="text-slate-300">{asset.asset_id}</span>
                  <span className="text-amber-300">
                    exposure = {asset.incoming_exposure.toFixed(4)}
                  </span>
                </li>
              ))}
            </ul>
          </div>
        )}
      </div>
    </section>
  );
}