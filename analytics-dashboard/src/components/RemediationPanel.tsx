import type { RemediationResponse } from "../types";

interface RemediationPanelProps {
  /** Result of POST /api/remediation/suggest; null before analysis. */
  remediation: RemediationResponse | null;
}

/**
 * Remediation recommendations panel.
 *
 * Presents the ranked output of the edge-removal analysis: each candidate
 * names the specific patching or configuration action that breaks the threat
 * path, ordered by the number of critical attack paths eliminated.
 */
export default function RemediationPanel({
  remediation,
}: RemediationPanelProps): JSX.Element {
  return (
    <section className="rounded border border-slate-800 bg-slate-900">
      <div className="border-b border-slate-800 px-4 py-3">
        <h2 className="text-sm font-semibold uppercase tracking-wider text-slate-300">
          Remediation Strategy
        </h2>
      </div>

      <div className="px-4 py-4">
        {remediation === null ? (
          <p className="text-sm text-slate-500">
            Run an analysis to compute ranked mitigation recommendations.
          </p>
        ) : remediation.candidates.length === 0 ? (
          <p className="text-sm text-slate-500">
            No single-edge mitigation reduces the baseline of{" "}
            {remediation.baseline_path_count} attack path(s).
          </p>
        ) : (
          <>
            <p className="mb-3 text-xs text-slate-400">
              Baseline:{" "}
              <span className="font-mono text-slate-200">
                {remediation.baseline_path_count}
              </span>{" "}
              critical attack path(s) to the crown jewel. Ranked by paths
              eliminated per edge removal.
            </p>

            <ol className="space-y-3">
              {remediation.candidates.map((candidate, index) => (
                <li
                  key={`${candidate.edge.source}->${candidate.edge.target}`}
                  className={`rounded border px-4 py-3 ${
                    index === 0
                      ? "border-emerald-800 bg-emerald-950/30"
                      : "border-slate-800 bg-slate-950/60"
                  }`}
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="font-mono text-xs text-slate-300">
                      #{index + 1} &nbsp;
                      {candidate.edge.source} &rarr; {candidate.edge.target}
                    </span>
                    <span
                      className={`rounded px-2 py-0.5 font-mono text-xs ${
                        index === 0
                          ? "bg-emerald-900/60 text-emerald-300"
                          : "bg-slate-800 text-slate-400"
                      }`}
                    >
                      breaks {candidate.paths_eliminated} path(s)
                    </span>
                  </div>
                  <p className="mt-2 text-sm leading-relaxed text-slate-300">
                    {candidate.recommendation}
                  </p>
                  <p className="mt-1 font-mono text-xs text-slate-500">
                    Remaining paths after removal: {candidate.remaining_paths}
                  </p>
                </li>
              ))}
            </ol>
          </>
        )}
      </div>
    </section>
  );
}