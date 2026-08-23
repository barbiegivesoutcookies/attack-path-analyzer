# Mathematical Framework

This document defines every mathematical quantity used by the Attack Path
Analyzer, states the modeling assumptions, proves the correctness of the
shortest-path transformation, and analyzes computational complexity.

## 1. Graph Model

The enterprise environment is modeled as a directed graph `G = (V, E)`:

- **Nodes** `V` represent assets: hosts, subnets, databases, and Active
  Directory domains, plus a synthetic external-attacker origin.
- **Edges** `(u, v) in E` represent a directed exploitability relation: a
  successful exploitation of a vulnerability (CVE) or abuse of a
  misconfiguration on asset `v` by an attacker positioned at asset `u`.

Each edge carries the four CVSS v3.1 Exploitability metrics of the
vulnerability it models:

| Metric | Values | Weight |
| --- | --- | --- |
| Attack Vector (AV) | Network / Adjacent / Local / Physical | 0.85 / 0.62 / 0.55 / 0.20 |
| Attack Complexity (AC) | Low / High | 0.77 / 0.44 |
| Privileges Required (PR) | None / Low / High | 0.85 / 0.62 / 0.27 |
| User Interaction (UI) | None / Required | 0.85 / 0.62 |

## 2. CVSS-to-Probability Mapping

Each edge's exploit probability is derived from the literal CVSS v3.1
Exploitability subscore formula (FIRST specification, Appendix A):

```
Exploitability = 8.22 x AV x AC x PR x UI
```

The subscore attains its maximum when every metric is most exploitable:
`8.22 x 0.85 x 0.77 x 0.85 x 0.85 = 3.887`. Normalizing to `[0, 1]`:

```
p_i = Exploitability / 3.887
```

**Clamping.** The raw quotient can approach zero for the least exploitable
combination (Physical / High / High / Required gives approximately 0.031,
and arbitrary future metric tables could reach exactly zero). Because
Section 4 uses the transformation `-ln(p_i)`, any `p_i = 0` would produce an
infinite weight and break shortest-path arithmetic. The implementation
therefore clamps:

```
p_i = clamp(Exploitability / 3.887, 0.01, 1.0)
```

The floor of **0.01** keeps all weights finite while remaining negligible
relative to typical probabilities; the ceiling guards against floating-point
drift pushing the maximal combination marginally above 1.0.

## 3. Path Risk Probability

For a simple path `P = (v_0 -> v_1 -> ... -> v_k)` with edge probabilities
`p_1, ..., p_k`, the cumulative exploit probability is:

```
P(Path) = Product_{i=1..k} p_i
```

### Modeling assumption: conditional independence

The product form is exact only if the sequential exploit events are
conditionally independent given the attacker's position at each intermediate
node. This is a deliberate simplification with known real-world limitations:

- **Positive correlation (underestimation).** Credential material, session
  tokens, or network footholds harvested at one stage frequently raise the
  success probability of later stages, so the product tends to underestimate
  chained intrusion success.
- **Negative correlation (overestimation).** Defensive detection triggered
  mid-chain can suppress subsequent stages, causing overestimation.

Despite these limitations, the product form is the standard first-order
Bayesian approximation in attack-graph literature (e.g., Sheyner et al.'s
attack scenario graphs). It yields monotone, comparable risk scores, which is
sufficient for the system's objective: prioritization of attack routes and
mitigations rather than absolute probabilistic forecasting.

## 4. Most Probable Attack Path via Dijkstra

Define each edge's attacker-difficulty weight as:

```
w_i = -ln(p_i)
```

Since `p_i in [0.01, 1]`, every weight lies in `[0, ln(100)]`: non-negative
and finite, satisfying Dijkstra's preconditions.

**Equivalence proof (one line).** For any path P:

```
Sum_{i in P} w_i = Sum (-ln p_i) = -ln( Product p_i ) = -ln P(Path)
```

Because `-ln` is strictly monotonically decreasing on `(0, 1]`, minimizing
`Sum(w_i)` over all paths is equivalent to maximizing `Product(p_i)`.
Therefore Dijkstra's algorithm over these weights returns the path with the
highest true probability product -- not merely the fewest hops. This property
is verified empirically by `test_most_probable_path_via_dijkstra`, whose toy
graph contains a one-hop route with probability 0.05 competing against a
three-hop route with probability 0.729; the engine must select the longer
route.

## 5. Remediation Optimization

Given entry points `S` and crown jewel `t`, let `Paths(S, t)` be the set of
simple attack paths from any entry point to `t`. For each candidate edge
`e in E`:

1. Temporarily remove `e` from a copy of `G`.
2. Recompute `Paths(S, t)` on the modified graph.
3. Score `e` by `eliminated(e) = |Paths(S, t)| - |Paths_e(S, t)|`.

Edges are ranked descending by `eliminated(e)`; ties preserve input order for
deterministic output. An edge eliminating all paths (a cut edge / bottleneck)
ranks first and represents the single highest-leverage mitigation.

### Complexity analysis

Let `E` be the number of candidate edges, `V` the number of nodes, and `L`
the cutoff-bounded maximum path length.

- Baseline enumeration: bounded by the cutoff, `O(V^L)` worst case;
  practically far smaller on sparse enterprise graphs.
- Per candidate edge: graph copy plus recomputation costs `O(E + V log V)`
  when restricted to shortest-path recomputation.
- Total for the shortest-path-recomputation formulation:

```
O(E x (E + V log V))
```

**Tractability note.** This remains tractable for the small-to-medium graphs
used in this project's presentation scope (tens of nodes and edges): even
with E = 100 candidates, sub-millisecond Dijkstra recomputations complete the
full ranking well under a second. Production deployments at enterprise scale
would replace exhaustive enumeration with approximate techniques --
betweenness-based criticality scoring or Monte Carlo path sampling -- which
are outside this project's scope but noted as future work.

## 6. Aggregate Metrics

- **Total attack paths**: `|Paths(S, t)|` summed across all crown jewels,
  computed by cutoff-bounded enumeration of simple paths.
- **Average path length**: mean edge count across enumerated paths.
- **Incoming exposure** per asset `v`:
  `exposure(v) = Sum over incoming edges (u,v) of p_(u,v)`, a proxy for how
  much attacker success mass converges on the asset. The top five assets by
  exposure are reported as "top vulnerable assets".

## 7. Worked Example (seed dataset)

Using the seed topology, the most probable path from `attacker-ext` to
`db-financial` traverses:

```
attacker-ext --(1.000)--> web-server-01 --(0.7295)--> subnet-corp
             --(1.000)--> workstation-finance --(0.7295)--> db-financial
```

```
P(Path) = 1.0 x 0.7295 x 1.0 x 0.7295 = 0.5322  (53.22%)
```

The competing route through the VPN gateway carries per-edge probabilities
`0.304 x 1.0 x ...` and is strictly dominated at its first hop, so Dijkstra
correctly discards it despite comparable hop counts. The remediation engine
additionally identifies edges such as `subnet-corp -> workstation-finance`
as high-leverage bottlenecks because they lie on multiple distinct attack
routes converging on the core tier.