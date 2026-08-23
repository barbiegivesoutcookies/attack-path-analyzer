"""
Automated test suite for the attack-path analysis algorithms.

Run from the ``core-engine`` directory with Python's native unittest runner::

    python -m unittest test_algorithms -v

Each test constructs a small hand-built toy graph whose expected outputs are
computed manually, so a failure pinpoints a defect in the mathematics rather
than in data plumbing.
"""

from __future__ import annotations

import itertools
import math
import unittest

import networkx as nx

from algorithms import (
    MAX_EXPLOITABILITY,
    MIN_PROBABILITY_FLOOR,
    cvss_to_probability,
    edge_probability,
    most_probable_attack_path,
    path_probability,
    rank_remediation_edges,
)

ATTACK_VECTORS = ["NETWORK", "ADJACENT_NETWORK", "LOCAL", "PHYSICAL"]
ATTACK_COMPLEXITIES = ["LOW", "HIGH"]
PRIVILEGES_REQUIRED = ["NONE", "LOW", "HIGH"]
USER_INTERACTIONS = ["NONE", "REQUIRED"]


def _make_graph(edges: list[tuple[str, str, float]]) -> nx.DiGraph:
    """Build a directed graph whose edges carry explicit probabilities.

    :param edges: Triples of ``(source, target, probability)``.
    :return: Directed graph with precomputed per-edge exploit probabilities.
    """
    graph: nx.DiGraph = nx.DiGraph()
    for source, target, probability in edges:
        graph.add_edge(source, target, probability=probability)
    return graph


class TestCvssProbabilityMapping(unittest.TestCase):
    """Validate the CVSS v3.1 Exploitability-to-probability transformation."""

    def test_cvss_probability_mapping(self) -> None:
        """Every CVSS metric combination must map into [0.01, 1.0].

        The full Cartesian product of CVSS v3.1 Exploitability metrics is
        exercised so no boundary combination can silently escape the clamp.
        """
        combinations = itertools.product(
            ATTACK_VECTORS,
            ATTACK_COMPLEXITIES,
            PRIVILEGES_REQUIRED,
            USER_INTERACTIONS,
        )
        checked: int = 0
        for av, ac, pr, ui in combinations:
            probability: float = cvss_to_probability(av, ac, pr, ui)
            self.assertGreaterEqual(
                probability,
                MIN_PROBABILITY_FLOOR,
                msg=f"p below floor for ({av}, {ac}, {pr}, {ui})",
            )
            self.assertLessEqual(
                probability,
                1.0,
                msg=f"p above 1.0 for ({av}, {ac}, {pr}, {ui})",
            )
            checked += 1
        self.assertEqual(
            checked,
            len(ATTACK_VECTORS)
            * len(ATTACK_COMPLEXITIES)
            * len(PRIVILEGES_REQUIRED)
            * len(USER_INTERACTIONS),
            msg="Cartesian product did not cover every metric combination.",
        )

    def test_maximum_combination_normalizes_to_one(self) -> None:
        """The most exploitable combination must normalize to exactly 1.0.

        NETWORK/LOW/NONE/NONE yields Exploitability = 8.22 x 0.85 x 0.77 x
        0.85 x 0.85 = 3.887..., which divided by MAX_EXPLOITABILITY reaches
        the upper clamp.
        """
        probability: float = cvss_to_probability("NETWORK", "LOW", "NONE", "NONE")
        self.assertAlmostEqual(probability, 1.0, places=9)

    def test_formula_matches_literal_specification(self) -> None:
        """Verify the literal formula against an independently computed value.

        For ADJACENT_NETWORK/HIGH/LOW/REQUIRED:
            Exploitability = 8.22 x 0.62 x 0.44 x 0.62 x 0.62
        and p = Exploitability / 3.887, unclamped since it exceeds 0.01.
        """
        expected_raw: float = (
            8.22 * 0.62 * 0.44 * 0.62 * 0.62 / MAX_EXPLOITABILITY
        )
        expected: float = max(MIN_PROBABILITY_FLOOR, min(expected_raw, 1.0))
        actual: float = cvss_to_probability(
            "ADJACENT_NETWORK", "HIGH", "LOW", "REQUIRED"
        )
        self.assertAlmostEqual(actual, expected, places=12)


class TestPathProbabilityProduct(unittest.TestCase):
    """Validate P(Path) = Product(p_i) against manual calculations."""

    def test_path_probability_product(self) -> None:
        """The computed product must equal the hand-calculated product.

        Toy chain: A ->(0.5)-> B ->(0.4)-> C ->(0.25)-> D.
        Manual expectation: 0.5 x 0.4 x 0.25 = 0.05.
        """
        graph: nx.DiGraph = _make_graph(
            [
                ("A", "B", 0.5),
                ("B", "C", 0.4),
                ("C", "D", 0.25),
            ]
        )
        result: float = path_probability(graph, ["A", "B", "C", "D"])
        self.assertAlmostEqual(result, 0.5 * 0.4 * 0.25, places=12)
        self.assertAlmostEqual(result, 0.05, places=12)

    def test_single_node_path_has_unit_probability(self) -> None:
        """A trivial path containing only the source carries probability 1.0."""
        graph: nx.DiGraph = _make_graph([("A", "B", 0.7)])
        self.assertAlmostEqual(path_probability(graph, ["A"]), 1.0, places=12)

    def test_missing_edge_raises_value_error(self) -> None:
        """Referencing a non-existent consecutive edge must fail loudly."""
        graph: nx.DiGraph = _make_graph([("A", "B", 0.5)])
        with self.assertRaises(ValueError):
            path_probability(graph, ["A", "Z"])


class TestMostProbablePathViaDijkstra(unittest.TestCase):
    """Validate that Dijkstra over -ln(p) weights maximizes true probability."""

    def test_most_probable_path_via_dijkstra(self) -> None:
        """The engine must prefer higher cumulative probability over fewer hops.

        Toy topology with two competing routes from S to T:

            Direct route (1 hop):   S ->(0.05)-> T              => P = 0.05
            Multi-hop route (3 hops): S ->(0.9)-> A ->(0.9)-> B ->(0.9)-> T
                                    => P = 0.9^3 = 0.729

        A naive hop-count shortest path would select the direct route. The
        -ln(p) weight transform makes Sum(w) = -ln(Product p), so Dijkstra
        must select the three-hop route because -ln(0.729) < -ln(0.05).
        """
        graph: nx.DiGraph = _make_graph(
            [
                ("S", "T", 0.05),
                ("S", "A", 0.9),
                ("A", "B", 0.9),
                ("B", "T", 0.9),
            ]
        )

        path, probability = most_probable_attack_path(graph, "S", "T")

        self.assertEqual(path, ["S", "A", "B", "T"])
        self.assertAlmostEqual(probability, 0.9 ** 3, places=12)
        self.assertAlmostEqual(probability, 0.729, places=12)

    def test_dijkstra_equivalence_identity_holds(self) -> None:
        """Confirm -ln(Product p) equals Sum(-ln p) on the selected route.

        This is the identity underpinning the algorithm's correctness; if it
        ever failed, the weight transform would not be optimizing the true
        path probability.
        """
        graph: nx.DiGraph = _make_graph(
            [
                ("S", "A", 0.9),
                ("A", "B", 0.9),
                ("B", "T", 0.9),
            ]
        )
        _path, probability = most_probable_attack_path(graph, "S", "T")
        self.assertAlmostEqual(-math.log(probability), -3 * math.log(0.9), places=12)

    def test_no_path_raises_value_error(self) -> None:
        """Disconnected endpoints must raise rather than return garbage."""
        graph: nx.DiGraph = _make_graph([("A", "B", 0.5)])
        with self.assertRaises(ValueError):
            most_probable_attack_path(graph, "A", "X")


class TestRemediationEdgeRanking(unittest.TestCase):
    """Validate bottleneck identification by exhaustive edge removal."""

    def test_remediation_edge_ranking(self) -> None:
        """The known bottleneck edge must rank first among mitigations.

        Toy topology where two independent routes converge on a single final
        hop M ->(0.95)-> T:

            S ->(0.9)-> A ->(0.9)-> M ->(0.95)-> T
            S ->(0.8)-> B ->(0.9)-> M ->(0.95)-> T

        Removing M -> T destroys both baseline paths (eliminates 2); removing
        any other single edge destroys exactly one. The remediation function
        must therefore rank (M, T) first.
        """
        graph: nx.DiGraph = _make_graph(
            [
                ("S", "A", 0.9),
                ("S", "B", 0.8),
                ("A", "M", 0.9),
                ("B", "M", 0.9),
                ("M", "T", 0.95),
            ]
        )

        rankings = rank_remediation_edges(graph, entry_points=["S"], target="T")

        self.assertTrue(rankings, "Rankings must not be empty.")
        top: dict = rankings[0]
        self.assertEqual(top["edge"], {"source": "M", "target": "T"})
        self.assertEqual(top["paths_eliminated"], 2)
        self.assertEqual(top["remaining_paths"], 0)

        # Every other candidate must eliminate exactly one path, confirming
        # the bottleneck's strict dominance.
        others = [r for r in rankings[1:] if r["paths_eliminated"]]
        for record in others:
            self.assertEqual(record["paths_eliminated"], 1)

    def test_ranking_is_sorted_descending(self) -> None:
        """Output ordering must be non-increasing in paths eliminated."""
        graph: nx.DiGraph = _make_graph(
            [
                ("S", "A", 0.9),
                ("A", "M", 0.9),
                ("B", "M", 0.9),
                ("M", "T", 0.95),
            ]
        )
        rankings = rank_remediation_edges(graph, entry_points=["S"], target="T")
        counts = [int(r["paths_eliminated"]) for r in rankings]  # type: ignore[arg-type]
        self.assertEqual(counts, sorted(counts, reverse=True))

    def test_recommendation_text_mentions_cve_and_assets(self) -> None:
        """Recommendations must name the CVE and both endpoint assets."""
        graph: nx.DiGraph = nx.DiGraph()
        graph.add_edge(
            "web-01",
            "db-core",
            cve_id="CVE-2024-0001",
            attack_vector="NETWORK",
            attack_complexity="LOW",
            privileges_required="NONE",
            user_interaction="NONE",
            probability=edge_probability({}),
        )
        # Recompute properly from the stored metrics instead of the empty
        # placeholder used at construction time.
        graph.edges["web-01", "db-core"]["probability"] = cvss_to_probability(
            "NETWORK", "LOW", "NONE", "NONE"
        )
        rankings = rank_remediation_edges(graph, entry_points=["web-01"], target="db-core")
        recommendation: str = str(rankings[0]["recommendation"])
        self.assertIn("CVE-2024-0001", recommendation)
        self.assertIn("web-01", recommendation)
        self.assertIn("db-core", recommendation)


if __name__ == "__main__":
    unittest.main()