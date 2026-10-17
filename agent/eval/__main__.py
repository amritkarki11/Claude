"""CLI entry point: python -m agent.eval

Examples:
    python -m agent.eval --fixture altoro --target http://demo.testfire.net
    python -m agent.eval --fixture altoro --save-baseline
    python -m agent.eval --fixture altoro --compare
"""
from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys

from .runner import EvalRunner
from .baseline import save_baseline, load_baseline, compare
from .fixtures import ALL_FIXTURES


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="python -m agent.eval",
        description="AUTON eval harness — measure scanner precision/recall/F1",
    )
    p.add_argument("--fixture", required=True, choices=list(ALL_FIXTURES.keys()),
                   help="Target fixture name")
    p.add_argument("--target", help="Override target URL (default: fixture's base_url)")
    p.add_argument("--output-dir", default="outputs/eval", help="Eval output directory")
    p.add_argument("--no-recon", action="store_true", help="Skip recon phase")
    p.add_argument("--attacker-cookie", help="Attacker session cookie string")
    p.add_argument("--victim-cookie", help="Victim session cookie string")
    p.add_argument("--save-baseline", action="store_true",
                   help="Save this run's metrics as the new baseline")
    p.add_argument("--compare", action="store_true",
                   help="Compare against stored baseline")
    p.add_argument("-v", "--verbose", action="store_true")
    return p


def main() -> None:
    args = _build_parser().parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s %(name)s: %(message)s",
    )

    runner = EvalRunner(
        args.fixture,
        target_override=args.target,
        output_dir=args.output_dir,
        recon=not args.no_recon,
        attacker_cookie=args.attacker_cookie,
        victim_cookie=args.victim_cookie,
    )

    result = asyncio.run(runner.run())

    if result.error:
        print(f"\n✗ Eval run failed: {result.error}", file=sys.stderr)
        sys.exit(1)

    m = result.metrics
    assert m is not None

    print(f"\n{'='*60}")
    print(f"  AUTON Eval — {result.fixture_name}")
    print(f"  Target: {result.target}")
    print(f"  Duration: {result.duration_s}s")
    print(f"{'='*60}")
    print(f"  Precision: {m.precision:.4f}")
    print(f"  Recall:    {m.recall:.4f}")
    print(f"  F1:        {m.f1:.4f}")
    print(f"  TP: {m.true_positive_count}  FP: {m.false_positive_count}  FN: {m.false_negative_count}")
    print(f"  Expected: {m.total_expected}  Confirmed: {m.total_confirmed}")
    print(f"{'='*60}")

    if m.match_detail.true_positives:
        print("\n  True Positives:")
        for exp, conf in m.match_detail.true_positives:
            print(f"    ✓ {exp.vuln_class}: {exp.endpoint} → {conf.get('scanner', '?')}")

    if m.match_detail.false_negatives:
        print("\n  False Negatives (missed):")
        for exp in m.match_detail.false_negatives:
            print(f"    ✗ {exp.vuln_class}: {exp.endpoint} ({exp.description})")

    if m.match_detail.false_positives:
        print("\n  False Positives:")
        for conf in m.match_detail.false_positives:
            print(f"    ! {conf.get('recipe_id', '?')}: {conf.get('endpoint', '?')}")

    metrics_dict = {
        "precision": m.precision,
        "recall": m.recall,
        "f1": m.f1,
        "true_positives": m.true_positive_count,
        "false_negatives": m.false_negative_count,
        "false_positives": m.false_positive_count,
    }

    if args.save_baseline:
        bp = save_baseline(args.fixture, metrics_dict)
        print(f"\n  Baseline saved to {bp}")

    if args.compare:
        bl = load_baseline(args.fixture)
        if bl is None:
            print("\n  No baseline found. Run with --save-baseline first.")
        else:
            comp = compare(bl, metrics_dict)
            print(f"\n  Baseline Comparison:")
            for line in comp.summary().split("\n"):
                print(f"    {line}")
            if comp.any_regression:
                sys.exit(2)


if __name__ == "__main__":
    main()
