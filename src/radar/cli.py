"""CLI entry point for Robot Security Radar.

Usage:
    radar run [--offline] [--registry PATH] [--raw-dir PATH] [--site-dir PATH]
    radar load-seed [--seeds DIR] [--registry PATH] [--dry-run]
    radar emit [--registry PATH] [--site-dir PATH]
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path


def _default_registry() -> str:
    """Prefer the live registry; fall back to the fixture for pre-first-run local use."""
    return "data/registry.json" if Path("data/registry.json").exists() else "data/fixtures/registry.json"


def _run(args: argparse.Namespace) -> None:
    from radar.runner import run

    try:
        summary = run(
            offline=args.offline,
            registry_path=Path(args.registry or _default_registry()),
            raw_dir=Path(args.raw_dir) if args.raw_dir else None,
            site_dir=Path(args.site_dir),
        )
        print(f"Done: fetched={summary['fetched']}, gated={summary['gated']}, added={summary['added']}")
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)


def _load_seed(args: argparse.Namespace) -> None:
    from pathlib import Path as _Path

    from radar.seed_loader import load_seeds
    from radar.registry import load, save

    seeds_dir = _Path(args.seeds) if args.seeds else _Path("data/seeds")
    registry_path = _Path(args.registry) if args.registry else _Path(_default_registry())

    try:
        reg = load(registry_path)
        merged, summary = load_seeds(seeds_dir, reg, dry_run=args.dry_run)

        print(f"Loaded: {summary['loaded']}, Skipped: {summary['skipped']}, Rejected: {summary['rejected']}")
        if summary["rejected_details"]:
            print("\nRejected incidents:")
            for detail in summary["rejected_details"]:
                print(f"  - {detail['id']}: {detail['title']}")
                print(f"    Reason: {detail['reason']}")

        if not args.dry_run:
            save(merged, registry_path)
            print(f"\nRegistry saved to {registry_path}")
        else:
            print("\nDry run — no changes written.")
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)


def _emit(args: argparse.Namespace) -> None:
    from radar.emitters import emit
    from radar.registry import load

    try:
        reg = load(Path(args.registry or _default_registry()))
        emit(reg, Path(args.site_dir))
        print("Emitted site files.")
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="radar",
        description="Robot Security Radar — buyer-first security radar for embodied intelligence",
    )
    sub = parser.add_subparsers(dest="command")

    # radar run
    run_parser = sub.add_parser("run", help="Run the fetch→gate→apply→save→emit pipeline")
    run_parser.add_argument("--offline", action="store_true", help="Use offline fixture mode")
    run_parser.add_argument("--registry", default=None, help="Registry file path")
    run_parser.add_argument("--raw-dir", default=None, help="Raw fixture directory (offline mode)")
    run_parser.add_argument("--site-dir", default="site", help="Site output directory")
    run_parser.set_defaults(func=_run, registry=None)

    # radar load-seed
    seed_parser = sub.add_parser("load-seed", help="Load hand-curated seed incidents into the registry")
    seed_parser.add_argument("--seeds", default=None, help="Seeds directory (default: data/seeds)")
    seed_parser.add_argument("--registry", default=None, help="Registry file path")
    seed_parser.add_argument("--dry-run", action="store_true", help="Validate only, print what would load/reject")
    seed_parser.set_defaults(func=_load_seed)

    # radar emit
    emit_parser = sub.add_parser("emit", help="Emit site files from existing registry")
    emit_parser.add_argument("--registry", default=None, help="Registry file path")
    emit_parser.add_argument("--site-dir", default="site", help="Site output directory")
    emit_parser.set_defaults(func=_emit, registry=None)

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(1)
    args.func(args)


if __name__ == "__main__":
    main()
