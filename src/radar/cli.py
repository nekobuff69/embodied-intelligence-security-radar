"""CLI entry point for Robot Security Radar.

Usage:
    radar run [--offline] [--registry PATH] [--raw-dir PATH] [--site-dir PATH]
    radar emit [--registry PATH] [--site-dir PATH]
    radar prune [--registry PATH] [--dry-run]
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
        reg_path = Path(args.registry) if args.registry else Path("data/registry.json")
        summary = run(
            offline=args.offline,
            registry_path=reg_path,
            raw_dir=Path(args.raw_dir) if args.raw_dir else None,
            site_dir=Path(args.site_dir),
        )
        print(f"Done: fetched={summary['fetched']}, gated={summary['gated']}, added={summary['added']}")
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


def _override(args: argparse.Namespace) -> None:
    from radar.overrides import (
        detach_items,
        merge_incidents,
        save_atomic,
        split_incident,
    )
    from radar.registry import load

    registry_path = Path(args.registry) if args.registry else Path(_default_registry())

    try:
        reg = load(registry_path)

        if args.op == "split":
            keep_items = (
                [s.strip() for s in args.items.split(",") if s.strip()]
                if args.items
                else []
            )
            reg, summary = split_incident(reg, args.incident, keep_items)

        elif args.op == "merge":
            if not args.with_id:
                print("Error: merge requires --with <incident_id>", file=sys.stderr)
                sys.exit(1)
            reg, summary = merge_incidents(reg, args.incident, args.with_id)

        elif args.op == "detach":
            detach_ids = (
                [s.strip() for s in args.items.split(",") if s.strip()]
                if args.items
                else []
            )
            if not detach_ids:
                print("Error: detach requires --items <id1,id2,...>", file=sys.stderr)
                sys.exit(1)
            reg, summary = detach_items(reg, args.incident, detach_ids)

        else:
            print(f"Error: unknown operation {args.op!r}", file=sys.stderr)
            sys.exit(1)

        # Print summary
        print(f"Operation: {summary['operation']}")
        for key, value in summary.items():
            if key == "operation":
                continue
            print(f"  {key}: {value}")

        if args.dry_run:
            print("\nDry run — no changes written.")
        else:
            save_atomic(reg, registry_path)
            print(f"\nRegistry saved to {registry_path}")

    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)


def _prune(args: argparse.Namespace) -> None:
    from pathlib import Path as _Path

    from radar.prune import prune
    from radar.registry import load, save_dismissed
    from radar.overrides import save_atomic

    registry_path = _Path(args.registry) if args.registry else _Path("data/registry.json")
    dismissed_path = _Path("data/dismissed_urls.json")

    try:
        reg = load(registry_path)
        reg, summary = prune(reg)

        print("Prune summary:")
        for key, value in summary.items():
            print(f"  {key}: {value}")

        if args.dry_run:
            print("\nDry run — no changes written.")
        else:
            # Persist blocklist
            save_dismissed(dismissed_path, set(summary["dismissed_urls"]))
            # Save pruned registry
            save_atomic(reg, registry_path)
            print(f"\nRegistry saved to {registry_path}")
            print(f"Blocklist saved to {dismissed_path}")

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

    # radar emit
    emit_parser = sub.add_parser("emit", help="Emit site files from existing registry")
    emit_parser.add_argument("--registry", default=None, help="Registry file path")
    emit_parser.add_argument("--site-dir", default="site", help="Site output directory")
    emit_parser.set_defaults(func=_emit, registry=None)

    # radar override
    override_parser = sub.add_parser(
        "override",
        help="Operator corrections: split, merge, detach incidents",
    )
    override_parser.add_argument(
        "--op", required=True, choices=["split", "merge", "detach"],
        help="Operation: split | merge | detach",
    )
    override_parser.add_argument(
        "--incident", required=True, help="Target incident ID",
    )
    override_parser.add_argument(
        "--with", dest="with_id", default=None,
        help="Incident ID to merge INTO --incident (merge only)",
    )
    override_parser.add_argument(
        "--items", default=None,
        help="Comma-separated item IDs (split keep-set or detach list)",
    )
    override_parser.add_argument(
        "--registry", default=None, help="Registry file path",
    )
    override_parser.add_argument(
        "--dry-run", action="store_true",
        help="Print summary without writing",
    )
    override_parser.set_defaults(func=_override)

    # radar prune
    prune_parser = sub.add_parser(
        "prune",
        help="Retroactive pruning: dismiss stale/commentary items, demote ineligible incidents",
    )
    prune_parser.add_argument("--registry", default=None, help="Registry file path")
    prune_parser.add_argument("--dry-run", action="store_true", help="Print summary without writing")
    prune_parser.set_defaults(func=_prune)

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(1)
    args.func(args)


if __name__ == "__main__":
    main()
