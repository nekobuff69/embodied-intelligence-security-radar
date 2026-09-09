"""CLI entry point for Robot Security Radar.

Usage:
    radar run [--offline] [--registry PATH] [--raw-dir PATH] [--site-dir PATH]
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
