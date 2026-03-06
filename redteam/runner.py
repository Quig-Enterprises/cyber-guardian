#!/usr/bin/env python3
"""Security Red Team - CLI Runner"""

import argparse
import asyncio
import sys
import logging
import time
from datetime import datetime
from pathlib import Path

from shared import load_config
from redteam.client import RedTeamClient
from redteam.registry import AttackRegistry
from redteam.scoring import aggregate_scores
from redteam.reporters.console import ConsoleReporter
from redteam.reporters.json_report import JsonReporter
from redteam.reporters.html import HtmlReporter
from redteam.cleanup.db import DatabaseCleaner

logger = logging.getLogger("redteam")


def parse_args():
    parser = argparse.ArgumentParser(
        description="Security Red Team - EQMON Attack Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  runner.py --list
  runner.py --all --report console json
  runner.py --category ai --report console
  runner.py --attack ai.jailbreak --verbose
  runner.py --cleanup
        """,
    )

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--all", action="store_true", help="Run all attack batteries")
    group.add_argument(
        "--category",
        choices=["ai", "api", "web", "compliance"],
        help="Run attacks in a specific category",
    )
    group.add_argument(
        "--attack",
        type=str,
        metavar="NAME",
        help="Run a specific attack (e.g., ai.jailbreak)",
    )
    group.add_argument(
        "--list",
        action="store_true",
        help="List all available attacks",
    )
    group.add_argument(
        "--cleanup",
        action="store_true",
        help="Run cleanup only (remove test data)",
    )

    parser.add_argument(
        "--report",
        choices=["console", "json", "html"],
        nargs="+",
        default=["console"],
        help="Report format(s) (default: console)",
    )
    parser.add_argument(
        "--output",
        type=str,
        default="reports/",
        help="Report output directory (default: reports/)",
    )
    parser.add_argument(
        "--no-cleanup",
        action="store_true",
        help="Skip cleanup after run",
    )
    parser.add_argument(
        "--config",
        type=str,
        default="config.yaml",
        help="Config file path (default: config.yaml)",
    )
    parser.add_argument(
        "--mode",
        choices=["full", "aws"],
        default=None,
        help="Execution mode: 'full' (all attacks) or 'aws' (EC2-safe, restricted). "
             "Overrides execution.mode in config.yaml.",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose (DEBUG) logging",
    )

    return parser.parse_args()


async def run(args):
    # Setup logging
    level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    )

    # Load config
    config = load_config(args.config)

    # CLI --mode overrides execution.mode in config
    if args.mode is not None:
        config.setdefault("execution", {})["mode"] = args.mode
    exec_mode = config.get("execution", {}).get("mode", "full")
    logger.info(f"Execution mode: {exec_mode}")

    # Discover attacks
    registry = AttackRegistry()
    count = registry.discover()
    logger.info(f"Discovered {count} attack modules")

    # Handle --list
    if args.list:
        attacks = registry.list_attacks()
        console = ConsoleReporter()
        console.print_attack_list(attacks)
        return

    # Handle --cleanup
    if args.cleanup:
        # from redteam.cleanup.db import DatabaseCleaner
        # cleaner = DatabaseCleaner(config["database"])
        # await cleaner.cleanup(config["auth"]["test_users"])
        logger.info("Cleanup complete")
        return

    # Select attacks
    if args.all:
        attacks = registry.get_all()
    elif args.category:
        attacks = registry.get_by_category(args.category)
    elif args.attack:
        attack = registry.get_by_name(args.attack)
        if not attack:
            logger.error(f"Attack not found: {args.attack}")
            sys.exit(1)
        attacks = [attack]
    else:
        attacks = []

    if not attacks:
        logger.warning("No attacks matched the filter")
        return

    # In AWS mode, drop attacks that are in the skip list
    skip_attacks = config.get("execution", {}).get("aws", {}).get("skip_attacks", [])
    if skip_attacks:
        before = len(attacks)
        attacks = [a for a in attacks if a.name not in skip_attacks]
        skipped = before - len(attacks)
        if skipped:
            logger.info(f"AWS mode: skipping {skipped} attack(s): {skip_attacks}")

    # Authenticate
    test_user = config["redteam"]["auth"]["test_users"]["system_admin"]
    async with RedTeamClient(config["target"]["base_url"]) as client:
        if not await client.login(test_user["username"], test_user["password"]):
            logger.error("Authentication failed. Have test users been created?")
            sys.exit(1)

        # Run attacks
        suite_start = time.time()
        suite_start_iso = datetime.now().isoformat()
        scores = []
        for attack in attacks:
            logger.info(f"Running: {attack.name} ({attack.category})")
            attack._config = config  # make execution config available inside attack
            attack_start = time.time()
            try:
                results = await attack.execute(client)
                score = attack.score(results)
                attack_elapsed = (time.time() - attack_start) * 1000
                score.duration_ms = attack_elapsed
                scores.append(score)
                logger.info(
                    f"  -> {score.vulnerable} vulnerable, "
                    f"{score.partial} partial, "
                    f"{score.defended} defended "
                    f"({attack_elapsed:.0f}ms)"
                )
            except Exception as e:
                logger.error(f"  -> Error running {attack.name}: {e}")

            # Per-attack cleanup
            if not args.no_cleanup:
                try:
                    await attack.cleanup(client)
                except Exception as e:
                    logger.warning(f"  -> Cleanup error for {attack.name}: {e}")

        suite_end = time.time()
        suite_end_iso = datetime.now().isoformat()
        suite_duration_ms = (suite_end - suite_start) * 1000

        # Aggregate results
        summary = aggregate_scores(scores)
        summary["timing"] = {
            "start": suite_start_iso,
            "end": suite_end_iso,
            "duration_ms": round(suite_duration_ms, 1),
        }

        # Generate reports
        Path(args.output).mkdir(parents=True, exist_ok=True)
        for fmt in args.report:
            if fmt == "console":
                ConsoleReporter().print_report(summary)
            elif fmt == "json":
                path = JsonReporter().write_report(summary, args.output)
                logger.info(f"JSON report: {path}")
            elif fmt == "html":
                path = HtmlReporter().write_report(summary, args.output)
                logger.info(f"HTML report: {path}")

    # Global cleanup
    if not args.no_cleanup and config.get("cleanup", {}).get("enabled", True):
        logger.info("Running global cleanup...")
        try:
            cleaner = DatabaseCleaner(config["database"])
            cleaner.cleanup(delete_users=False)
        except Exception as e:
            logger.warning(f"Cleanup failed (non-fatal): {e}")


def main():
    args = parse_args()
    asyncio.run(run(args))


if __name__ == "__main__":
    main()
