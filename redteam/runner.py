#!/usr/bin/env python3
"""Security Red Team - CLI Runner"""

import argparse
import asyncio
import os
import sys
import logging
import time
from datetime import datetime
from pathlib import Path

from shared import load_config
from shared.config import get_skip_attacks, get_execution_mode
from redteam.client import RedTeamClient
from redteam.wp_client import WordPressClient
from redteam.registry import AttackRegistry
from redteam.scoring import aggregate_scores
from redteam.reporters.console import ConsoleReporter
from redteam.reporters.json_report import JsonReporter
from redteam.reporters.html import HtmlReporter
from redteam.cleanup.db import DatabaseCleaner

logger = logging.getLogger("redteam")


def parse_args():
    parser = argparse.ArgumentParser(
        description="Security Red Team - Cyber-Guardian Attack Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  runner.py --list
  runner.py --list --target wordpress
  runner.py --all --report console json
  runner.py --category ai --report console
  runner.py --category wordpress --target wordpress
  runner.py --attack ai.jailbreak --verbose
  runner.py --attack wordpress.plugin_audit --plugin my-plugin --target wordpress
  runner.py --cleanup
        """,
    )

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--all", action="store_true", help="Run all attack batteries")
    group.add_argument(
        "--category",
        choices=["ai", "api", "web", "compliance", "wordpress"],
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
        "--target",
        choices=["eqmon", "wordpress", "generic"],
        default=None,
        help="Target type: 'eqmon' (default), 'wordpress', or 'generic'. "
             "Filters attacks by target_types compatibility.",
    )
    parser.add_argument(
        "--plugin",
        type=str,
        action="append",
        metavar="SLUG",
        help="WordPress plugin slug to audit (implies --target wordpress). "
             "Can be specified multiple times.",
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
    else:
        env_mode = os.environ.get("CYBER_GUARDIAN_MODE")
        if env_mode in ("full", "aws"):
            config.setdefault("execution", {})["mode"] = env_mode
    exec_mode = get_execution_mode(config)
    logger.info(f"Execution mode: {exec_mode}")

    # --plugin implies --target wordpress and adds slugs to config
    if args.plugin:
        args.target = "wordpress"
        wp_cfg = config.setdefault("target", {}).setdefault("wordpress", {})
        existing = wp_cfg.get("plugins", [])
        for slug in args.plugin:
            if slug not in existing:
                existing.append(slug)
        wp_cfg["plugins"] = existing

    # Determine target type (CLI > config > default)
    target_type = args.target or config.get("target", {}).get("type", "eqmon")
    config.setdefault("target", {})["type"] = target_type
    logger.info(f"Target type: {target_type}")

    # Discover attacks
    registry = AttackRegistry()
    count = registry.discover()
    logger.info(f"Discovered {count} attack modules")

    # Handle --list
    if args.list:
        all_attacks = registry.get_all()
        if args.target:
            all_attacks = _filter_by_target(all_attacks, target_type)
        attacks_info = [
            {
                "key": f"{a.category}.{a.name.split('.')[-1] if '.' in a.name else a.name}",
                "name": a.name,
                "category": a.category,
                "severity": a.severity.value,
                "description": a.description,
                "target_types": ", ".join(sorted(a.target_types)),
            }
            for a in all_attacks
        ]
        console = ConsoleReporter()
        console.print_attack_list(attacks_info)
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

    # Filter attacks by target type compatibility
    attacks = _filter_by_target(attacks, target_type)
    if not attacks:
        logger.warning(f"No attacks compatible with target type '{target_type}'")
        return
    logger.info(f"Running {len(attacks)} attack(s) for target '{target_type}'")

    # In AWS mode, drop attacks that are in the skip list
    skip_attacks = get_skip_attacks(config)
    if skip_attacks:
        before = len(attacks)
        attacks = [a for a in attacks if a.name not in skip_attacks]
        skipped = before - len(attacks)
        if skipped:
            logger.info(f"AWS mode: skipping {skipped} attack(s): {skip_attacks}")

    # Create client and authenticate based on target type
    base_url = config["target"]["base_url"]
    if target_type == "wordpress":
        wp_cfg = config.get("target", {}).get("wordpress", {})
        client = WordPressClient(base_url, wp_config=wp_cfg)
    else:
        client = RedTeamClient(base_url)

    async with client:
        # Authenticate with appropriate method
        if target_type == "wordpress":
            test_users = config.get("redteam", {}).get("auth", {}).get("test_users", {})
            wp_user = test_users.get("wp_admin", {})
            username = os.environ.get("WP_ADMIN_USER", wp_user.get("username", ""))
            password = os.environ.get("WP_ADMIN_PASS", wp_user.get("password", ""))
            if username and password and not username.startswith("${"):
                if not await client.wp_login(username, password):
                    logger.warning("WordPress admin login failed — running unauthenticated tests only")
            else:
                logger.info("No WordPress credentials configured — running unauthenticated tests only")
        elif target_type == "generic":
            # Generic targets: try auth if credentials provided, otherwise run unauthenticated
            test_users = config.get("redteam", {}).get("auth", {}).get("test_users", {})
            generic_user = test_users.get("generic_admin", {})
            username = generic_user.get("username", "")
            password = generic_user.get("password", "")
            if username and password and not username.startswith("${"):
                login_endpoint = config.get("target", {}).get("generic", {}).get("login_endpoint", "/login")
                login_fields = config.get("target", {}).get("generic", {}).get("login_fields", {})
                u_field = login_fields.get("username_field", "username")
                p_field = login_fields.get("password_field", "password")
                status, body, headers = await client.post(
                    login_endpoint,
                    json_body={u_field: username, p_field: password},
                )
                if status == 200:
                    logger.info("Generic target login successful")
                else:
                    logger.warning(f"Generic target login returned {status} — running unauthenticated")
            else:
                logger.info("No generic credentials configured — running unauthenticated tests")
        else:
            test_user = config["redteam"]["auth"]["test_users"]["system_admin"]
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


def _filter_by_target(attacks: list, target_type: str) -> list:
    """Filter attacks by target type compatibility.

    An attack is included if:
    - target_type is in the attack's target_types, OR
    - "generic" is in the attack's target_types
    """
    filtered = []
    for a in attacks:
        if target_type in a.target_types or "generic" in a.target_types:
            filtered.append(a)
    return filtered


def main():
    args = parse_args()
    asyncio.run(run(args))


if __name__ == "__main__":
    main()
