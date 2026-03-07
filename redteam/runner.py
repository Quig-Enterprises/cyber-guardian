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
from redteam.state import ScanState

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
        choices=["ai", "api", "web", "compliance", "wordpress", "cve", "malware", "infrastructure", "dns", "secrets", "exposure", "cloud"],
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
        type=str,
        default=None,
        help="Target type(s): 'app' (default), 'ai', 'wordpress', or 'generic'. "
             "Comma-separated for multi-target, e.g. 'app,ai'.",
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
        "--url",
        type=str,
        default=None,
        metavar="URL",
        help="Target base URL. Overrides config.yaml target.base_url. "
             "Example: --url http://sandbox.quigs.com",
    )
    parser.add_argument(
        "--profile",
        choices=["wordpress"],
        default=None,
        help="Scan profile: 'wordpress' runs all WordPress-relevant attacks "
             "across categories and sets target type automatically.",
    )
    parser.add_argument(
        "--path",
        type=str,
        default=None,
        metavar="DIR",
        help="Local source directory for static PHP analysis. "
             "Can be combined with --url for static + live scanning.",
    )
    parser.add_argument(
        "--wp-user",
        type=str,
        default=None,
        metavar="USERNAME",
        help="WordPress admin username (overrides config/env at runtime).",
    )
    parser.add_argument(
        "--wp-pass",
        type=str,
        default=None,
        metavar="PASSWORD",
        help="WordPress admin password (overrides config/env at runtime).",
    )
    parser.add_argument(
        "--origin-ip",
        type=str,
        default=None,
        metavar="IP",
        help="Connect directly to this IP instead of resolving the hostname "
             "(bypasses Cloudflare/CDN). Sets Host header to the hostname from base_url.",
    )
    parser.add_argument(
        "--cve-sync",
        action="store_true",
        help="Sync CVE data sources (KEV, ExploitDB, cvelistV5) before running",
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

    # --profile wordpress: set target type and expand categories
    if args.profile == "wordpress":
        args.target = args.target or "wordpress"
        logger.info("Profile: wordpress — targeting wordpress + generic attack categories")

    # --plugin implies --target wordpress and adds slugs to config
    if args.plugin:
        args.target = "wordpress"
        wp_cfg = config.setdefault("target", {}).setdefault("wordpress", {})
        existing = wp_cfg.get("plugins", [])
        for slug in args.plugin:
            if slug not in existing:
                existing.append(slug)
        wp_cfg["plugins"] = existing

    # --url overrides config target.base_url
    if args.url:
        config.setdefault("target", {})["base_url"] = args.url
        logger.info(f"Target URL override: {args.url}")

    # --path enables static source scanning
    if args.path:
        config.setdefault("target", {})["source_path"] = args.path
        logger.info(f"Static source path: {args.path}")

    # --wp-user / --wp-pass override credentials at runtime
    if args.wp_user:
        config.setdefault("auth", {}).setdefault("test_users", {}).setdefault("wp_admin", {})["username"] = args.wp_user
    if args.wp_pass:
        config.setdefault("auth", {}).setdefault("test_users", {}).setdefault("wp_admin", {})["password"] = args.wp_pass

    # --origin-ip: store for client creation below
    if args.origin_ip:
        config.setdefault("target", {})["origin_ip"] = args.origin_ip

    # Determine target type(s) (CLI > config > default)
    target_raw = args.target or config.get("target", {}).get("type", "app")
    # --path without --url or --target adds "static" to target types
    if args.path and not args.url and not args.target:
        target_raw = "static"
    target_types = set(t.strip() for t in target_raw.split(","))
    if args.path:
        target_types.add("static")
    config.setdefault("target", {})["type"] = ",".join(sorted(target_types))
    logger.info(f"Target type(s): {', '.join(sorted(target_types))}")

    # CVE data sync (if requested)
    if getattr(args, 'cve_sync', False):
        try:
            from redteam.cve.sync import CVESyncManager
            logger.info("Syncing CVE data sources...")
            sync_mgr = CVESyncManager(config)
            await sync_mgr.sync_all()
            logger.info("CVE data sync complete")
        except ImportError:
            logger.warning("CVE sync module not available — skipping")
        except Exception as e:
            logger.warning(f"CVE data sync failed (non-fatal): {e}")

    # Discover attacks
    registry = AttackRegistry()
    count = registry.discover()
    logger.info(f"Discovered {count} attack modules")

    # Handle --list
    if args.list:
        all_attacks = registry.get_all()
        if args.target:
            all_attacks = _filter_by_target(all_attacks, target_types)
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
    attacks = _filter_by_target(attacks, target_types)
    if not attacks:
        logger.warning(f"No attacks compatible with target type(s) '{target_raw}'")
        return
    logger.info(f"Running {len(attacks)} attack(s) for target(s) '{target_raw}'")

    # In AWS mode, drop attacks that are in the skip list
    skip_attacks = get_skip_attacks(config)
    if skip_attacks:
        before = len(attacks)
        attacks = [a for a in attacks if a.name not in skip_attacks]
        skipped = before - len(attacks)
        if skipped:
            logger.info(f"AWS mode: skipping {skipped} attack(s): {skip_attacks}")

    # Static-only mode: no HTTP client needed
    if target_types == {"static"}:
        scores = []
        for attack in attacks:
            attack._config = config
            try:
                results = await attack.execute(None)
                score = attack.score(results)
                scores.append(score)
            except Exception as e:
                logger.error(f"  -> Error running {attack.name}: {e}")
        summary = aggregate_scores(scores)
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
        return

    # Create client and authenticate based on target type
    base_url = config["target"]["base_url"]
    origin_ip = config.get("target", {}).get("origin_ip")
    if origin_ip:
        logger.info(f"Origin-direct mode: connecting to {origin_ip} with Host header from {base_url}")
    if "wordpress" in target_types:
        wp_cfg = config.get("target", {}).get("wordpress", {})
        client = WordPressClient(base_url, wp_config=wp_cfg, origin_ip=origin_ip)
    else:
        client = RedTeamClient(base_url, origin_ip=origin_ip)

    async with client:
        # Authenticate with appropriate method
        if "wordpress" in target_types:
            test_users = config.get("redteam", {}).get("auth", {}).get("test_users", {})
            wp_user = test_users.get("wp_admin", {})
            # --wp-user/--wp-pass override env vars, which override config
            cli_user = config.get("auth", {}).get("test_users", {}).get("wp_admin", {})
            username = cli_user.get("username") or os.environ.get("WP_ADMIN_USER", wp_user.get("username", ""))
            password = cli_user.get("password") or os.environ.get("WP_ADMIN_PASS", wp_user.get("password", ""))
            if username and password and not username.startswith("${"):
                if not await client.wp_login(username, password):
                    logger.warning("WordPress admin login failed — running unauthenticated tests only")
            else:
                logger.info("No WordPress credentials configured — running unauthenticated tests only")
        elif "generic" in target_types:
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
        elif "app" in target_types or "ai" in target_types:
            test_user = config["redteam"]["auth"]["test_users"]["system_admin"]
            if not await client.login(test_user["username"], test_user["password"]):
                logger.error("Authentication failed. Have test users been created?")
                sys.exit(1)

        # Run attacks
        suite_start = time.time()
        suite_start_iso = datetime.now().isoformat()
        scores = []

        # Create shared state for cross-attack communication
        scan_state = ScanState()

        for attack in attacks:
            logger.info(f"Running: {attack.name} ({attack.category})")
            attack._config = config  # make execution config available inside attack
            attack._state = scan_state  # pass shared state to attacks
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


def _filter_by_target(attacks: list, target_types: set[str]) -> list:
    """Filter attacks by target type compatibility.

    An attack is included if:
    - ANY of the requested target_types is in the attack's target_types, OR
    - "generic" is in the attack's target_types
    """
    filtered = []
    for a in attacks:
        if target_types & a.target_types or "generic" in a.target_types:
            filtered.append(a)
    return filtered


def main():
    args = parse_args()
    asyncio.run(run(args))


if __name__ == "__main__":
    main()
