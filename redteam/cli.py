"""Red Team CLI handler for Cyber-Guardian"""

import asyncio
import sys
import logging
from pathlib import Path

import os

from shared import load_config
from redteam.client import RedTeamClient
from redteam.wp_client import WordPressClient
from redteam.registry import AttackRegistry
from redteam.scoring import aggregate_scores
from redteam.reporters.console import ConsoleReporter
from redteam.reporters.json_report import JsonReporter
from redteam.reporters.html import HtmlReporter
from redteam.cleanup.db import DatabaseCleaner

logger = logging.getLogger("redteam")


def run_redteam(args):
    """
    Execute red team attacks based on command-line arguments.

    Args:
        args: Parsed argparse Namespace from CLI

    Returns:
        Exit code (0 for success, 1 for failure)
    """
    # Setup logging
    logging.basicConfig(
        level=logging.DEBUG if hasattr(args, 'verbose') and args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    )

    try:
        # Load configuration
        config = load_config(args.config)

        # Handle cleanup-only mode
        if hasattr(args, 'cleanup') and args.cleanup:
            return asyncio.run(cleanup_only(config))

        # Run attacks
        results = asyncio.run(execute_attacks(args, config))

        # Generate reports
        if hasattr(args, 'report') and args.report:
            generate_reports(args.report, results, config)

        # Cleanup if enabled
        if not (hasattr(args, 'no_cleanup') and args.no_cleanup):
            if config.get("redteam", {}).get("cleanup", True):
                asyncio.run(cleanup_only(config))

        return 0

    except Exception as e:
        logger.error(f"Red team execution failed: {e}", exc_info=True)
        return 1


async def execute_attacks(args, config):
    """Execute the selected attacks"""
    registry = AttackRegistry()
    registry.discover()

    # Determine which attacks to run
    if args.all:
        attacks = registry.get_all()
    elif hasattr(args, 'category') and args.category:
        attacks = registry.get_by_category(args.category)
    elif hasattr(args, 'attack') and args.attack:
        attack = registry.get(args.attack)
        attacks = [attack] if attack else []
    else:
        logger.error("No attack selection specified")
        return []

    if not attacks:
        logger.warning("No attacks found matching criteria")
        return []

    # Determine target type
    target = config.get("target", {})
    target_type = getattr(args, "target", None) or target.get("type", "eqmon")
    base_url = target.get("base_url", "")

    # Handle --plugin flag
    if hasattr(args, "plugin") and args.plugin:
        target_type = "wordpress"
        wp_cfg = config.setdefault("target", {}).setdefault("wordpress", {})
        existing = wp_cfg.get("plugins", [])
        for slug in args.plugin:
            if slug not in existing:
                existing.append(slug)
        wp_cfg["plugins"] = existing

    # Filter attacks by target type
    attacks = [
        a for a in attacks
        if target_type in a.target_types or "generic" in a.target_types
    ]
    if not attacks:
        logger.warning(f"No attacks compatible with target type '{target_type}'")
        return []

    # Create appropriate client
    if target_type == "wordpress":
        wp_cfg = target.get("wordpress", {})
        client = WordPressClient(base_url, wp_config=wp_cfg)
    else:
        client = RedTeamClient(base_url)

    async with client:
        # Authenticate based on target type
        if target_type == "wordpress":
            auth = config.get("redteam", {}).get("auth", {})
            test_users = auth.get("test_users", {})
            wp_user = test_users.get("wp_admin", {})
            username = os.environ.get("WP_ADMIN_USER", wp_user.get("username", ""))
            password = os.environ.get("WP_ADMIN_PASS", wp_user.get("password", ""))
            if username and password and not username.startswith("${"):
                await client.wp_login(username, password)
            else:
                logger.info("No WordPress credentials — running unauthenticated tests only")
        else:
            auth = config.get("redteam", {}).get("auth", {})
            test_users = auth.get("test_users", {})
            if test_users:
                user_config = next(iter(test_users.values()))
                username = user_config.get("username")
                password = user_config.get("password")
                if username and password:
                    await client.login(username, password)

        # Run all attacks
        all_results = []
        for attack in attacks:
            logger.info(f"Running attack: {attack.name}")
            attack._config = config
            results = await attack.execute(client)
            all_results.extend(results)

        return all_results


def generate_reports(report_format, results, config):
    """Generate reports in requested formats"""
    output_dir = Path(config.get("redteam", {}).get("reporting", {}).get("output_dir", "reports"))
    output_dir.mkdir(parents=True, exist_ok=True)

    if "console" in report_format or report_format == "console":
        reporter = ConsoleReporter()
        reporter.generate(results)

    if "json" in report_format or report_format == "json":
        reporter = JsonReporter(output_dir / "redteam-results.json")
        reporter.generate(results)

    if "html" in report_format or report_format == "html":
        reporter = HtmlReporter(output_dir / "redteam-report.html")
        reporter.generate(results)


async def cleanup_only(config):
    """Run cleanup only"""
    logger.info("Running cleanup...")

    db_config = config.get("database", {})
    test_users = config.get("redteam", {}).get("auth", {}).get("test_users", {})

    cleaner = DatabaseCleaner(db_config)

    # Get user IDs from test users
    user_ids = []
    for user_config in test_users.values():
        # This would need to query the database to get user_id from username
        # For now, we'll just use the session prefix
        pass

    session_prefix = config.get("redteam", {}).get("test_data", {}).get("session_id_prefix", "redteam-")

    try:
        count = await cleaner.cleanup_by_session_prefix(session_prefix)
        logger.info(f"Cleaned up {count} test artifacts")
        return 0
    except Exception as e:
        logger.error(f"Cleanup failed: {e}")
        return 1
