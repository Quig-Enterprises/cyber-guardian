#!/usr/bin/env python3
"""
Cyber-Guardian CLI

Unified command-line interface for red team and blue team operations.
"""

import sys
import argparse
from pathlib import Path


def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(
        description="Cyber-Guardian - Integrated Offensive & Defensive Security",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Red Team
  cyber-guardian redteam --all
  cyber-guardian redteam --category ai
  cyber-guardian redteam --attack ai.jailbreak

  # Blue Team
  cyber-guardian blueteam --daemon
  cyber-guardian blueteam --report compliance

  # Dashboard
  cyber-guardian dashboard
        """
    )

    parser.add_argument(
        "--version",
        action="version",
        version="Cyber-Guardian 1.0.0"
    )

    parser.add_argument(
        "--config",
        default="config.yaml",
        help="Path to config file (default: config.yaml)"
    )

    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # Red Team subcommand
    redteam_parser = subparsers.add_parser("redteam", help="Run red team attacks")
    redteam_parser.add_argument("--all", action="store_true", help="Run all attacks")
    redteam_parser.add_argument("--category", choices=["ai", "api", "web", "compliance", "wordpress", "cve", "malware"], help="Run category")
    redteam_parser.add_argument("--attack", help="Run specific attack (e.g., ai.jailbreak)")
    redteam_parser.add_argument("--target", type=str, default=None, help="Target type(s): app, ai, wordpress, generic (comma-separated)")
    redteam_parser.add_argument("--url", type=str, default=None, metavar="URL", help="Target base URL (overrides config.yaml)")
    redteam_parser.add_argument("--profile", choices=["wordpress"], default=None, help="Scan profile (e.g. wordpress)")
    redteam_parser.add_argument("--path", type=str, default=None, metavar="DIR", help="Local source directory for static PHP analysis")
    redteam_parser.add_argument("--origin-ip", type=str, default=None, metavar="IP", help="Connect to this IP directly, bypassing CDN/DNS")
    redteam_parser.add_argument("--wp-user", type=str, default=None, help="WordPress admin username")
    redteam_parser.add_argument("--wp-pass", type=str, default=None, help="WordPress admin password")
    redteam_parser.add_argument("--plugin", type=str, action="append", metavar="SLUG", help="WordPress plugin slug to audit (repeatable)")
    redteam_parser.add_argument("--mode", choices=["full", "aws"], default=None, help="Execution mode")
    redteam_parser.add_argument("--report", choices=["html", "json", "console"], nargs="+", default=["console"], help="Report format(s)")
    redteam_parser.add_argument("--output", type=str, default="reports/", help="Report output directory")
    redteam_parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose logging")
    redteam_parser.add_argument("--list", action="store_true", help="List available attacks")
    redteam_parser.add_argument("--cleanup", action="store_true", help="Clean up test artifacts")
    redteam_parser.add_argument("--no-cleanup", action="store_true", help="Skip cleanup")

    # Blue Team subcommand
    blueteam_parser = subparsers.add_parser("blueteam", help="Run blue team monitoring")
    blueteam_parser.add_argument("--daemon", action="store_true", help="Start monitoring daemon")
    blueteam_parser.add_argument("--report", choices=["compliance", "incidents", "ssp", "poam"], help="Report type")
    blueteam_parser.add_argument("--ssp", action="store_true", help="Generate System Security Plan")
    blueteam_parser.add_argument("--incident", help="Create incident report (UUID)")

    # Dashboard subcommand
    dashboard_parser = subparsers.add_parser("dashboard", help="Launch web dashboard")
    dashboard_parser.add_argument("--host", default="0.0.0.0", help="Dashboard host")
    dashboard_parser.add_argument("--port", type=int, default=8080, help="Dashboard port")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return 0

    # Import command handlers
    if args.command == "redteam":
        from redteam.cli import run_redteam
        return run_redteam(args)
    elif args.command == "blueteam":
        from blueteam.cli import run_blueteam
        return run_blueteam(args)
    elif args.command == "dashboard":
        from cyberguardian.dashboard import run_dashboard
        return run_dashboard(args)
    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    sys.exit(main())
