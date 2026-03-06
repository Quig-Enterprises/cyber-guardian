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
    redteam_parser.add_argument("--category", choices=["ai", "api", "web"], help="Run category")
    redteam_parser.add_argument("--attack", help="Run specific attack (e.g., ai.jailbreak)")
    redteam_parser.add_argument("--report", choices=["html", "json", "console"], help="Report format")
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
