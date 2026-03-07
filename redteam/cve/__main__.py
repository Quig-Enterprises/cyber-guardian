"""Standalone CVE CLI -- run with: python3 -m redteam.cve <command>

Commands:
    sync              Sync all local CVE data sources (KEV, ExploitDB, cvelistV5)
    status            Show data source freshness
    lookup <query>    Look up CVEs for a software+version (e.g. "nginx 1.24.0")
"""

import argparse
import asyncio
import logging
import os
import sys

# Ensure project root is on path
project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from shared import load_config
from redteam.cve.models import CVEQuery
from redteam.cve.sync import CVESyncManager


logger = logging.getLogger("redteam.cve")


def parse_args():
    parser = argparse.ArgumentParser(
        prog="python3 -m redteam.cve",
        description="Cyber-Guardian CVE Lookup Engine -- standalone CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    python3 -m redteam.cve sync
    python3 -m redteam.cve sync --force
    python3 -m redteam.cve status
    python3 -m redteam.cve lookup "nginx 1.24.0"
    python3 -m redteam.cve lookup "wordpress 6.4.1" --ecosystem wordpress-core
    python3 -m redteam.cve lookup "firebase/php-jwt" --version 6.11.1 --ecosystem pypi
    python3 -m redteam.cve lookup "numpy" --version 1.24.0 --min-cvss 7.0
        """,
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable debug logging")
    parser.add_argument("--config", default="redteam/config.yaml", help="Config file path")

    sub = parser.add_subparsers(dest="command", required=True)

    # sync
    sync_parser = sub.add_parser("sync", help="Sync local CVE data sources")
    sync_parser.add_argument("--force", action="store_true", help="Force re-download even if fresh")
    sync_parser.add_argument(
        "--source",
        choices=["kev", "exploitdb", "cvelistv5"],
        help="Sync only a specific source",
    )

    # status
    sub.add_parser("status", help="Show data source freshness")

    # lookup
    lookup_parser = sub.add_parser("lookup", help="Look up CVEs for software+version")
    lookup_parser.add_argument("query", help="Software name (and optionally version), e.g. 'nginx 1.24.0'")
    lookup_parser.add_argument("--version", help="Version (if not included in query string)")
    lookup_parser.add_argument("--ecosystem", default="",
                               help="Ecosystem: wordpress-plugin, wordpress-core, pypi, npm, generic")
    lookup_parser.add_argument("--vendor", default="", help="CPE vendor name")
    lookup_parser.add_argument("--min-cvss", type=float, default=0.0, help="Minimum CVSS score filter")
    lookup_parser.add_argument("--max-results", type=int, default=25, help="Maximum results to show")
    lookup_parser.add_argument("--json", action="store_true", help="Output as JSON")

    return parser.parse_args()


async def cmd_sync(config, args):
    """Sync local CVE data sources."""
    mgr = CVESyncManager(config)
    if args.source:
        method = getattr(mgr, f"sync_{args.source}")
        await method(force=args.force)
    else:
        await mgr.sync_all(force=args.force)
    print("Sync complete.")


def cmd_status(config):
    """Show data source freshness."""
    mgr = CVESyncManager(config)
    freshness = mgr.check_freshness()

    print("\nCVE Data Source Status")
    print("=" * 60)
    for source, info in freshness.items():
        last = info["last_sync"] or "never"
        max_age = info["max_age_hours"]
        stale = info["stale"]
        status_icon = "STALE" if stale else "OK"
        print(f"  {source:<15} {status_icon:<6} last_sync={last}  max_age={max_age}h")
    print()


async def cmd_lookup(config, args):
    """Look up CVEs for a software+version."""
    from redteam.cve.engine import CVEEngine

    # Parse query string: "nginx 1.24.0" -> software="nginx", version="1.24.0"
    parts = args.query.strip().split(maxsplit=1)
    software = parts[0]
    version = args.version or (parts[1] if len(parts) > 1 else "")

    query = CVEQuery(
        software=software,
        version=version,
        ecosystem=args.ecosystem,
        vendor=args.vendor,
        min_cvss=args.min_cvss,
        max_results=args.max_results,
    )

    print(f"\nLooking up CVEs for: {software} {version}")
    if args.ecosystem:
        print(f"  Ecosystem: {args.ecosystem}")
    if args.min_cvss > 0:
        print(f"  Min CVSS: {args.min_cvss}")
    print()

    engine = CVEEngine(config)
    records = await engine.lookup(query)

    if not records:
        print("No CVEs found.")
        return

    if args.json:
        import json
        from dataclasses import asdict
        output = [asdict(r) for r in records]
        print(json.dumps(output, indent=2, default=str))
        return

    # Table output
    print(f"Found {len(records)} CVE(s):\n")
    print(f"{'CVE ID':<20} {'CVSS':>5} {'Risk':>5} {'Severity':<10} {'KEV':>3} {'Exploits':>8} {'Description'}")
    print("-" * 110)

    for r in records:
        cvss = f"{r.cvss_v31_score:.1f}" if r.cvss_v31_score else "  -  "
        risk = f"{r.risk_score:.1f}"
        kev = "YES" if r.in_kev else " - "
        exploits = str(len(r.exploit_refs)) if r.exploit_refs else "  -  "
        desc = r.description[:55] + "..." if len(r.description) > 58 else r.description
        desc = desc.replace("\n", " ")
        print(f"{r.cve_id:<20} {cvss:>5} {risk:>5} {r.severity:<10} {kev:>3} {exploits:>8}  {desc}")

    # Summary
    print()
    kev_count = sum(1 for r in records if r.in_kev)
    exploit_count = sum(1 for r in records if r.exploit_refs)
    critical = sum(1 for r in records if r.severity == "critical")
    high = sum(1 for r in records if r.severity == "high")
    print(f"Summary: {len(records)} CVEs ({critical} critical, {high} high), "
          f"{kev_count} in CISA KEV, {exploit_count} with known exploits")


async def main():
    args = parse_args()

    level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(level=level, format="%(asctime)s [%(name)s] %(levelname)s: %(message)s")

    config = load_config(args.config)

    if args.command == "sync":
        await cmd_sync(config, args)
    elif args.command == "status":
        cmd_status(config)
    elif args.command == "lookup":
        await cmd_lookup(config, args)


if __name__ == "__main__":
    asyncio.run(main())
