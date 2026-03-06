"""Blue Team CLI handler for Cyber-Guardian"""

import sys
import logging
from pathlib import Path

from shared import load_config

logger = logging.getLogger("blueteam")


def run_blueteam(args):
    """
    Execute blue team operations based on command-line arguments.

    Args:
        args: Parsed argparse Namespace from CLI

    Returns:
        Exit code (0 for success, 1 for failure)
    """
    # Setup logging
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    )

    try:
        # Load configuration
        config = load_config(args.config)

        # Handle different commands
        if hasattr(args, 'daemon') and args.daemon:
            return run_daemon(config)
        elif hasattr(args, 'report') and args.report:
            return generate_report(args.report, config)
        elif hasattr(args, 'ssp') and args.ssp:
            return generate_ssp(config)
        elif hasattr(args, 'incident') and args.incident:
            return create_incident(args.incident, config)
        else:
            logger.error("No blue team command specified")
            return 1

    except Exception as e:
        logger.error(f"Blue team execution failed: {e}", exc_info=True)
        return 1


def run_daemon(config):
    """Start monitoring daemon"""
    logger.info("Starting blue team monitoring daemon...")

    try:
        # Import and start monitoring
        from blueteam.blueteam.monitor import main as monitor_main
        monitor_main()
        return 0
    except ImportError:
        logger.error("Blue team monitoring module not available")
        return 1
    except Exception as e:
        logger.error(f"Daemon failed: {e}", exc_info=True)
        return 1


def generate_report(report_type, config):
    """Generate compliance or incident report"""
    logger.info(f"Generating {report_type} report...")

    try:
        if report_type == "compliance":
            from blueteam.blueteam.reports.posture import generate_compliance_report
            output = generate_compliance_report(config)
            logger.info(f"Compliance report generated: {output}")

        elif report_type == "incidents":
            from blueteam.blueteam.reports.assessor import generate_incident_summary
            output = generate_incident_summary(config)
            logger.info(f"Incident summary generated: {output}")

        elif report_type == "ssp":
            return generate_ssp(config)

        elif report_type == "poam":
            from blueteam.blueteam.reports.assessor import generate_poam
            output = generate_poam(config)
            logger.info(f"POA&M generated: {output}")

        else:
            logger.error(f"Unknown report type: {report_type}")
            return 1

        return 0

    except ImportError as e:
        logger.error(f"Report module not available: {e}")
        return 1
    except Exception as e:
        logger.error(f"Report generation failed: {e}", exc_info=True)
        return 1


def generate_ssp(config):
    """Generate System Security Plan"""
    logger.info("Generating System Security Plan (SSP)...")

    try:
        from blueteam.blueteam.reports.assessor import generate_ssp as gen_ssp
        output = gen_ssp(config)
        logger.info(f"SSP generated: {output}")
        return 0
    except ImportError:
        logger.error("SSP generation module not available")
        return 1
    except Exception as e:
        logger.error(f"SSP generation failed: {e}", exc_info=True)
        return 1


def create_incident(incident_uuid, config):
    """Create incident report"""
    logger.info(f"Creating incident report for: {incident_uuid}")

    try:
        from blueteam.blueteam.incidents.manager import IncidentManager

        manager = IncidentManager(config)
        incident = manager.get_incident(incident_uuid)

        if not incident:
            logger.error(f"Incident not found: {incident_uuid}")
            return 1

        logger.info(f"Incident details: {incident}")
        return 0

    except ImportError:
        logger.error("Incident management module not available")
        return 1
    except Exception as e:
        logger.error(f"Incident report failed: {e}", exc_info=True)
        return 1
