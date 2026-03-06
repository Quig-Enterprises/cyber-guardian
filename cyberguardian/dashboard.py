"""Dashboard launcher for Cyber-Guardian"""

import logging

logger = logging.getLogger("dashboard")


def run_dashboard(args):
    """
    Launch web dashboard for Cyber-Guardian.

    Args:
        args: Parsed argparse Namespace with host and port

    Returns:
        Exit code (0 for success, 1 for failure)
    """
    host = args.host if hasattr(args, 'host') else "0.0.0.0"
    port = args.port if hasattr(args, 'port') else 8080

    logger.info(f"Starting Cyber-Guardian dashboard on {host}:{port}")

    try:
        # Import FastAPI app from blue team (which has the dashboard)
        from blueteam.blueteam.api import app
        import uvicorn

        uvicorn.run(app, host=host, port=port)
        return 0

    except ImportError:
        logger.error("Dashboard module not available")
        logger.info("Install dashboard dependencies: pip install fastapi uvicorn")
        return 1
    except Exception as e:
        logger.error(f"Dashboard failed: {e}", exc_info=True)
        return 1
