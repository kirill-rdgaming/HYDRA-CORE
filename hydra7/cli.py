"""
Command-line interface for HYDRA7 mesh network node.
"""

import argparse
import asyncio
import os
import sys
import logging

from hydra7 import __version__
from hydra7.core import HydraNode


def setup_logging(verbose: bool = False):
    """Configure logging based on verbosity level."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s \033[92m[%(levelname)s]\033[0m %(message)s',
        datefmt='%H:%M:%S'
    )


def main():
    """Main entry point for the HYDRA7 CLI."""
    parser = argparse.ArgumentParser(
        prog="hydra7",
        description="HYDRA7 - Secure Mesh Network with DPI Evasion",
        epilog="For more information, visit: https://github.com/kirill-rdgaming/HYDRA-CORE"
    )
    
    parser.add_argument(
        "--version",
        action="version",
        version=f"HYDRA7 v{__version__}"
    )
    
    parser.add_argument(
        "--port",
        type=int,
        metavar="PORT",
        help="Override the default HYDRA port (default: auto-generated from secret)"
    )
    
    parser.add_argument(
        "--secret",
        type=str,
        metavar="SECRET",
        help="Network secret key (or set HYDRA_SECRET env var)"
    )
    
    parser.add_argument(
        "--seeds",
        type=str,
        metavar="SEEDS",
        help="Comma-separated list of seed nodes (IP:PORT) (or set HYDRA_SEEDS env var)"
    )
    
    parser.add_argument(
        "--socks-port",
        type=int,
        default=1080,
        metavar="PORT",
        help="Local SOCKS5 proxy port (default: 1080)"
    )
    
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose logging (DEBUG level)"
    )
    
    args = parser.parse_args()
    
    # Setup logging
    setup_logging(verbose=args.verbose)
    
    # Set environment variables from CLI args if provided
    if args.port:
        os.environ["HYDRA_PORT"] = str(args.port)
    
    if args.secret:
        os.environ["HYDRA_SECRET"] = args.secret
    
    if args.seeds:
        os.environ["HYDRA_SEEDS"] = args.seeds
    
    # Override SOCKS port constant if specified
    if args.socks_port != 1080:
        import hydra7.core
        hydra7.core.SOCKS_PORT = args.socks_port
    
    # Print banner
    print("\033[96m" + "=" * 60 + "\033[0m")
    print(f"\033[96m  HYDRA7 v{__version__} - Secure Mesh Network\033[0m")
    print("\033[96m" + "=" * 60 + "\033[0m")
    print()
    
    # Create and start the node
    try:
        # Check for uvloop on non-Windows systems
        if os.name != 'nt':
            try:
                import uvloop
                uvloop.install()
                logging.info("Using uvloop for improved performance")
            except ImportError:
                logging.debug("uvloop not available, using default event loop")
        else:
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
        
        node = HydraNode()
        asyncio.run(node.start())
    except KeyboardInterrupt:
        print("\n\033[93m[SHUTDOWN] Received interrupt signal\033[0m")
        sys.exit(0)
    except Exception as e:
        logging.error(f"Fatal error: {e}", exc_info=args.verbose)
        sys.exit(1)


if __name__ == "__main__":
    main()
