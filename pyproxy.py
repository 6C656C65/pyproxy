"""
This script implements a lightweight and fast Python-based proxy server.
It listens for client requests, filters URLs based on a list, and allows or blocks access 
to those URLs. The proxy can handle both HTTP and HTTPS requests, and logs access and block events.
"""

import argparse
from rich_argparse import MetavarTypeRichHelpFormatter

from utils.proxy import ProxyServer
from utils.version import __version__

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Lightweight and fast python web proxy",
        formatter_class=MetavarTypeRichHelpFormatter
    )
    parser.add_argument(
        "-v",
        "--version",
        action='version',
        version=__version__,
        help="Show version"
    )
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    parser.add_argument("-H", "--host", type=str, default="0.0.0.0", help="IP address to listen on")
    parser.add_argument("-P", "--port", type=int, default=8080, help="Port to listen on")
    parser.add_argument(
        "--access-log",
        type=str,
        default="logs/access.log",
        help="Path to the access log file"
    )
    parser.add_argument(
        "--block-log",
        type=str,
        default="logs/block.log",
        help="Path to the block log file"
    )
    parser.add_argument(
        "--html-403",
        type=str,
        default="assets/403.html",
        help="Path to the custom 403 Forbidden HTML page"
    )
    parser.add_argument("--no-filter", action="store_true", help="Disable URL and domain filtering")
    parser.add_argument("--no-logging-access", action="store_true", help="Disable access logging")
    parser.add_argument("--no-logging-block", action="store_true", help="Disable block logging")
    parser.add_argument("--ssl-inspect", action="store_true", help="Enable SSL inspection")

    args = parser.parse_args()

    proxy = ProxyServer(
        host=args.host,
        port=args.port,
        debug=args.debug,
        access_log=args.access_log,
        block_log=args.block_log,
        html_403=args.html_403,
        no_filter=args.no_filter,
        no_logging_access=args.no_logging_access,
        no_logging_block=args.no_logging_block,
        ssl_inspect=args.ssl_inspect,
        blocked_sites="config/blocked_sites.txt",
        blocked_url="config/blocked_url.txt"
    )

    proxy.start()
