"""
This script implements a lightweight and fast Python-based proxy server.
It listens for client requests, filters URLs based on a list, and allows or blocks access 
to those URLs. The proxy can handle both HTTP and HTTPS requests, and logs access and block events.
"""

import argparse
from rich_argparse import MetavarTypeRichHelpFormatter

from utils.proxy import ProxyServer
from utils.config import load_config
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
    parser.add_argument("-H", "--host", type=str, help="IP address to listen on")
    parser.add_argument("-P", "--port", type=int, help="Port to listen on")
    parser.add_argument(
        "-f",
        "--config-file",
        type=str,
        default="./config.ini",
        help="Path to config.ini file"
    )
    parser.add_argument(
        "--access-log",
        type=str,
        help="Path to the access log file"
    )
    parser.add_argument(
        "--block-log",
        type=str,
        help="Path to the block log file"
    )
    parser.add_argument(
        "--html-403",
        type=str,
        help="Path to the custom 403 Forbidden HTML page"
    )
    parser.add_argument("--no-filter", action="store_true", help="Disable URL and domain filtering")
    parser.add_argument("--no-logging-access", action="store_true", help="Disable access logging")
    parser.add_argument("--no-logging-block", action="store_true", help="Disable block logging")
    parser.add_argument("--ssl-inspect", action="store_true", help="Enable SSL inspection")

    args = parser.parse_args()

    config = load_config(args.config_file)

    host = args.host if args.host else config.get('Server', 'host', fallback="0.0.0.0")
    port = args.port if args.port else config.getint('Server', 'port', fallback=8080)
    debug = args.debug if args.debug else config.getboolean('Logging', 'debug', fallback=False)
    access_log = (
        args.access_log
        if args.access_log
        else config.get('Logging', 'access_log', fallback="logs/access.log")
    )
    block_log = (
        args.block_log
        if args.block_log
        else config.get('Logging', 'block_log', fallback="logs/block.log")
    )

    html_403 = (
        args.html_403
        if args.html_403
        else config.get('Files', 'html_403', fallback="assets/403.html")
    )

    no_filter = (
        args.no_filter
        if args.no_filter
        else config.getboolean('Filtering', 'no_filter', fallback=False)
    )

    no_logging_access = (
        args.no_logging_access
        if args.no_logging_access
        else config.getboolean('Logging', 'no_logging_access', fallback=False)
    )

    no_logging_block = (
        args.no_logging_block
        if args.no_logging_block
        else config.getboolean('Logging', 'no_logging_block', fallback=False)
    )

    ssl_inspect = (
        args.ssl_inspect
        if args.ssl_inspect
        else config.getboolean('Security', 'ssl_inspect', fallback=False)
    )

    proxy = ProxyServer(
        host=host,
        port=port,
        debug=debug,
        access_log=access_log,
        block_log=block_log,
        html_403=html_403,
        no_filter=no_filter,
        no_logging_access=no_logging_access,
        no_logging_block=no_logging_block,
        ssl_inspect=ssl_inspect,
        blocked_sites="config/blocked_sites.txt",
        blocked_url="config/blocked_url.txt",
        inspect_ca_cert="certs/ca/cert.pem",
        inspect_ca_key="certs/ca/key.pem"
    )

    proxy.start()
