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
    parser.add_argument(
        "--filter-mode",
        type=str,
        choices=["local", "http"],
        help="Filter list mode"
    )
    parser.add_argument(
        "--blocked-sites",
        type=str,
        help="Path to the text file containing the list of sites to block"
    )
    parser.add_argument(
        "--blocked-url",
        type=str,
        help="Path to the text file containing the list of URLs to block"
    )
    parser.add_argument(
        "--shortcuts",
        type=str,
        help="Path to the text file containing the list of shortcuts"
    )
    parser.add_argument(
        "--custom-header",
        type=str,
        help="Path to the json file containing the list of custom headers"
    )
    parser.add_argument("--no-logging-access", action="store_true", help="Disable access logging")
    parser.add_argument("--no-logging-block", action="store_true", help="Disable block logging")
    parser.add_argument("--ssl-inspect", action="store_true", help="Enable SSL inspection")
    parser.add_argument("--inspect-ca-cert", type=str, help="Path to the CA certificate")
    parser.add_argument("--inspect-ca-key", type=str, help="Path to the CA key")
    parser.add_argument(
        "--inspect-certs-folder",
        type=str,
        help="Path to the generated certificates folder"
    )
    parser.add_argument(
        "--cancel-inspect",
        type=str,
        help="Path to the text file containing the list of URLs without ssl inspection"
    )

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
    filter_mode = (
        args.filter_mode
        if args.filter_mode
        else config.get('Filtering', 'filter_mode', fallback="local")
    )
    blocked_sites = (
        args.blocked_sites
        if args.blocked_sites
        else config.get('Filtering', 'blocked_sites', fallback="config/blocked_sites.txt")
    )
    blocked_url = (
        args.blocked_url
        if args.blocked_url
        else config.get('Filtering', 'blocked_url', fallback="config/blocked_url.txt")
    )
    shortcuts = (
        args.blocked_url
        if args.blocked_url
        else config.get('Options', 'shortcuts', fallback="config/shortcuts.txt")
    )
    custom_header = (
        args.blocked_url
        if args.blocked_url
        else config.get('Options', 'custom_header', fallback="config/custom_header.json")
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
    inspect_certs_folder = (
        args.inspect_certs_folder
        if args.inspect_certs_folder
        else config.get('Security', 'inspect_certs_folder', fallback="certs/")
    )
    inspect_ca_cert = (
        args.inspect_ca_cert
        if args.inspect_ca_cert
        else config.get('Security', 'inspect_ca_cert', fallback="certs/ca/cert.pem")
    )
    inspect_ca_key = (
        args.inspect_ca_key
        if args.inspect_ca_key
        else config.get('Security', 'inspect_ca_key', fallback="certs/ca/key.pem")
    )
    cancel_inspect = (
        args.inspect_ca_key
        if args.inspect_ca_key
        else config.get('Security', 'cancel_inspect', fallback="config/cancel_inspect.txt")
    )

    proxy = ProxyServer(
        host=host,
        port=port,
        debug=debug,
        access_log=access_log,
        block_log=block_log,
        html_403=html_403,
        no_filter=no_filter,
        filter_mode=filter_mode,
        no_logging_access=no_logging_access,
        no_logging_block=no_logging_block,
        ssl_inspect=ssl_inspect,
        blocked_sites=blocked_sites,
        blocked_url=blocked_url,
        shortcuts=shortcuts,
        custom_header=custom_header,
        inspect_ca_cert=inspect_ca_cert,
        inspect_ca_key=inspect_ca_key,
        inspect_certs_folder=inspect_certs_folder,
        cancel_inspect=cancel_inspect
    )

    proxy.start()
