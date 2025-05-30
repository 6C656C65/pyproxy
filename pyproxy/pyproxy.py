"""
This script implements a lightweight and fast Python-based proxy server.
It listens for client requests, filters URLs based on a list, and allows or blocks access
to those URLs. The proxy can handle both HTTP and HTTPS requests, and logs access and block events.
"""

from .server import ProxyServer
from .utils.args import parse_args, load_config, get_config_value, str_to_bool
from .utils.config import ProxyConfigLogger, ProxyConfigFilter, ProxyConfigSSL


def main():
    """
    Main entry point of the proxy server. It parses command-line arguments,
    loads the configuration file, retrieves configuration values, and starts the proxy server.
    """
    args = parse_args()
    config = load_config(args.config_file)

    host = get_config_value(args, config, "host", "Server", "0.0.0.0")  # nosec
    port = int(get_config_value(args, config, "port", "Server", 8080))  # nosec
    debug = get_config_value(args, config, "debug", "Logging", False)
    html_403 = get_config_value(args, config, "html_403", "Files", "assets/403.html")
    shortcuts = get_config_value(
        args, config, "shortcuts", "Options", "config/shortcuts.txt"
    )
    custom_header = get_config_value(
        args, config, "custom_header", "Options", "config/custom_header.json"
    )
    authorized_ips = get_config_value(
        args, config, "authorized_ips", "Options", "config/authorized_ips.txt"
    )
    flask_port = get_config_value(args, config, "flask_port", "Monitoring", 5000)
    flask_pass = get_config_value(args, config, "flask_pass", "Monitoring", "password")
    proxy_enable = get_config_value(args, config, "proxy_enable", "Proxy", False)
    proxy_host = get_config_value(args, config, "proxy_host", "Proxy", "127.0.0.1")
    proxy_port = get_config_value(args, config, "proxy_port", "Proxy", 8081)

    logger_config = ProxyConfigLogger(
        access_log=get_config_value(
            args, config, "access_log", "Logging", "logs/access.log"
        ),
        block_log=get_config_value(
            args, config, "block_log", "Logging", "logs/block.log"
        ),
        no_logging_access=str_to_bool(
            get_config_value(args, config, "no_logging_access", "Logging", False)
        ),
        no_logging_block=str_to_bool(
            get_config_value(args, config, "no_logging_block", "Logging", False)
        ),
    )

    filter_config = ProxyConfigFilter(
        no_filter=str_to_bool(
            get_config_value(args, config, "no_filter", "Filtering", False)
        ),
        filter_mode=get_config_value(args, config, "filter_mode", "Filtering", "local"),
        blocked_sites=get_config_value(
            args, config, "blocked_sites", "Filtering", "config/blocked_sites.txt"
        ),
        blocked_url=get_config_value(
            args, config, "blocked_url", "Filtering", "config/blocked_url.txt"
        ),
    )

    ssl_config = ProxyConfigSSL(
        ssl_inspect=str_to_bool(
            get_config_value(args, config, "ssl_inspect", "Security", False)
        ),
        inspect_ca_cert=get_config_value(
            args, config, "inspect_ca_cert", "Security", "certs/ca/cert.pem"
        ),
        inspect_ca_key=get_config_value(
            args, config, "inspect_ca_key", "Security", "certs/ca/key.pem"
        ),
        inspect_certs_folder=get_config_value(
            args, config, "inspect_certs_folder", "Security", "certs/"
        ),
        cancel_inspect=get_config_value(
            args, config, "cancel_inspect", "Security", "config/cancel_inspect.txt"
        ),
    )

    proxy = ProxyServer(
        host=host,
        port=port,
        debug=str_to_bool(debug),
        logger_config=logger_config,
        filter_config=filter_config,
        ssl_config=ssl_config,
        flask_port=flask_port,
        flask_pass=flask_pass,
        html_403=html_403,
        shortcuts=shortcuts,
        custom_header=custom_header,
        authorized_ips=authorized_ips,
        proxy_enable=str_to_bool(proxy_enable),
        proxy_host=proxy_host,
        proxy_port=proxy_port,
    )

    proxy.start()


if __name__ == "__main__":
    main()
