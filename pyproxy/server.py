"""
server.py

This module defines a Python-based proxy server capable of handling both HTTP
and HTTPS requests. It forwards client requests to target servers, applies
filtering, serves custom 403 pages for blocked content, and logs access and
block events.
"""

import socket
import threading
import logging
import multiprocessing
import os
import time
import ipaddress

from pyproxy import __slim__
from pyproxy.utils.logger import configure_file_logger, configure_console_logger
from pyproxy.handlers.client import ProxyHandlers
from pyproxy.modules.filter import filter_process
from pyproxy.modules.cancel_inspect import cancel_inspect_process

if not __slim__:
    from pyproxy.modules.shortcuts import shortcuts_process
if not __slim__:
    from pyproxy.modules.custom_header import custom_header_process
if not __slim__:
    from pyproxy.monitoring.web import start_flask_server


class ProxyServer:
    """
    A proxy server that forwards HTTP and HTTPS requests, blocks based on rules,
    injects headers, and logs events.
    """

    _EXCLUDE_DEBUG_KEYS = {
        "filter_proc",
        "filter_queue",
        "filter_result_queue",
        "shortcuts_proc",
        "shortcuts_queue",
        "shortcuts_result_queue",
        "cancel_inspect_proc",
        "cancel_inspect_queue",
        "cancel_inspect_result_queue",
        "custom_header_proc",
        "custom_header_queue",
        "custom_header_result_queue",
        "console_logger",
        "access_logger",
        "block_logger",
        "authorized_ips",
        "active_connections",
    }

    def __init__(
        self,
        host,
        port,
        debug,
        logger_config,
        filter_config,
        html_403,
        ssl_config,
        shortcuts,
        custom_header,
        flask_port,
        flask_pass,
        proxy_enable,
        proxy_host,
        proxy_port,
        authorized_ips,
    ):
        """
        Initialize the ProxyServer with configuration parameters.
        """
        self.host_port = (host, port)
        self.debug = debug
        self.html_403 = html_403
        self.active_connections = {}

        self.logger_config = logger_config
        self.filter_config = filter_config
        self.ssl_config = ssl_config

        # Monitoring
        self.flask_port = flask_port
        self.flask_pass = flask_pass

        # Proxy
        self.proxy_enable = proxy_enable
        self.proxy_host = proxy_host
        self.proxy_port = proxy_port

        # Authorized IPS
        self.authorized_ips = authorized_ips
        self.allowed_subnets = None

        # Process communication queues
        self.filter_proc = None
        self.filter_queue = multiprocessing.Queue()
        self.filter_result_queue = multiprocessing.Queue()
        self.shortcuts_proc = None
        self.shortcuts_queue = multiprocessing.Queue()
        self.shortcuts_result_queue = multiprocessing.Queue()
        self.cancel_inspect_proc = None
        self.cancel_inspect_queue = multiprocessing.Queue()
        self.cancel_inspect_result_queue = multiprocessing.Queue()
        self.custom_header_proc = None
        self.custom_header_queue = multiprocessing.Queue()
        self.custom_header_result_queue = multiprocessing.Queue()

        # Logging
        self.console_logger = configure_console_logger()
        if not self.logger_config.no_logging_access:
            self.logger_config.access_logger = configure_file_logger(
                self.logger_config.access_log, "AccessLogger"
            )
        if not self.logger_config.no_logging_block:
            self.logger_config.block_logger = configure_file_logger(
                self.logger_config.block_log, "BlockLogger"
            )

        # Configuration files
        self.config_shortcuts = shortcuts
        self.config_custom_header = custom_header

    def _initialize_processes(self):
        """
        Initializes and starts multiple processes for various tasks if their
        respective configurations and conditions are met.
        """
        if not self.filter_config.no_filter:
            self.filter_proc = multiprocessing.Process(
                target=filter_process,
                args=(
                    self.filter_queue,
                    self.filter_result_queue,
                    self.filter_config.filter_mode,
                    self.filter_config.blocked_sites,
                    self.filter_config.blocked_url,
                ),
            )
            self.filter_proc.start()
            self.console_logger.debug("[*] Starting the filter process...")

        if (
            not __slim__
            and self.config_shortcuts
            and os.path.isfile(self.config_shortcuts)
        ):
            self.shortcuts_proc = multiprocessing.Process(
                target=shortcuts_process,
                args=(
                    self.shortcuts_queue,
                    self.shortcuts_result_queue,
                    self.config_shortcuts,
                ),
            )
            self.shortcuts_proc.start()
            self.console_logger.debug("[*] Starting the shortcuts process...")

        if self.ssl_config.cancel_inspect and os.path.isfile(
            self.ssl_config.cancel_inspect
        ):
            self.cancel_inspect_proc = multiprocessing.Process(
                target=cancel_inspect_process,
                args=(
                    self.cancel_inspect_queue,
                    self.cancel_inspect_result_queue,
                    self.ssl_config.cancel_inspect,
                ),
            )
            self.cancel_inspect_proc.start()
            self.console_logger.debug("[*] Starting the cancel inspection process...")

        if (
            not __slim__
            and self.config_custom_header
            and os.path.isfile(self.config_custom_header)
        ):
            self.custom_header_proc = multiprocessing.Process(
                target=custom_header_process,
                args=(
                    self.custom_header_queue,
                    self.custom_header_result_queue,
                    self.config_custom_header,
                ),
            )
            self.custom_header_proc.start()
            self.console_logger.debug("[*] Starting the custom header process...")

    def _clean_inspection_folder(self):
        """
        Delete old inspection cert/key files if they exist.
        """
        for file in os.listdir(self.ssl_config.inspect_certs_folder):
            if file.endswith((".key", ".pem")):
                file_path = os.path.join(self.ssl_config.inspect_certs_folder, file)
                try:
                    os.remove(file_path)
                except (FileNotFoundError, PermissionError, OSError) as e:
                    self.console_logger.debug("Error deleting %s: %s", file_path, e)

    def _load_authorized_ips(self):
        """
        Load authorized IPs/subnets from the file.
        """
        self.allowed_subnets = None

        if self.authorized_ips and os.path.isfile(self.authorized_ips):
            with open(self.authorized_ips, "r", encoding="utf-8") as f:
                lines = [line.strip() for line in f if line.strip()]
            try:
                self.allowed_subnets = [
                    ipaddress.ip_network(line, strict=False) for line in lines
                ]
                self.console_logger.debug(
                    "[*] Loaded %d authorized IPs/subnets", len(self.allowed_subnets)
                )
            except ValueError as e:
                self.console_logger.error(
                    "[*] Invalid IP/subnet in %s: %s", self.authorized_ips, e
                )
                self.allowed_subnets = None

    def start(self):
        """
        Start the proxy server and listen for incoming client connections.
        Logs configuration if debug is enabled.
        """
        self.console_logger.setLevel(logging.DEBUG if self.debug else logging.INFO)

        if self.debug:
            self.console_logger.debug("Configuration used:")
            for key in sorted(vars(self)):
                if key not in self._EXCLUDE_DEBUG_KEYS:
                    self.console_logger.debug("[*] %s = %s", key, getattr(self, key))

        if self.ssl_config.ssl_inspect:
            if not self.ssl_config.inspect_ca_cert or not os.path.isfile(
                self.ssl_config.inspect_ca_cert
            ):
                raise FileNotFoundError(
                    f"CA certificate not found: {self.ssl_config.inspect_ca_cert}"
                )
            if not self.ssl_config.inspect_ca_key or not os.path.isfile(
                self.ssl_config.inspect_ca_key
            ):
                raise FileNotFoundError(
                    f"CA key not found: {self.ssl_config.inspect_ca_key}"
                )
            os.makedirs(self.ssl_config.inspect_certs_folder, exist_ok=True)
            self._clean_inspection_folder()

        if self.filter_config.filter_mode == "local":
            for file in [
                self.filter_config.blocked_sites,
                self.filter_config.blocked_url,
            ]:
                if not os.path.exists(file):
                    with open(file, "w", encoding="utf-8"):
                        pass

        self._initialize_processes()
        self._load_authorized_ips()

        if not __slim__:
            flask_thread = threading.Thread(
                target=start_flask_server,
                args=(self, self.flask_port, self.flask_pass, self.debug),
                daemon=True,
            )
            flask_thread.start()
            self.console_logger.debug("[*] Starting the monitoring process...")

        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(self.host_port)
        server.listen(10)
        self.console_logger.info("Proxy server started on %s...", self.host_port)

        try:
            while True:
                client_socket, addr = server.accept()
                client_ip, client_port = addr

                if self.allowed_subnets:
                    ip_obj = ipaddress.ip_address(client_ip)
                    if not any(ip_obj in net for net in self.allowed_subnets):
                        self.console_logger.debug(
                            "Unauthorized IP blocked: %s", client_ip
                        )
                        client_socket.close()
                        continue

                self.console_logger.debug("Connection from %s", addr)
                client = ProxyHandlers(
                    html_403=self.html_403,
                    logger_config=self.logger_config,
                    filter_config=self.filter_config,
                    ssl_config=self.ssl_config,
                    filter_queue=self.filter_queue,
                    filter_result_queue=self.filter_result_queue,
                    shortcuts_queue=self.shortcuts_queue,
                    shortcuts_result_queue=self.shortcuts_result_queue,
                    cancel_inspect_queue=self.cancel_inspect_queue,
                    cancel_inspect_result_queue=self.cancel_inspect_result_queue,
                    custom_header_queue=self.custom_header_queue,
                    custom_header_result_queue=self.custom_header_result_queue,
                    console_logger=self.console_logger,
                    shortcuts=self.config_shortcuts,
                    custom_header=self.config_custom_header,
                    proxy_enable=self.proxy_enable,
                    proxy_host=self.proxy_host,
                    proxy_port=self.proxy_port,
                    active_connections=self.active_connections,
                )
                client_handler = threading.Thread(
                    target=client.handle_client, args=(client_socket,), daemon=True
                )
                client_handler.start()
                client_ip, client_port = addr
                self.active_connections[client_handler.ident] = {
                    "client_ip": client_ip,
                    "client_port": client_port,
                    "start_time": time.time(),
                    "bytes_sent": 0,
                    "bytes_received": 0,
                    "thread_name": client_handler.name,
                }
        except KeyboardInterrupt:
            self.console_logger.info("Proxy interrupted, shutting down.")
