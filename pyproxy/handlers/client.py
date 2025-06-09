"""
pyproxy.handlers.client.py

This module defines the ProxyHandlers class used by the proxy server to process
HTTP and HTTPS client connections. It handles request forwarding, blocking, shortcut
redirection, custom headers, and optional SSL inspection.
"""

import threading

from pyproxy.handlers.http import HttpHandler
from pyproxy.handlers.https import HttpsHandler


class ProxyHandlers:
    """
    ProxyHandlers manages client connections for a proxy server, handling both HTTP
    and HTTPS requests. It processes request forwarding, blocking, SSL inspection,
    and custom headers based on configuration settings. This class is responsible
    for dispatching the correct handler for HTTP or HTTPS requests and managing
    connection-related operations.
    """

    def __init__(
        self,
        html_403,
        logger_config,
        filter_config,
        ssl_config,
        filter_queue,
        filter_result_queue,
        shortcuts_queue,
        shortcuts_result_queue,
        cancel_inspect_queue,
        cancel_inspect_result_queue,
        custom_header_queue,
        custom_header_result_queue,
        console_logger,
        shortcuts,
        custom_header,
        active_connections,
        proxy_config,
    ):
        self.html_403 = html_403
        self.logger_config = logger_config
        self.filter_config = filter_config
        self.ssl_config = ssl_config
        self.filter_queue = filter_queue
        self.filter_result_queue = filter_result_queue
        self.shortcuts_queue = shortcuts_queue
        self.shortcuts_result_queue = shortcuts_result_queue
        self.cancel_inspect_queue = cancel_inspect_queue
        self.cancel_inspect_result_queue = cancel_inspect_result_queue
        self.custom_header_queue = custom_header_queue
        self.custom_header_result_queue = custom_header_result_queue
        self.console_logger = console_logger
        self.config_shortcuts = shortcuts
        self.config_custom_header = custom_header
        self.proxy_config = proxy_config
        self.active_connections = active_connections

    def _create_handler(self, handler_class, **extra_kwargs):
        """
        Factory to create handler instance with shared common parameters.
        """
        params = dict(
            html_403=self.html_403,
            logger_config=self.logger_config,
            filter_config=self.filter_config,
            filter_queue=self.filter_queue,
            filter_result_queue=self.filter_result_queue,
            shortcuts_queue=self.shortcuts_queue,
            shortcuts_result_queue=self.shortcuts_result_queue,
            custom_header_queue=self.custom_header_queue,
            custom_header_result_queue=self.custom_header_result_queue,
            console_logger=self.console_logger,
            shortcuts=self.config_shortcuts,
            custom_header=self.config_custom_header,
            proxy_config=self.proxy_config,
            active_connections=self.active_connections,
        )
        params.update(extra_kwargs)
        return handler_class(**params)

    def handle_client(self, client_socket):
        """
        Handles an incoming client connection by processing the request and forwarding
        it to the appropriate handler based on whether the request is HTTP or HTTPS.

        Args:
            client_socket (socket): The socket object for the client connection.
        """
        try:
            client_socket.settimeout(10)
            request = client_socket.recv(4096)

            if not request:
                return

            first_line = request.decode(errors="ignore").split("\n")[0]
            if first_line.startswith("CONNECT"):
                https_handler = self._create_handler(
                    HttpsHandler,
                    ssl_config=self.ssl_config,
                    cancel_inspect_queue=self.cancel_inspect_queue,
                    cancel_inspect_result_queue=self.cancel_inspect_result_queue,
                )
                https_handler.handle_https_connection(client_socket, first_line)
            else:
                http_handler = self._create_handler(HttpHandler)
                http_handler.handle_http_request(client_socket, request)
        finally:
            client_socket.close()
            self.active_connections.pop(threading.get_ident(), None)
