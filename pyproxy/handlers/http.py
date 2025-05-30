"""
pyproxy.handlers.http.py

This module defines the HttpHandler class used by the proxy server to process
HTTP client connections. It handles request forwarding, blocking, and custom headers.
"""

import socket
import os
import threading

from pyproxy.utils.http_req import extract_headers, parse_url


class HttpHandler:
    """
    HttpHandler manages client HTTP connections for a proxy server,
    handling request forwarding, filtering, blocking, and custom header modification
    based on configuration settings.
    """

    def __init__(
        self,
        html_403,
        logger_config,
        filter_config,
        filter_queue,
        filter_result_queue,
        shortcuts_queue,
        shortcuts_result_queue,
        custom_header_queue,
        custom_header_result_queue,
        console_logger,
        shortcuts,
        custom_header,
        active_connections,
        proxy_enable,
        proxy_host,
        proxy_port,
    ):
        self.html_403 = html_403
        self.logger_config = logger_config
        self.filter_config = filter_config
        self.filter_queue = filter_queue
        self.filter_result_queue = filter_result_queue
        self.shortcuts_queue = shortcuts_queue
        self.shortcuts_result_queue = shortcuts_result_queue
        self.custom_header_queue = custom_header_queue
        self.custom_header_result_queue = custom_header_result_queue
        self.console_logger = console_logger
        self.config_shortcuts = shortcuts
        self.config_custom_header = custom_header
        self.proxy_enable = proxy_enable
        self.proxy_host = proxy_host
        self.proxy_port = proxy_port
        self.active_connections = active_connections

    def handle_http_request(self, client_socket, request):
        """
        Processes an HTTP request, checks for URL filtering, applies shortcuts,
        and forwards the request to the target server if not blocked.

        Args:
            client_socket (socket): The socket object for the client connection.
            request (bytes): The raw HTTP request sent by the client.
        """
        first_line = request.decode(errors="ignore").split("\n")[0]
        url = first_line.split(" ")[1]

        if self.config_custom_header and os.path.isfile(self.config_custom_header):
            headers = extract_headers(request.decode(errors="ignore"))
            self.custom_header_queue.put(url)
            new_headers = self.custom_header_result_queue.get(timeout=5)
            headers.update(new_headers)

        if self.config_shortcuts and os.path.isfile(self.config_shortcuts):
            domain, _ = parse_url(url)
            self.shortcuts_queue.put(domain)
            shortcut_url = self.shortcuts_result_queue.get(timeout=5)
            if shortcut_url:
                response = (
                    f"HTTP/1.1 302 Found\r\n"
                    f"Location: {shortcut_url}\r\n"
                    f"Content-Length: 0\r\n"
                    "\r\n"
                )

                client_socket.sendall(response.encode())
                client_socket.close()
                self.active_connections.pop(threading.get_ident(), None)
                return

        if not self.filter_config.no_filter:
            self.filter_queue.put(url)
            result = self.filter_result_queue.get(timeout=5)
            if result[1] == "Blocked":
                if not self.logger_config.no_logging_block:
                    self.logger_config.block_logger.info(
                        "%s - %s - %s", client_socket.getpeername()[0], url, first_line
                    )
                with open(self.html_403, "r", encoding="utf-8") as f:
                    custom_403_page = f.read()
                response = (
                    f"HTTP/1.1 403 Forbidden\r\n"
                    f"Content-Length: {len(custom_403_page)}\r\n"
                    f"\r\n"
                    f"{custom_403_page}"
                )
                client_socket.sendall(response.encode())
                client_socket.close()
                self.active_connections.pop(threading.get_ident(), None)
                return
        server_host, _ = parse_url(url)
        if not self.logger_config.no_logging_access:
            self.logger_config.access_logger.info(
                "%s - %s - %s",
                client_socket.getpeername()[0],
                f"http://{server_host}",
                first_line,
            )

        if self.config_custom_header and os.path.isfile(self.config_custom_header):
            request_lines = request.decode(errors="ignore").split("\r\n")
            request_line = request_lines[0]  # GET / HTTP/1.1

            header_lines = [f"{key}: {value}" for key, value in headers.items()]
            reconstructed_headers = "\r\n".join(header_lines)

            if "\r\n\r\n" in request.decode(errors="ignore"):
                body = request.decode(errors="ignore").split("\r\n\r\n", 1)[1]
            else:
                body = ""

            modified_request = (
                f"{request_line}\r\n{reconstructed_headers}\r\n\r\n{body}".encode()
            )

            self.forward_request_to_server(client_socket, modified_request, url)

        else:
            self.forward_request_to_server(client_socket, request, url)

    def forward_request_to_server(self, client_socket, request, url):
        """
        Forwards the HTTP request to the target server and sends the response back to the client.

        Args:
            client_socket (socket): The socket object for the client connection.
            request (bytes): The raw HTTP request sent by the client.
            url (str): The target URL from the HTTP request.
        """
        if self.proxy_enable:
            server_host, server_port = self.proxy_host, self.proxy_port
        else:
            server_host, server_port = parse_url(url)
        thread_id = threading.get_ident()

        if thread_id in self.active_connections:
            self.active_connections[thread_id]["target_ip"] = server_host
            self.active_connections[thread_id]["target_port"] = server_port

        try:
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.connect((server_host, server_port))
            server_socket.sendall(request)
            server_socket.settimeout(5)
            self.active_connections[thread_id]["bytes_sent"] += len(request)

            while True:
                try:
                    response = server_socket.recv(4096)
                    if response:
                        client_socket.send(response)
                        self.active_connections[thread_id]["bytes_received"] += len(
                            response
                        )
                    else:
                        break
                except socket.timeout:
                    break
        except (socket.timeout, socket.gaierror, ConnectionRefusedError, OSError) as e:
            self.console_logger.error(
                "Error connecting to the server %s : %s", server_host, e
            )
            response = (
                f"HTTP/1.1 502 Bad Gateway\r\n"
                f"Content-Length: {len('Bad Gateway')} \r\n"
                "\r\n"
                f"Bad Gateway"
            )
            client_socket.sendall(response.encode())
            client_socket.close()
            self.active_connections.pop(thread_id, None)
        finally:
            client_socket.close()
            server_socket.close()
            self.active_connections.pop(thread_id, None)
