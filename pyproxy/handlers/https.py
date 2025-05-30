"""
pyproxy.handlers.https.py

This class handles HTTPS CONNECT requests, applies filtering rules, supports SSL inspection,
generates certificates dynamically, and logs access and blocked attempts. It can also
relay raw data when SSL inspection is disabled.
"""

import socket
import select
import os
import ssl
import threading

from pyproxy.utils.crypto import generate_certificate


class HttpsHandler:
    """
    Handles HTTPS client connections for a proxy server.

    Supports SSL interception, filtering of targets, and custom logging. This handler
    processes HTTPS `CONNECT` requests and either tunnels them directly to the destination
    or performs SSL interception for inspection and filtering.
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
        proxy_enable,
        proxy_host,
        proxy_port,
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
        self.proxy_enable = proxy_enable
        self.proxy_host = proxy_host
        self.proxy_port = proxy_port
        self.active_connections = active_connections

    def handle_https_connection(self, client_socket, first_line):
        """
        Handles HTTPS connections by establishing a connection with the target server
        and relaying data between the client and server.

        Args:
            client_socket (socket): The socket object for the client connection.
            first_line (str): The first line of the CONNECT request from the client.
        """
        target = first_line.split(" ")[1]
        server_host, server_port = target.split(":")
        server_port = int(server_port)

        if not self.filter_config.no_filter:
            self.filter_queue.put(target)
            result = self.filter_result_queue.get(timeout=5)
            if result[1] == "Blocked":
                if not self.logger_config.no_logging_block:
                    self.logger_config.block_logger.info(
                        "%s - %s - %s",
                        client_socket.getpeername()[0],
                        target,
                        first_line,
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

        not_inspect = False
        if (
            self.ssl_config.ssl_inspect
            and self.ssl_config.cancel_inspect
            and os.path.isfile(self.ssl_config.cancel_inspect)
        ):
            self.cancel_inspect_queue.put(server_host)
            not_inspect = self.cancel_inspect_result_queue.get(timeout=5)

        if self.ssl_config.ssl_inspect and not not_inspect:
            cert_path, key_path = generate_certificate(
                server_host,
                self.ssl_config.inspect_certs_folder,
                self.ssl_config.inspect_ca_cert,
                self.ssl_config.inspect_ca_key,
            )
            client_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            client_context.load_cert_chain(certfile=cert_path, keyfile=key_path)
            client_context.options |= (
                ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 | ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1
            )
            client_context.load_verify_locations(self.ssl_config.inspect_ca_cert)

            try:
                client_socket.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                ssl_client_socket = client_context.wrap_socket(
                    client_socket, server_side=True, do_handshake_on_connect=False
                )
                ssl_client_socket.do_handshake()

                if self.proxy_enable:
                    next_proxy_socket = socket.create_connection(
                        (self.proxy_host, self.proxy_port)
                    )
                    connect_command = (
                        f"CONNECT {server_host}:{server_port} HTTP/1.1\r\n"
                        f"Host: {server_host}:{server_port}\r\n\r\n"
                    )
                    next_proxy_socket.sendall(connect_command.encode())

                    response = b""
                    while b"\r\n\r\n" not in response:
                        chunk = next_proxy_socket.recv(4096)
                        if not chunk:
                            raise ConnectionError("Connection to next proxy failed")
                        response += chunk

                    if b"200 Connection Established" not in response:
                        raise ConnectionRefusedError("Next proxy refused CONNECT")

                    server_socket = next_proxy_socket
                else:
                    server_socket = socket.create_connection((server_host, server_port))

                server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                if self.proxy_enable:
                    server_context.check_hostname = False
                    server_context.verify_mode = ssl.CERT_NONE
                else:
                    server_context.load_default_certs()

                ssl_server_socket = server_context.wrap_socket(
                    server_socket,
                    server_hostname=server_host,
                    do_handshake_on_connect=True,
                )

                try:
                    first_request = ssl_client_socket.recv(4096).decode(errors="ignore")
                    request_line = first_request.split("\r\n")[0]
                    method, path, _ = request_line.split(" ")

                    full_url = f"https://{server_host}{path}"

                    if not self.filter_config.no_filter:
                        self.filter_queue.put(f"{server_host}{path}")
                        result = self.filter_result_queue.get(timeout=5)
                        if result[1] == "Blocked":
                            if not self.logger_config.no_logging_block:
                                self.logger_config.block_logger.info(
                                    "%s - %s - %s",
                                    ssl_client_socket.getpeername()[0],
                                    target,
                                    first_line,
                                )
                            with open(self.html_403, "r", encoding="utf-8") as f:
                                custom_403_page = f.read()
                            response = (
                                f"HTTP/1.1 403 Forbidden\r\n"
                                f"Content-Length: {len(custom_403_page)}\r\n"
                                f"\r\n"
                                f"{custom_403_page}"
                            )
                            ssl_client_socket.sendall(response.encode())
                            ssl_client_socket.close()
                            self.active_connections.pop(threading.get_ident(), None)
                            return

                    if not self.logger_config.no_logging_access:
                        self.logger_config.access_logger.info(
                            "%s - %s - %s %s",
                            ssl_client_socket.getpeername()[0],
                            f"https://{server_host}",
                            method,
                            full_url,
                        )

                    ssl_server_socket.sendall(first_request.encode())

                except ValueError:
                    self.console_logger.error(
                        "Error parsing request: malformed request line."
                    )

                except (socket.error, ssl.SSLError) as e:
                    self.console_logger.error("Network or SSL error : %s", str(e))

                self.transfer_data_between_sockets(ssl_client_socket, ssl_server_socket)

            except ssl.SSLError as e:
                self.console_logger.error("SSL error: %s", str(e))
            except socket.error as e:
                self.console_logger.error("Socket error: %s", str(e))
            finally:
                client_socket.close()
                self.active_connections.pop(threading.get_ident(), None)

        else:
            try:
                server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                server_socket.connect((server_host, server_port))
                client_socket.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                if not self.logger_config.no_logging_access:
                    self.logger_config.access_logger.info(
                        "%s - %s - %s",
                        client_socket.getpeername()[0],
                        f"https://{server_host}",
                        first_line,
                    )
                self.transfer_data_between_sockets(client_socket, server_socket)
            except (
                socket.timeout,
                socket.gaierror,
                ConnectionRefusedError,
                OSError,
            ) as e:
                self.console_logger.error(
                    "Error connecting to the server %s: %s", server_host, e
                )
                response = (
                    f"HTTP/1.1 502 Bad Gateway\r\n"
                    f"Content-Length: {len('Bad Gateway')} \r\n"
                    f"\r\n"
                    f"Bad Gateway"
                )
                client_socket.sendall(response.encode())
                client_socket.close()

    def transfer_data_between_sockets(self, client_socket, server_socket):
        """
        Transfers data between the client socket and server socket.

        Args:
            client_socket (socket): The socket object for the client connection.
            server_socket (socket): The socket object for the server connection.
        """
        sockets = [client_socket, server_socket]
        thread_id = threading.get_ident()

        if (
            thread_id in self.active_connections
            and "target_ip" not in self.active_connections[thread_id]
        ):
            try:
                target_ip, target_port = server_socket.getpeername()
                self.active_connections[thread_id]["target_ip"] = target_ip
                self.active_connections[thread_id]["target_port"] = target_port
            except OSError as e:
                self.console_logger.debug("Could not get peer name: %s", e)

        try:
            while True:
                readable, _, _ = select.select(sockets, [], [], 1)
                for sock in readable:
                    data = sock.recv(4096)
                    if len(data) == 0:
                        self.console_logger.debug("Closing connection.")
                        client_socket.close()
                        server_socket.close()
                        self.active_connections.pop(threading.get_ident(), None)
                        return
                    if sock is client_socket:
                        server_socket.sendall(data)
                        self.active_connections[thread_id]["bytes_sent"] += len(data)
                    else:
                        client_socket.sendall(data)
                        self.active_connections[thread_id]["bytes_received"] += len(
                            data
                        )
        except (socket.error, OSError):
            client_socket.close()
            server_socket.close()
            self.active_connections.pop(threading.get_ident(), None)
