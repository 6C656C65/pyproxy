"""
handlers.py

This module defines the ProxyHandlers class used by the proxy server to process
HTTP and HTTPS client connections. It handles request forwarding, blocking, shortcut
redirection, custom headers, and optional SSL inspection.
"""

import socket
import select
import os
import ssl
import threading
from OpenSSL import crypto

# pylint: disable=R0914
class ProxyHandlers:
    """
    ProxyHandlers manages client connections for a proxy server,
    handling both HTTP and HTTPS requests. It processes request forwarding,
    blocking, SSL inspection, and custom headers based on configuration settings.
    """
    def __init__(self, html_403, logger_config, filter_config, ssl_config,
                 filter_queue, filter_result_queue, shortcuts_queue, shortcuts_result_queue,
                 cancel_inspect_queue, cancel_inspect_result_queue, custom_header_queue,
                 custom_header_result_queue, console_logger, shortcuts, custom_header,
                 active_connections):
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
        self.active_connections = active_connections

    def handle_client(self, client_socket):
        """
        Handles an incoming client connection by processing the request.
        
        Args:
            client_socket (socket): The socket object for the client connection.
        """
        request = client_socket.recv(4096)

        if not request:
            self.console_logger.debug("No request received, closing connection.")
            client_socket.close()
            self.active_connections.pop(threading.get_ident(), None)
            return

        first_line = request.decode(errors='ignore').split("\n")[0]

        if first_line.startswith("CONNECT"):
            self.handle_https_connection(client_socket, first_line)
        else:
            self.handle_http_request(client_socket, request)

    def handle_http_request(self, client_socket, request):
        """
        Handles HTTP requests, checks if the URL is blocked,
        and forwards the request to the target server.
        
        Args:
            client_socket (socket): The socket object for the client connection.
            request (bytes): The raw HTTP request sent by the client.
        """
        first_line = request.decode(errors='ignore').split("\n")[0]
        url = first_line.split(" ")[1]

        if self.config_custom_header and os.path.isfile(self.config_custom_header):
            headers = self.extract_headers(request.decode(errors='ignore'))
            self.custom_header_queue.put(url)
            new_headers = self.custom_header_result_queue.get()
            headers.update(new_headers)

        if self.config_shortcuts:
            domain, _ = self.parse_url(url)
            self.shortcuts_queue.put(domain)
            shortcut_url = self.shortcuts_result_queue.get()
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
            result = self.filter_result_queue.get()
            if result[1] == "Blocked":
                if not self.logger_config.no_logging_block:
                    self.logger_config.block_logger.info(
                        "%s - %s - %s",
                        client_socket.getpeername()[0],
                        url,
                        first_line
                    )
                with open(self.html_403, "r", encoding='utf-8') as f:
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
        server_host, _ = self.parse_url(url)
        if not self.logger_config.no_logging_access:
            self.logger_config.access_logger.info(
                "%s - %s - %s",
                client_socket.getpeername()[0],
                f"http://{server_host}",
                first_line
            )

        if self.config_custom_header and os.path.isfile(self.config_custom_header):
            request_lines = request.decode(errors='ignore').split("\r\n")
            request_line = request_lines[0]  # GET / HTTP/1.1

            header_lines = [f"{key}: {value}" for key, value in headers.items()]
            reconstructed_headers = "\r\n".join(header_lines)

            if "\r\n\r\n" in request.decode(errors='ignore'):
                body = request.decode(errors='ignore').split("\r\n\r\n", 1)[1]
            else:
                body = ""

            modified_request = f"{request_line}\r\n{reconstructed_headers}\r\n\r\n{body}".encode()

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
        server_host, server_port = self.parse_url(url)
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
                        self.active_connections[thread_id]["bytes_received"] += len(response)
                    else:
                        break
                except socket.timeout:
                    break
        except (socket.timeout, socket.gaierror, ConnectionRefusedError, OSError) as e:
            self.console_logger.error("Error connecting to the server %s : %s", server_host, e)
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

    def parse_url(self, url):
        """
        Parses the URL to extract the host and port for connecting to the target server.
        
        Args:
            url (str): The URL to be parsed.
        
        Returns:
            tuple: The server host and port.
        """
        http_pos = url.find("//")
        if http_pos != -1:
            url = url[(http_pos + 2):]
        port_pos = url.find(":")
        path_pos = url.find("/")
        if path_pos == -1:
            path_pos = len(url)

        server_host = url[:path_pos] if port_pos == -1 or port_pos > path_pos else url[:port_pos]
        if port_pos == -1 or port_pos > path_pos:
            server_port = 80
        else:
            server_port = int(url[(port_pos + 1):path_pos])

        return server_host, server_port

    def extract_headers(self, request_str):
        """
        Extracts the HTTP headers from a raw HTTP request string.

        Args:
            request_str (str): The full HTTP request as a decoded string.

        Returns:
            dict: A dictionary containing the HTTP header fields as key-value pairs.
        """
        headers = {}
        lines = request_str.split("\n")[1:]
        for line in lines:
            if line.strip():
                key, value = line.split(":", 1)
                headers[key.strip()] = value.strip()
        return headers

    # pylint: disable=too-many-locals,too-many-statements,too-many-branches,too-many-nested-blocks
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
            result = self.filter_result_queue.get()
            if result[1] == "Blocked":
                if not self.logger_config.no_logging_block:
                    self.logger_config.block_logger.info(
                        "%s - %s - %s",
                        client_socket.getpeername()[0],
                        target,
                        first_line
                    )
                with open(self.html_403, "r", encoding='utf-8') as f:
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
        if self.ssl_config.ssl_inspect:
            self.cancel_inspect_queue.put(server_host)
            not_inspect = self.cancel_inspect_result_queue.get()

        if self.ssl_config.ssl_inspect and not not_inspect:
            cert_path, key_path = self.generate_certificate(server_host)
            client_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            client_context.load_cert_chain(certfile=cert_path, keyfile=key_path)
            client_context.options |= (
                ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 |
                ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1
            )
            client_context.load_verify_locations(self.ssl_config.inspect_cert)

            try:
                client_socket.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                ssl_client_socket = client_context.wrap_socket(
                    client_socket,
                    server_side=True,
                    do_handshake_on_connect=False
                )
                ssl_client_socket.do_handshake()

                server_socket = socket.create_connection((server_host, server_port))

                server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                server_context.load_default_certs()

                ssl_server_socket = server_context.wrap_socket(
                    server_socket,
                    server_hostname=server_host,
                    do_handshake_on_connect=True
                )

                try:
                    first_request = ssl_client_socket.recv(4096).decode(errors="ignore")
                    request_line = first_request.split("\r\n")[0]
                    method, path, _ = request_line.split(" ")

                    full_url = f"https://{server_host}{path}"

                    if not self.filter_config.no_filter:
                        self.filter_queue.put(f"{server_host}{path}")
                        result = self.filter_result_queue.get()
                        if result[1] == "Blocked":
                            if not self.logger_config.no_logging_block:
                                self.logger_config.block_logger.info(
                                    "%s - %s - %s",
                                    ssl_client_socket.getpeername()[0],
                                    target,
                                    first_line
                                )
                            with open(self.html_403, "r", encoding='utf-8') as f:
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
                            full_url
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
                        first_line
                    )
                self.transfer_data_between_sockets(client_socket, server_socket)
            except (socket.timeout, socket.gaierror, ConnectionRefusedError, OSError) as e:
                self.console_logger.error("Error connecting to the server %s: %s", server_host, e)
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
            thread_id in self.active_connections and
            "target_ip" not in self.active_connections[thread_id]
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
                        self.active_connections[thread_id]["bytes_received"] += len(data)
        except (socket.error, OSError):
            client_socket.close()
            server_socket.close()
            self.active_connections.pop(threading.get_ident(), None)

    def generate_certificate(self, domain):
        """
        Generates a self-signed SSL certificate for the given domain.

        Args:
            domain (str): The domain name for which the certificate is generated.

        Returns:
            tuple: Paths to the generated certificate and private key files.
        """
        cert_path = f"{self.ssl_config.inspect_certs_folder}{domain}.pem"
        key_path = f"{self.ssl_config.inspect_certs_folder}{domain}.key"

        if not os.path.exists(cert_path):
            key = crypto.PKey()
            key.generate_key(crypto.TYPE_RSA, 2048)

            with open(self.ssl_config.inspect_ca_cert, "r", encoding='utf-8') as f:
                ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, f.read())
            with open(self.ssl_config.inspect_ca_key, "r", encoding='utf-8') as f:
                ca_key = crypto.load_privatekey(crypto.FILETYPE_PEM, f.read())

            cert = crypto.X509()
            cert.set_serial_number(int.from_bytes(os.urandom(16), 'big'))
            cert.get_subject().CN = domain
            cert.gmtime_adj_notBefore(0)
            cert.gmtime_adj_notAfter(365 * 24 * 60 * 60)
            cert.set_issuer(ca_cert.get_subject())
            cert.set_pubkey(key)
            cert.sign(ca_key, 'sha256')

            with open(cert_path, "wb") as f:
                f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
            with open(key_path, "wb") as f:
                f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))

        return cert_path, key_path
