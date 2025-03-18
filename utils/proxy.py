"""
proxy.py

This module implements a simple Python-based proxy server that handles both HTTP and HTTPS requests.
It forwards requests to the target server, checks URLs against a blocklist,
and serves custom 403 pages for blocked sites. The server also logs access and blocked 
requests to specified log files.

Classes:
- ProxyServer: A class that defines the proxy server. It listens for incoming connections,
processes requests, forwards them to the target server, and logs events.
"""

import socket
import select
import threading
import logging
import multiprocessing
import os
import ssl
from OpenSSL import crypto

from utils.filter import filter_process
from utils.logger import configure_file_logger, configure_console_logger

class ProxyServer:
    """
    A simple Python-based proxy server that handles HTTP and HTTPS requests. 
    It forwards requests to the target server, filters URLs, and blocks access to 
    certain sites based on a configured list.
    The server logs access and blocked requests to specified log files.
    """
    def __init__(self, host, port, debug, access_log, block_log,
                 html_403, no_filter, no_logging_access, no_logging_block, ssl_inspect,
                 blocked_sites, blocked_url, inspect_ca_cert, inspect_ca_key):
        """
        Initializes the ProxyServer instance with the provided configurations.
        """
        self.host_port = (host, port)
        self.debug = debug
        self.html_403 = html_403
        self.no_filter = no_filter
        self.no_logging_access = no_logging_access
        self.no_logging_block = no_logging_block
        self.ssl_inspect = ssl_inspect
        self.filter_proc = None
        self.queue = multiprocessing.Queue()
        self.result_queue = multiprocessing.Queue()
        self.console_logger = configure_console_logger()
        self.config_blocked_sites = blocked_sites
        self.config_blocked_url = blocked_url
        self.config_inspect_cert = inspect_ca_cert
        self.config_inspect_key = inspect_ca_key
        if not self.no_logging_access:
            self.access_logger = configure_file_logger(access_log, "AccessLogger")
        if not self.no_logging_block:
            self.block_logger = configure_file_logger(block_log, "BlockLogger")

    def start(self):
        """
        Starts the proxy server, initializes the filtering process if enabled,
        and begins listening for incoming client connections.
        It creates a socket server and manages client threads.
        """
        if self.debug:
            self.console_logger.setLevel(logging.DEBUG)
            self.console_logger.debug("Configuration used :")
            self.console_logger.debug("[*] Host, Port = %s", self.host_port)
            self.console_logger.debug("[*] debug = %s", self.debug)
            self.console_logger.debug("[*] html_403 = %s", self.html_403)
            self.console_logger.debug("[*] no_filter = %s", self.no_filter)
            self.console_logger.debug("[*] no_logging_access = %s", self.no_logging_access)
            self.console_logger.debug("[*] no_logging_block = %s", self.no_logging_block)
            self.console_logger.debug("[*] ssl_inspect = %s", self.ssl_inspect)
            self.console_logger.debug("[*] blocked_sites = %s", self.config_blocked_sites)
            self.console_logger.debug("[*] blocked_url = %s", self.config_blocked_url)
            self.console_logger.debug("[*] inspect_ca_cert = %s", self.config_inspect_cert)
            self.console_logger.debug("[*] inspect_ca_key = %s", self.config_inspect_key)
        else:
            self.console_logger.setLevel(logging.INFO)

        if not os.path.exists(self.config_blocked_sites):
            with open(self.config_blocked_sites, "w", encoding='utf-8'):
                pass
        if not os.path.exists(self.config_blocked_url):
            with open(self.config_blocked_url, "w", encoding='utf-8'):
                pass

        if not self.no_filter:
            self.filter_proc = multiprocessing.Process(
                target=filter_process,
                args=(
                    self.queue,
                    self.result_queue,
                    self.config_blocked_sites,
                    self.config_blocked_url
                )
            )
            self.filter_proc.start()

        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(self.host_port)
        server.listen(10)

        self.console_logger.info("Proxy server started on %s...", self.host_port)

        try:
            while True:
                client_socket, addr = server.accept()
                self.console_logger.debug("Connection from %s", addr)
                client_handler = threading.Thread(
                    target=self.handle_client,
                    args=(client_socket,)
                )
                client_handler.start()
        except KeyboardInterrupt:
            self.console_logger.info("Proxy interrupted, shutting down.")

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

        if not self.no_filter:
            self.queue.put(url)
            result = self.result_queue.get()
            if result[1] == "Blocked":
                if not self.no_logging_block:
                    self.block_logger.info(
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
                return
        server_host, _ = self.parse_url(url)
        if not self.no_logging_access:
            self.access_logger.info(
                "%s - %s - %s",
                client_socket.getpeername()[0],
                f"http://{server_host}",
                first_line
            )
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
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.connect((server_host, server_port))
        server_socket.sendall(request)

        while True:
            response = server_socket.recv(4096)
            if len(response) > 0:
                client_socket.send(response)
            else:
                break

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

    # pylint: disable=too-many-locals,too-many-statements
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

        if not self.no_filter:
            self.queue.put(target)
            result = self.result_queue.get()
            if result[1] == "Blocked":
                if not self.no_logging_block:
                    self.block_logger.info(
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
                return

        if self.ssl_inspect:
            cert_path, key_path = self.generate_certificate(server_host)
            client_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            client_context.load_cert_chain(certfile=cert_path, keyfile=key_path)
            client_context.options |= (
                ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 |
                ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1
            )
            client_context.load_verify_locations(self.config_inspect_cert)

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

                    if not self.no_logging_access:
                        self.access_logger.info(
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

        else:
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.connect((server_host, server_port))
            client_socket.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            if not self.no_logging_access:
                self.access_logger.info(
                    "%s - %s - %s",
                    client_socket.getpeername()[0],
                    f"https://{server_host}",
                    first_line
                )
            self.transfer_data_between_sockets(client_socket, server_socket)

    def transfer_data_between_sockets(self, client_socket, server_socket):
        """
        Transfers data between the client socket and server socket.
        
        Args:
            client_socket (socket): The socket object for the client connection.
            server_socket (socket): The socket object for the server connection.
        """
        sockets = [client_socket, server_socket]
        try:
            while True:
                readable, _, _ = select.select(sockets, [], [], 1)
                for sock in readable:
                    data = sock.recv(4096)
                    if len(data) == 0:
                        self.console_logger.debug("Closing connection.")
                        client_socket.close()
                        server_socket.close()
                        return
                    if sock is client_socket:
                        server_socket.sendall(data)
                    else:
                        client_socket.sendall(data)
        except (socket.error, OSError):
            client_socket.close()
            server_socket.close()

    def generate_certificate(self, domain):
        """
        Generates a self-signed SSL certificate for the given domain.

        Args:
            domain (str): The domain name for which the certificate is generated.

        Returns:
            tuple: Paths to the generated certificate and private key files.
        """
        cert_path = f"./certs/{domain}.pem"
        key_path = f"./certs/{domain}.key"

        if not os.path.exists(cert_path):
            key = crypto.PKey()
            key.generate_key(crypto.TYPE_RSA, 2048)

            with open(self.config_inspect_cert, "r", encoding='utf-8') as f:
                ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, f.read())
            with open(self.config_inspect_key, "r", encoding='utf-8') as f:
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
