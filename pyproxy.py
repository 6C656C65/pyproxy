"""
This script implements a lightweight and fast Python-based proxy server.
It listens for client requests, filters URLs based on a list, and allows or blocks access 
to those URLs. The proxy can handle both HTTP and HTTPS requests, and logs access and block events.
"""

import socket
import select
import threading
from datetime import datetime
import argparse
from rich_argparse import MetavarTypeRichHelpFormatter
import logging
import multiprocessing
import os

from utils.filter import filter_process
from utils.logger import configure_file_logger, configure_console_logger

def handle_client(
    client_socket: socket.socket,
    queue: multiprocessing.Queue,
    result_queue: multiprocessing.Queue,
    console_logger: logging.Logger,
    access_logger: logging.Logger,
    block_logger: logging.Logger,
    html_403: str,
    no_filter: bool
) -> None:
    """
    Handles a client connection, processing HTTP and HTTPS requests.
    
    Args:
        client_socket (socket.socket): The client socket.
        queue (multiprocessing.Queue): A queue to send domain/URL for filtering.
        result_queue (multiprocessing.Queue): A queue to receive
                    the filtering result (blocked or allowed).
        console_logger (logging.Logger): Logger to write in standard output.
        access_logger (logging.Logger): Logger to write logs to the file.
        block_logger (logging.Logger): Logger to write block logs to the file.
        html_403 (str): Path to HTML page 403 Forbidden.
        no_filter (bool): Disable URL and domain filtering.
    """
    request = client_socket.recv(4096)

    if not request:
        console_logger.debug(f"No request received, closing connection.")
        client_socket.close()
        return

    try:
        first_line = request.decode().split("\n")[0]
    except Exception as e:
        console_logger.error(f"Failed to parse request: {e}")
        client_socket.close()
        return

    if first_line.startswith("CONNECT"):
        try:
            target = first_line.split(" ")[1]
            server_host, server_port = target.split(":")
            server_port = int(server_port)

            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.connect((server_host, server_port))

            client_socket.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")

            access_logger.info(f"{client_socket.getpeername()[0]} - {server_host} - {first_line}")

            sockets = [client_socket, server_socket]
            while True:
                readable, _, _ = select.select(sockets, [], [], 1)
                for sock in readable:
                    data = sock.recv(4096)
                    if len(data) == 0:
                        console_logger.debug(f"Closing HTTPS tunnel.")
                        client_socket.close()
                        server_socket.close()
                        return
                    if sock is client_socket:
                        server_socket.sendall(data)
                    else:
                        client_socket.sendall(data)
        except Exception as e:
            console_logger.error(f"HTTPS tunnel error: {e}")
        finally:
            client_socket.close()
            server_socket.close()
        return

    try:
        url = first_line.split(" ")[1]
    except Exception as e:
        console_logger.error(f"URL parsing failed: {e}")
        client_socket.close()
        return

    if not no_filter:
        try:
            queue.put(url)
            result = result_queue.get()
            if result[1] == "Blocked":
                block_logger.info(f"{client_socket.getpeername()[0]} - {url} - {first_line}")
                with open(html_403, "r") as f:
                    custom_403_page = f.read()
                response = (
                    f"HTTP/1.1 403 Forbidden\r\n"
                    f"Content-Length: {len(custom_403_page)}\r\n\r\n"
                    f"{custom_403_page}"
                )
                client_socket.sendall(response.encode())
                client_socket.close()
                return
        except Exception as e:
            console_logger.error(f"Filtering domain failed: {e}")
            client_socket.close()
            return

    http_pos = url.find("//")
    if http_pos != -1:
        url = url[(http_pos+2):]
    port_pos = url.find(":")
    path_pos = url.find("/")
    if path_pos == -1:
        path_pos = len(url)

    server_host = ""
    server_port = 80
    if port_pos == -1 or port_pos > path_pos:
        server_host = url[:path_pos]
    else:
        server_host = url[:port_pos]
        server_port = int(url[(port_pos+1):path_pos])

    try:
        access_logger.info(f"{client_socket.getpeername()[0]} - {server_host} - {first_line}")

        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.connect((server_host, server_port))
        server_socket.sendall(request)

        while True:
            response = server_socket.recv(4096)
            if len(response) > 0:
                client_socket.send(response)
            else:
                break
    except Exception as e:
        console_logger.error(f"Connection error: {e}")
    finally:
        client_socket.close()
        server_socket.close()

def start_proxy(
    host: str,
    port: int,
    debug: bool,
    access_log: str,
    block_log: str,
    queue: multiprocessing.Queue,
    result_queue: multiprocessing.Queue,
    html_403: str,
    no_filter: bool
) -> None:
    """
    Starts the proxy server and listens for incoming client connections,
    querying the filter process.
    
    Args:
        host (str): The IP to listen on.
        port (int): The port to listen on.
        debug (bool): Enable debug logging.
        access_log (str): Path to the access log file
        block_log (str): Path to the block log file
        queue (multiprocessing.Queue): A queue to send domain/URL for filtering.
        result_queue (multiprocessing.Queue): A queue to get back result of filtering.
        html_403 (str): Path to HTML page 403 Forbidden.
        no_filter (bool): Disable URL and domain filtering.
    """
    console_logger = configure_console_logger()
    if debug:
        console_logger.setLevel(logging.DEBUG)
    else:
        console_logger.setLevel(logging.INFO)

    access_logger = configure_file_logger(access_log, "AccessLogger")
    block_logger = configure_file_logger(block_log, "BlockLogger")

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((host, port))
    server.listen(10)

    console_logger.info(f"Proxy server started on {host}:{port}...")

    try:
        while True:
            client_socket, addr = server.accept()
            console_logger.debug(f"Connection from {addr}")
            client_handler = threading.Thread(
                target=handle_client,
                args=(
                    client_socket,
                    queue,
                    result_queue,
                    console_logger,
                    access_logger,
                    block_logger,
                    html_403,
                    no_filter
                )
            )
            client_handler.start()
    except KeyboardInterrupt:
        console_logger.info("Proxy interrupted, shutting down.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Lightweight and fast python web proxy", formatter_class=MetavarTypeRichHelpFormatter)
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    parser.add_argument("-H", "--host", type=str, default="0.0.0.0", help="IP to listen on")
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
    parser.add_argument("--html-403", type=str, default="assets/403.html", help="403 Forbidden HTML page")
    parser.add_argument("--no-filter", action="store_true", help="Disable URL and domain filtering")

    args = parser.parse_args()

    if not os.path.exists("config/blocked_sites.txt"):
        open("config/blocked_sites.txt", "w").close()
    if not os.path.exists("config/blocked_url.txt"):
        open("config/blocked_url.txt", "w").close()

    if not args.no_filter:
        queue = multiprocessing.Queue()
        result_queue = multiprocessing.Queue()
        filter_proc = multiprocessing.Process(
            target=filter_process,
            args=(queue, result_queue, "config/blocked_sites.txt", "config/blocked_url.txt")
        )
        filter_proc.start()

    start_proxy(
        args.host,
        args.port,
        args.debug,
        args.access_log,
        args.block_log,
        queue,
        result_queue,
        args.html_403,
        args.no_filter
    )
