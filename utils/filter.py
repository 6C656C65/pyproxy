"""
filter.py

This module contains functions and a process to filter and block domains and URLs.
It loads blocked domain names and URLs from specified files, then listens for 
incoming requests to check if the domain or URL should be blocked.

Functions:
- load_blacklist: Loads blocked FQDNs and URLs from files into sets for fast lookup.
- filter_process: The process that checks whether a domain or URL is blocked.
"""

import multiprocessing
import time
import sys
import threading

def load_blacklist(blocked_sites_path: str, blocked_url_path: str) -> set:
    """
    Loads blocked FQDNs or URLs from a file into a set for fast lookup.
    
    Args:
        blocked_sites_path (str): The path to the file containing blocked FQDNs.
        blocked_url_path (str): The path to the file containing blocked URLs.
    
    Returns:
        set: A set of blocked domains/URLs.
    """
    blocked_sites = set()
    blocked_url = set()

    with open(blocked_sites_path, 'r', encoding='utf-8') as f:
        for line in f:
            blocked_sites.add(line.strip())
    with open(blocked_url_path, 'r', encoding='utf-8') as f:
        for line in f:
            blocked_url.add(line.strip())

    return blocked_sites, blocked_url

def filter_process(
    queue: multiprocessing.Queue,
    result_queue: multiprocessing.Queue,
    blocked_sites_path: str,
    blocked_url_path: str
) -> None:
    """
    Process that listens for requests and checks if the domain/URL should be blocked.
    
    Args:
        queue (multiprocessing.Queue): A queue to receive URL/domain for checking.
        result_queue (multiprocessing.Queue): A queue to send back the result of
                the filtering (blocked or allowed).
        blocked_sites_path (str): The path to the file containing blocked FQDNs.
        blocked_url_path (str): The path to the file containing blocked URLs.
    """
    manager = multiprocessing.Manager()
    blocked_data = manager.dict({
        "sites": load_blacklist(blocked_sites_path, blocked_url_path)[0],
        "urls": load_blacklist(blocked_sites_path, blocked_url_path)[1],
    })

    error_event = threading.Event()

    def file_monitor() -> None:
        try:
            while True:
                new_blocked_sites, new_blocked_url = load_blacklist(
                    blocked_sites_path,
                    blocked_url_path
                )

                blocked_data["sites"] = new_blocked_sites
                blocked_data["urls"] = new_blocked_url

                time.sleep(5)
        except (IOError, ValueError) as e:
            print(f"File monitor error: {e}")
            error_event.set()

    monitor_thread = threading.Thread(target=file_monitor, daemon=True)
    monitor_thread.start()

    while True:
        if error_event.is_set():
            print("Error detected in file monitor thread, terminating process.")
            sys.exit(1)

        try:
            request = queue.get()

            http_pos = request.find("//")
            if http_pos != -1:
                request = request[(http_pos+2):]
            port_pos = request.find(":")
            path_pos = request.find("/")
            if path_pos == -1:
                path_pos = len(request)

            if port_pos != -1 and port_pos < path_pos:
                server_host = request[:port_pos]
            else:
                server_host = request[:path_pos]
            url_path = request[path_pos:] if path_pos < len(request) else "/"

            if server_host in blocked_data["sites"] or "*" in blocked_data["sites"]:
                result_queue.put((server_host, "Blocked"))
            elif server_host + url_path in blocked_data["urls"]:
                result_queue.put((server_host + url_path, "Blocked"))
            else:
                result_queue.put((server_host, "Allowed"))

        except KeyboardInterrupt:
            break
