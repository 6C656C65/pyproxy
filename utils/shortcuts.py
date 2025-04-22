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
import requests

def load_shortcuts(shortcuts_path: str) -> dict:
    """
    Loads blocked FQDNs or URLs from a file or URL into a set for fast lookup.
    
    Args:
        blocked_sites_path (str): The path or URL to the file containing blocked FQDNs.
        blocked_url_path (str): The path or URL to the file containing blocked URLs.
        filter_mode (str): Mode to determine if we load from local file or HTTP URL.
    
    Returns:
        set: A set of blocked domains/URLs.
    """
    shortcuts = {}

    with open(shortcuts_path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if "=" in line:
                alias, url = line.split("=", 1) 
                shortcuts[alias.strip()] = url.strip()

    return shortcuts

# pylint: disable=too-many-locals
def shortcuts_process(
    queue: multiprocessing.Queue,
    result_queue: multiprocessing.Queue,
    shortcuts_path: str
) -> None:
    """
    Process that listens for requests and checks if the domain/URL should be blocked.
    
    Args:
        queue (multiprocessing.Queue): A queue to receive URL/domain for checking.
        result_queue (multiprocessing.Queue): A queue to send back the result of
                the filtering (blocked or allowed).
        filter_mode (str): Filter list mode (local or http).
        blocked_sites_path (str): The path to the file containing blocked FQDNs.
        blocked_url_path (str): The path to the file containing blocked URLs.
    """
    manager = multiprocessing.Manager()
    shortcuts_data = manager.dict({
        "shortcuts": load_shortcuts(shortcuts_path)
    })

    error_event = threading.Event()

    def file_monitor() -> None:
        try:
            while True:
                new_shortcuts = load_shortcuts(shortcuts_path)

                shortcuts_data["shortcuts"] = new_shortcuts

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
            alias = queue.get()
            url = shortcuts_data["shortcuts"].get(alias)
            result_queue.put(url)

        except KeyboardInterrupt:
            break
