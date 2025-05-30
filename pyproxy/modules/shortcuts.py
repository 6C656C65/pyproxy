"""
pyproxy.modules.shortcuts.py

This module contains functions and a process to load and manage URL shortcuts.
It loads shortcuts (alias to URL mappings) from a specified file, and provides
a process that listens for requests to resolve an alias to its corresponding URL.

Functions:
- load_shortcuts: Loads URL alias mappings from a file into a dictionary for fast lookup.
- shortcuts_process: The process that listens for alias requests and resolves them to URLs.
"""

import multiprocessing
import time
import sys
import threading


def load_shortcuts(shortcuts_path: str) -> dict:
    """
    Loads URL alias mappings from a file into a dictionary for fast lookup.

    Args:
        shortcuts_path (str): The path to the file containing alias=URL mappings.

    Returns:
        dict: A dictionary mapping aliases to URLs.
    """
    shortcuts = {}

    with open(shortcuts_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if "=" in line:
                alias, url = line.split("=", 1)
                shortcuts[alias.strip()] = url.strip()

    return shortcuts


def shortcuts_process(
    queue: multiprocessing.Queue,
    result_queue: multiprocessing.Queue,
    shortcuts_path: str,
) -> None:
    """
    Process that listens for alias requests and resolves them to URLs.

    Args:
        queue (multiprocessing.Queue): A queue to receive alias for URL resolution.
        result_queue (multiprocessing.Queue): A queue to send back the resolved URL.
        shortcuts_path (str): The path to the file containing alias=URL mappings.
    """
    manager = multiprocessing.Manager()
    shortcuts_data = manager.dict({"shortcuts": load_shortcuts(shortcuts_path)})

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
