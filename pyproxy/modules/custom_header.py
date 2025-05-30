"""
pyproxy.modules.custom_header.py

This module contains functions and a process to load and monitor custom header entries.
It reads a file with custom header data and checks if specific entries exist in it.
The file is monitored in a background thread for live updates.

Functions:
- load_custom_header: Loads custom header entries from a file into a list.
- custom_header_process: Process that listens for header-like entries and checks
  if they exist in the custom header list.
"""

import multiprocessing
import time
import sys
import threading
import json


def load_custom_header(custom_header_path: str) -> dict:
    """
    Loads custom header entries from a file into a list.

    Args:
        custom_header_path (str): The path to the file containing the custom headers.

    Returns:
        dict: A dictionary containing the custom header data loaded from the file.
    """
    with open(custom_header_path, "r", encoding="utf-8") as f:
        return json.load(f)


def custom_header_process(
    queue: multiprocessing.Queue,
    result_queue: multiprocessing.Queue,
    custom_header_path: str,
) -> None:
    """
    Process that monitors the custom header file and checks if received entries exist in it.

    Args:
        queue (multiprocessing.Queue): A queue to receive header-like entries to check.
        result_queue (multiprocessing.Queue): A queue to send back True/False depending on match.
        custom_header_path (str): Path to the file containing custom header entries.
    """
    manager = multiprocessing.Manager()
    custom_header_data = manager.dict(load_custom_header(custom_header_path))

    error_event = threading.Event()

    def file_monitor() -> None:
        try:
            while True:
                new_custom_header = load_custom_header(custom_header_path)
                custom_header_data.clear()
                custom_header_data.update(new_custom_header)
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
            url = queue.get()
            headers = custom_header_data.get(url, {})
            result_queue.put(headers)

        except KeyboardInterrupt:
            break
