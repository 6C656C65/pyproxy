"""
pyproxy.modules.cancel_inspect.py

This module contains functions and a process to load and monitor cancel inspection entries.
It reads a file containing cancel inspection data and checks whether specific entries exist
in that file. The file is monitored in a background thread for live updates.

Functions:
- load_cancel_inspect: Loads the cancel inspection list from a file into a list.
- cancel_inspect_process: Process that listens for URL-like entries and checks
  if they exist in the cancel inspection list.
"""

import multiprocessing
import time
import sys
import threading


def load_cancel_inspect(cancel_inspect_path: str) -> dict:
    """
    Loads cancel inspection entries from a file into a list.

    Args:
        cancel_inspect_path (str): The path to the file containing the entries.

    Returns:
        list: A list containing each line (entry) from the file.
    """
    cancel_inspect = []

    with open(cancel_inspect_path, "r", encoding="utf-8") as f:
        for line in f:
            cancel_inspect.append(line)

    return cancel_inspect


def cancel_inspect_process(
    queue: multiprocessing.Queue,
    result_queue: multiprocessing.Queue,
    cancel_inspect_path: str,
) -> None:
    """
    Process that monitors the cancel inspection file and checks if received entries exist in it.

    Args:
        queue (multiprocessing.Queue): A queue to receive entries to check.
        result_queue (multiprocessing.Queue): A queue to send back True/False depending on match.
        cancel_inspect_path (str): Path to the file containing cancel inspection entries.
    """
    manager = multiprocessing.Manager()
    cancel_inspect_data = manager.list(load_cancel_inspect(cancel_inspect_path))

    error_event = threading.Event()

    def file_monitor() -> None:
        try:
            while True:
                new_cancel_inspect = load_cancel_inspect(cancel_inspect_path)
                cancel_inspect_data[:] = new_cancel_inspect
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
            if url in cancel_inspect_data:
                result_queue.put(True)
            else:
                result_queue.put(False)

        except KeyboardInterrupt:
            break
