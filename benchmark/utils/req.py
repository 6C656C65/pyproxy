"""
Module for sending HTTP GET requests with and without a proxy,
and measuring the request completion time.
"""

import time
import requests


def send_request_without_proxy(url: str) -> float:
    """
    Sends an HTTP GET request to the provided URL without using a proxy,
    and measures the time it takes to complete the request.

    Args:
        url (str): The URL to send the request to.

    Returns:
        float: The time taken to complete the request in seconds.
    """
    start_time = time.time()
    requests.get(url, timeout=10)
    end_time = time.time()
    return end_time - start_time


def send_request_with_proxy(url: str, proxy: str) -> float:
    """
    Sends an HTTP GET request to the provided URL using a proxy,
    and measures the time it takes to complete the request.

    Args:
        url (str): The URL to send the request to.
        proxy (str): The proxy URL to use for the request.

    Returns:
        float: The time taken to complete the request in seconds.
    """
    proxies = {"http": proxy, "https": proxy}
    start_time = time.time()
    requests.get(url, proxies=proxies, timeout=10)
    end_time = time.time()
    return end_time - start_time
