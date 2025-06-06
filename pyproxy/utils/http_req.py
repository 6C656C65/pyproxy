"""
pyproxy.utils.http_req.py

HTTP request parsing utilities for pyproxy.
"""


def extract_headers(request_str):
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
