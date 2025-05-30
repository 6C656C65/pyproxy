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


def parse_url(url):
    """
    Parses the URL to extract the host and port for connecting to the target server.

    Args:
        url (str): The URL to be parsed.

    Returns:
        tuple: The server host and port.
    """
    http_pos = url.find("//")
    if http_pos != -1:
        url = url[(http_pos + 2) :]
    port_pos = url.find(":")
    path_pos = url.find("/")
    if path_pos == -1:
        path_pos = len(url)

    server_host = (
        url[:path_pos] if port_pos == -1 or port_pos > path_pos else url[:port_pos]
    )
    if port_pos == -1 or port_pos > path_pos:
        server_port = 80
    else:
        server_port = int(url[(port_pos + 1) : path_pos])

    return server_host, server_port
