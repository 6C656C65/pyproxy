"""
tests.utils.test_http_req.py

This module contains unit tests for the `http_req.py` module in the `pyproxy.utils` package.
"""

import unittest
from pyproxy.utils.http_req import extract_headers, parse_url


class TestHttpReq(unittest.TestCase):
    """
    Test suite for the HTTP request utilities.
    """

    def test_extract_headers(self):
        """
        Test the `extract_headers` function to ensure it correctly parses the headers
        from an HTTP request string.
        """

        request_str = """GET / HTTP/1.1
Host: example.com
User-Agent: Mozilla/5.0
Accept: */*

"""
        expected_headers = {
            "Host": "example.com",
            "User-Agent": "Mozilla/5.0",
            "Accept": "*/*",
        }

        headers = extract_headers(request_str)
        self.assertEqual(headers, expected_headers)

    def test_parse_url(self):
        """
        Test the `parse_url` function to ensure it correctly extracts the host and port
        from a URL.
        """

        url = "http://example.com:8080/path/to/resource"
        expected_host, expected_port = "example.com", 8080
        host, port = parse_url(url)
        self.assertEqual(host, expected_host)
        self.assertEqual(port, expected_port)

        url = "http://example.com/path/to/resource"
        expected_host, expected_port = "example.com", 80
        host, port = parse_url(url)
        self.assertEqual(host, expected_host)
        self.assertEqual(port, expected_port)

        url = "example.com:9090"
        expected_host, expected_port = "example.com", 9090
        host, port = parse_url(url)
        self.assertEqual(host, expected_host)
        self.assertEqual(port, expected_port)

        url = "example.com"
        expected_host, expected_port = "example.com", 80
        host, port = parse_url(url)
        self.assertEqual(host, expected_host)
        self.assertEqual(port, expected_port)


if __name__ == "__main__":
    unittest.main()
