"""
tests.utils.test_http_req.py

This module contains unit tests for the `http_req.py` module in the `pyproxy.utils` package.
"""

import unittest
from pyproxy.utils.http_req import extract_headers


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


if __name__ == "__main__":
    unittest.main()
