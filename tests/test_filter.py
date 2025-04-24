"""
test_filter.py

This module contains unit tests for the `filter.py` module.
It verifies the correct functionality of loading blacklists and filtering domains/URLs.

Tested Functions:
- load_blacklist: Ensures that the blacklist is correctly loaded from the file.
- filter_process: Ensures that domains/URLs are correctly filtered based on the blacklist.

Test Cases:
- TestLoadBlacklist: Checks the correct loading of blocked sites and URLs from the file.
- TestFilterProcess: Verifies that domains/URLs are correctly identified as blocked or allowed.
"""

import unittest
import multiprocessing
import time
from unittest.mock import patch, mock_open
from utils.proxy.filter import load_blacklist, filter_process

class TestFilter(unittest.TestCase):
    """
    Test suite for the filter module.
    """

    # pylint: disable=unused-argument
    @patch("builtins.open", new_callable=mock_open, read_data="blocked.com\nallowed.com/blocked")
    def test_load_blacklist(self, mock_file):
        """
        Tests that the load_blacklist function correctly loads blocked domains and URLs.

        - Ensures that the sites and URLs are correctly read and loaded into sets.
        - Verifies that the function handles the file content properly.
        """
        blocked_sites, blocked_urls = load_blacklist(
            "blocked_sites.txt",
            "blocked_urls.txt",
            "local"
        )

        self.assertIn("blocked.com", blocked_sites)
        self.assertIn("allowed.com/blocked", blocked_sites)
        self.assertIsInstance(blocked_sites, set)
        self.assertIsInstance(blocked_urls, set)

    def test_filter_process(self):
        """
        Tests that the filter_process function correctly blocks or allows domains/URLs.

        - Simulates the filtering process for blocked and allowed domains/URLs.
        - Ensures that blocked domains are flagged as blocked and allowed ones as allowed.
        """
        queue = multiprocessing.Queue()
        result_queue = multiprocessing.Queue()

        with patch(
            "builtins.open",
            new_callable=mock_open,
            read_data="blocked.com\nallowed.com/blocked"
        ):
            process = multiprocessing.Process(
                target=filter_process,
                args=(queue, result_queue, "local", "blocked_sites.txt", "blocked_urls.txt")
            )
            process.start()

            time.sleep(1)

            queue.put("http://blocked.com/")
            queue.put("http://allowed.com/")
            queue.put("http://allowed.com/blocked")
            queue.put("http://allowed.com/allowed")

            blocked_result = result_queue.get(timeout=2)
            allowed_result = result_queue.get(timeout=2)
            blocked_url_result = result_queue.get(timeout=2)
            allowed_url_result = result_queue.get(timeout=2)

            self.assertEqual(blocked_result, ("blocked.com", "Blocked"))
            self.assertEqual(allowed_result, ("allowed.com", "Allowed"))
            self.assertEqual(blocked_url_result, ("allowed.com/blocked", "Blocked"))
            self.assertEqual(allowed_url_result, ("allowed.com", "Allowed"))

            process.terminate()
            process.join()

if __name__ == "__main__":
    unittest.main()
