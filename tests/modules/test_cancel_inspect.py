"""
test_cancel_inspection.py

This test module verifies the functionality of the `cancel_inspection.py` module.

Tests:
- test_load_cancel_inspect: Ensures entries are correctly loaded from a test file.
- test_cancel_inspect_process: Validates the multiprocessing behavior of
                checking cancel inspection entries.
"""

import unittest
import tempfile
import os
import multiprocessing
import time

from pyproxy.modules.cancel_inspect import load_cancel_inspect, cancel_inspect_process


class TestCancelInspect(unittest.TestCase):
    """Unit tests for the cancel_inspection.py module."""

    def setUp(self):
        """Set up a temporary file with test data for cancel inspection."""
        self.temp_file = tempfile.NamedTemporaryFile(mode="w+", delete=False)
        self.temp_file.write("http://example.com/1\nhttp://example.com/2\n")
        self.temp_file.close()
        self.path = self.temp_file.name

    def tearDown(self):
        """Remove the temporary file after tests complete."""
        os.unlink(self.path)

    def test_load_cancel_inspect(self):
        """Test that the cancel inspection file is correctly loaded into a list."""
        entries = load_cancel_inspect(self.path)
        self.assertEqual(len(entries), 2)
        self.assertIn("http://example.com/1\n", entries)
        self.assertIn("http://example.com/2\n", entries)

    def test_cancel_inspect_process(self):
        """Test that the cancel inspection process returns the correct match result."""
        queue = multiprocessing.Queue()
        result_queue = multiprocessing.Queue()

        process = multiprocessing.Process(
            target=cancel_inspect_process, args=(queue, result_queue, self.path)
        )
        process.start()

        time.sleep(1)

        queue.put("http://example.com/1\n")
        result = result_queue.get(timeout=3)
        self.assertTrue(result)

        queue.put("http://nonexistent.com/\n")
        result = result_queue.get(timeout=3)
        self.assertFalse(result)

        process.terminate()
        process.join()


if __name__ == "__main__":
    unittest.main()
