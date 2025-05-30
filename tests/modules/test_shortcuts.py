"""
test_shortcuts.py

This module contains unit tests for the `shortcuts.py` module.
It verifies the correct functionality of loading shortcuts and resolving aliases.

Tested Functions:
- load_shortcuts: Ensures that the shortcut file is correctly loaded
                and the alias-URL mappings are correct.
- shortcuts_process: Ensures that alias requests are correctly processed
                and resolved to their corresponding URLs.

Test Cases:
- TestLoadShortcuts: Checks the correct loading of alias-URL mappings from the file.
- TestShortcutsProcess: Verifies that alias requests are correctly resolved to URLs.
- TestLoadShortcutsFileNotFound: Verifies that a FileNotFoundError is raised
                when the shortcuts file is missing.
- TestShortcutsProcessWithAliasRequest: Verifies that the process correctly
                resolves alias requests to URLs.
- TestShortcutsProcessFileMonitor: Verifies that the file monitor thread correctly
                updates the shortcuts when the file is changed.
"""

import unittest
import multiprocessing
from unittest.mock import patch, mock_open
from pyproxy.modules.shortcuts import load_shortcuts, shortcuts_process


class TestShortcuts(unittest.TestCase):
    """
    Test suite for the shortcuts module.
    """

    def setUp(self):
        """Sets up the common resources for tests."""
        self.queue = multiprocessing.Queue()
        self.result_queue = multiprocessing.Queue()

    def tearDown(self):
        """Cleans up after each test."""
        while not self.queue.empty():
            self.queue.get_nowait()
        while not self.result_queue.empty():
            self.result_queue.get_nowait()

    def test_load_shortcuts(self):
        """Tests if the shortcuts are correctly loaded from the file."""
        with patch(
            "builtins.open",
            new_callable=mock_open,
            read_data="alias1=http://example.com\nalias2=http://test.com",
        ):
            shortcuts = load_shortcuts("shortcuts.txt")
            self.assertEqual(shortcuts["alias1"], "http://example.com")
            self.assertEqual(shortcuts["alias2"], "http://test.com")
            self.assertIsInstance(shortcuts, dict)

    @patch("builtins.open", side_effect=FileNotFoundError("File not found"))
    def test_load_shortcuts_file_not_found(self, _mock_file):
        """Tests that a FileNotFoundError is raised when the shortcuts file is missing."""
        with self.assertRaises(FileNotFoundError):
            load_shortcuts("invalid_file.txt")

    def _test_shortcuts_process_helper(
        self, alias, expected_url, patch_data="alias1=http://example.com"
    ):
        """Helper method to test shortcuts_process with different alias requests."""
        with patch("builtins.open", new_callable=mock_open, read_data=patch_data):
            process = multiprocessing.Process(
                target=shortcuts_process,
                args=(self.queue, self.result_queue, "shortcuts.txt"),
            )
            process.start()

            self.queue.put(alias)

            result = self.result_queue.get(timeout=2)
            self.assertEqual(result, expected_url)

            process.terminate()
            process.join()

    def test_shortcuts_process(self):
        """Tests if alias requests are correctly resolved to URLs."""
        self._test_shortcuts_process_helper("alias1", "http://example.com")

    def test_shortcuts_process_invalid_alias(self):
        """Tests if an invalid alias returns None."""
        self._test_shortcuts_process_helper("invalid_alias", None)

    def test_shortcuts_process_with_multiple_aliases(self):
        """Tests if multiple alias requests are correctly resolved."""
        with patch(
            "builtins.open",
            new_callable=mock_open,
            read_data="alias1=http://example.com\nalias2=http://test.com",
        ):
            process = multiprocessing.Process(
                target=shortcuts_process,
                args=(self.queue, self.result_queue, "shortcuts.txt"),
            )
            process.start()

            self.queue.put("alias1")
            self.queue.put("alias2")

            result1 = self.result_queue.get(timeout=2)
            result2 = self.result_queue.get(timeout=2)

            self.assertEqual(result1, "http://example.com")
            self.assertEqual(result2, "http://test.com")

            process.terminate()
            process.join()


if __name__ == "__main__":
    unittest.main()
