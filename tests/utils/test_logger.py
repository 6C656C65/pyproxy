"""
tests.utils.test_logger.py

This module contains unit tests for the `logger.py` module.
It verifies the correct configuration of both console and file loggers.
"""

import unittest
import logging
import os
from unittest.mock import patch, MagicMock
from pyproxy.utils.logger import configure_console_logger, configure_file_logger


class TestLogger(unittest.TestCase):
    """
    Test suite for the logger module.
    """

    @patch("sys.stdout")
    def test_configure_console_logger(self, mock_stdout):
        """
        Test that the console logger is correctly configured.

        - Ensures the logger has at least one handler.
        - Checks that the log level is set to INFO.
        - Verifies that the handler is a StreamHandler.
        """
        logger = configure_console_logger()

        self.assertTrue(logger.hasHandlers())
        self.assertEqual(logger.level, logging.INFO)
        handler_types = [type(handler) for handler in logger.handlers]
        self.assertIn(logging.StreamHandler, handler_types)

    @patch("logging.FileHandler")
    def test_configure_file_logger(self, mock_file_handler):
        """
        Test that the file logger is correctly configured.

        - Uses a mock for FileHandler to avoid creating actual files.
        - Ensures the logger has at least one handler.
        - Checks that the log level is set to INFO.
        - Verifies that FileHandler is called with the correct log file path.
        """
        mock_handler_instance = MagicMock()
        mock_file_handler.return_value = mock_handler_instance

        log_path = "logs/test.log"
        logger = configure_file_logger(log_path, "TestLogger")

        self.assertTrue(logger.hasHandlers())
        self.assertEqual(logger.level, logging.INFO)
        mock_file_handler.assert_called_once_with(log_path)

    def tearDown(self):
        """
        Cleanup method executed after each test.

        - Deletes the test log file if it exists.
        """
        log_file = "logs/test.log"
        if os.path.exists(log_file):
            os.remove(log_file)


if __name__ == "__main__":
    unittest.main()
