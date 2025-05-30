"""
pyproxy.utils.logger.py

This module contains functions to configure and return loggers for both console and file output.
"""

import logging
import os


def configure_console_logger() -> logging.Logger:
    """
    Configures and returns a logger that outputs log messages to the console.

    Returns:
        logging.Logger: A logger instance that writes logs to the console.
    """
    console_logger = logging.getLogger("ConsoleLogger")
    console_logger.setLevel(logging.INFO)
    console_formatter = logging.Formatter(
        "%(asctime)s - %(message)s", datefmt="%d/%m/%Y %H:%M:%S"
    )
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(console_formatter)
    console_logger.addHandler(console_handler)
    return console_logger


def configure_file_logger(log_path: str, name: str) -> logging.Logger:
    """
    Configures and returns a logger that writes log messages to a specified file.

    Args:
        log_path (str): The path where the log file will be created or appended to.
        name (str): Logger's name.

    Returns:
        logging.Logger: A logger instance that writes to the specified log file.
    """
    os.makedirs(os.path.dirname(log_path), exist_ok=True)
    file_logger = logging.getLogger(name)
    file_logger.setLevel(logging.INFO)
    file_handler = logging.FileHandler(log_path)
    file_handler.setFormatter(logging.Formatter("%(asctime)s - %(message)s"))
    file_logger.addHandler(file_handler)
    return file_logger
