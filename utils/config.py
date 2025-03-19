"""
config.py

This module allows you to read the program configuration file and return the values.
"""

import configparser

def load_config(config_path: str) -> configparser.ConfigParser:
    """
    Loads the configuration file and returns the parsed config object.

    Args:
        config_path (str): The path to the configuration file to load.

    Returns:
        configparser.ConfigParser: The parsed configuration object.
    """
    config = configparser.ConfigParser()
    config.read(config_path)
    return config
