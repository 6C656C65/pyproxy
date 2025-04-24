"""
config.py

This module defines configuration classes used by the HTTP/HTTPS proxy.
"""

# pylint: disable=R0903
class ProxyConfigLogger:
    """
    Handles logging configuration for the proxy.
    """
    def __init__(self, access_logger, block_logger, no_logging_access, no_logging_block):
        self.access_logger = access_logger
        self.block_logger = block_logger
        self.no_logging_access = no_logging_access
        self.no_logging_block = no_logging_block

class ProxyConfigFilter:
    """
    Manages filtering configuration for the proxy.
    """
    def __init__(self, no_filter, filter_mode, blocked_sites, blocked_url):
        self.no_filter = no_filter
        self.filter_mode = filter_mode
        self.blocked_sites = blocked_sites
        self.blocked_url = blocked_url

class ProxyConfigSSL:
    """
    Handles SSL/TLS inspection configuration.
    """
    def __init__(self, ssl_inspect, inspect_ca_cert, inspect_ca_key,
                 inspect_certs_folder, cancel_inspect):
        self.ssl_inspect = ssl_inspect
        self.inspect_ca_cert = inspect_ca_cert
        self.inspect_ca_key = inspect_ca_key
        self.inspect_certs_folder = inspect_certs_folder
        self.cancel_inspect = cancel_inspect
