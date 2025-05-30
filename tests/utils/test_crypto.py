"""
tests.utils.test_crypto.py

This module contains unit tests for the `crypto.py` module in the `pyproxy.utils` package.
"""

import unittest
import os
import tempfile
from OpenSSL import crypto
from pyproxy.utils.crypto import generate_certificate


class TestCrypto(unittest.TestCase):
    """
    Test suite for the crypto module.
    """

    def setUp(self):
        """
        Set up a fake CA certificate and private key for testing.
        """
        self.certs_folder = tempfile.mkdtemp()
        self.domain = "example.com"
        self.ca_cert_path = os.path.join(self.certs_folder, "ca_cert.pem")
        self.ca_key_path = os.path.join(self.certs_folder, "ca_key.pem")

        self._generate_fake_ca()

    def _generate_fake_ca(self):
        """
        Generate a fake self-signed CA certificate and key for testing purposes.
        """
        ca_key = crypto.PKey()
        ca_key.generate_key(crypto.TYPE_RSA, 2048)

        ca_cert = crypto.X509()
        ca_cert.set_serial_number(1000)
        ca_cert.get_subject().CN = "Fake CA"
        ca_cert.gmtime_adj_notBefore(0)
        ca_cert.gmtime_adj_notAfter(365 * 24 * 60 * 60)
        ca_cert.set_issuer(ca_cert.get_subject())
        ca_cert.set_pubkey(ca_key)

        ca_cert.sign(ca_key, "sha256")

        with open(self.ca_cert_path, "wb") as cert_file:
            cert_file.write(crypto.dump_certificate(crypto.FILETYPE_PEM, ca_cert))
        with open(self.ca_key_path, "wb") as key_file:
            key_file.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, ca_key))

    def test_generate_certificate(self):
        """
        Test the `generate_certificate` function to ensure it generates a certificate
        and private key file for a given domain.
        """
        if not self.certs_folder.endswith("/"):
            self.certs_folder += "/"
        cert_path, key_path = generate_certificate(
            self.domain, self.certs_folder, self.ca_cert_path, self.ca_key_path
        )

        expected_cert_path = os.path.join(self.certs_folder, f"{self.domain}.pem")
        expected_key_path = os.path.join(self.certs_folder, f"{self.domain}.key")

        self.assertEqual(cert_path, expected_cert_path)
        self.assertEqual(key_path, expected_key_path)

        self.assertTrue(os.path.exists(cert_path))
        self.assertTrue(os.path.exists(key_path))

        with open(cert_path, "rb") as cert_file:
            cert_data = cert_file.read()
            cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert_data)

        with open(key_path, "rb") as key_file:
            key_data = key_file.read()
            key = crypto.load_privatekey(crypto.FILETYPE_PEM, key_data)

        self.assertEqual(
            crypto.dump_publickey(crypto.FILETYPE_PEM, cert.get_pubkey()),
            crypto.dump_publickey(crypto.FILETYPE_PEM, key),
        )

    def tearDown(self):
        """
        Cleanup method executed after each test.

        - Deletes the generated certificate and key files if they exist.
        - Removes the fake CA files.
        """
        cert_path = os.path.join(self.certs_folder, f"{self.domain}.pem")
        key_path = os.path.join(self.certs_folder, f"{self.domain}.key")

        if os.path.exists(cert_path):
            os.remove(cert_path)
        if os.path.exists(key_path):
            os.remove(key_path)

        if os.path.exists(self.ca_cert_path):
            os.remove(self.ca_cert_path)
        if os.path.exists(self.ca_key_path):
            os.remove(self.ca_key_path)

        if os.path.exists(self.certs_folder):
            os.rmdir(self.certs_folder)


if __name__ == "__main__":
    unittest.main()
