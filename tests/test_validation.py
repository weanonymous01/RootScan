"""Unit tests for target validation, scope boundaries, and anti-SSRF checks."""

import unittest
from app.security.validation import TargetType, validate_target


class TestValidation(unittest.TestCase):
    def test_valid_public_ipv4(self):
        res = validate_target("8.8.8.8", allow_private=False)
        self.assertTrue(res.is_valid)
        self.assertEqual(res.target_type, TargetType.IP_V4)
        self.assertEqual(res.normalized_target, "8.8.8.8")
        self.assertFalse(res.is_private)

    def test_private_ipv4_without_authorization(self):
        res = validate_target("192.168.1.1", allow_private=False)
        self.assertFalse(res.is_valid)
        self.assertTrue(res.is_private)
        self.assertIn("private IP", res.error_message)

    def test_private_ipv4_with_authorization(self):
        res = validate_target("10.0.0.1", allow_private=True)
        self.assertTrue(res.is_valid)
        self.assertTrue(res.is_private)
        self.assertEqual(res.normalized_target, "10.0.0.1")

    def test_loopback_rejection(self):
        res = validate_target("127.0.0.1", allow_private=True)
        self.assertFalse(res.is_valid)
        self.assertTrue(res.is_loopback)
        self.assertIn("Loopback", res.error_message)

    def test_cloud_metadata_rejection(self):
        res = validate_target("169.254.169.254", allow_private=True)
        self.assertFalse(res.is_valid)
        self.assertTrue(res.is_cloud_metadata)
        self.assertIn("metadata", res.error_message.lower())

    def test_url_normalization(self):
        res = validate_target("https://scanme.nmap.org/test/path?q=1")
        self.assertTrue(res.is_valid)
        self.assertEqual(res.target_type, TargetType.DOMAIN)
        self.assertEqual(res.normalized_target, "scanme.nmap.org")

    def test_invalid_target_rejection(self):
        res = validate_target("!not_a_valid_host!@@#")
        self.assertFalse(res.is_valid)
        self.assertEqual(res.target_type, TargetType.INVALID)


if __name__ == "__main__":
    unittest.main()

