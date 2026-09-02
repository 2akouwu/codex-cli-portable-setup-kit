#!/usr/bin/env python3
"""Unit tests for Security Boundary Auditor."""

import os
import sys
import unittest
from pathlib import Path

# Add toolkit parent dir to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from boundary_auditor import (
    PathBoundaryAuditor,
    NetworkBoundaryAuditor,
    EnvironmentBoundaryAuditor,
    StateIntegrityAuditor,
    run_full_security_audit,
)


class TestPathBoundaryAuditor(unittest.TestCase):
    """Test filesystem path canonicalization and boundary containment."""

    def setUp(self):
        self.base_dir = Path(__file__).resolve().parent

    def test_safe_relative_path(self):
        res = PathBoundaryAuditor.audit_path(self.base_dir, "test_pe_parser.py")
        self.assertTrue(res["is_safe"])
        self.assertEqual(len(res["findings"]), 0)

    def test_traversal_escape(self):
        res = PathBoundaryAuditor.audit_path(self.base_dir, "../../../../../Windows/System32")
        self.assertFalse(res["is_safe"])
        self.assertTrue(any("escape" in f.lower() for f in res["findings"]))

    def test_reserved_windows_device_names(self):
        for dev in ["NUL", "CON", "PRN", "AUX", "COM1", "LPT1"]:
            res = PathBoundaryAuditor.audit_path(self.base_dir, dev)
            self.assertFalse(res["is_safe"])
            self.assertTrue(any("reserved dos device" in f.lower() for f in res["findings"]))

    def test_nt_device_namespace(self):
        res = PathBoundaryAuditor.audit_path(self.base_dir, r"\\.\PhysicalDrive0")
        self.assertFalse(res["is_safe"])
        self.assertTrue(any("nt device namespace" in f.lower() for f in res["findings"]))

    def test_alternate_data_stream(self):
        res = PathBoundaryAuditor.audit_path(self.base_dir, "safe_file.txt:hidden_stream")
        self.assertFalse(res["is_safe"])
        self.assertTrue(any("alternate data stream" in f.lower() for f in res["findings"]))


class TestNetworkBoundaryAuditor(unittest.TestCase):
    """Test SSRF, cloud metadata, DNS rebinding, and loopback filtering."""

    def test_public_allowed_url(self):
        res = NetworkBoundaryAuditor.audit_url("https://api.openai.com/v1/chat/completions")
        self.assertTrue(res["is_safe"])
        self.assertEqual(len(res["findings"]), 0)

    def test_localhost_blocked(self):
        for host in ["localhost", "127.0.0.1", "0.0.0.0"]:
            res = NetworkBoundaryAuditor.audit_url(f"http://{host}:8000/api")
            self.assertFalse(res["is_safe"])
            self.assertTrue(any("localhost" in f.lower() or "loopback" in f.lower() or "restricted" in f.lower() for f in res["findings"]))

    def test_encoded_ip_formats_blocked(self):
        # Decimal 2130706433 = 127.0.0.1
        res = NetworkBoundaryAuditor.audit_url("http://2130706433/admin")
        self.assertFalse(res["is_safe"])
        self.assertTrue(any("loopback" in f.lower() or "restricted" in f.lower() for f in res["findings"]))

        # Hex 0x7f000001 = 127.0.0.1
        res = NetworkBoundaryAuditor.audit_url("http://0x7f000001/")
        self.assertFalse(res["is_safe"])
        self.assertTrue(any("loopback" in f.lower() or "restricted" in f.lower() for f in res["findings"]))

        # Octal 0177.0.0.1 = 127.0.0.1
        res = NetworkBoundaryAuditor.audit_url("http://0177.0.0.1/")
        self.assertFalse(res["is_safe"])
        self.assertTrue(any("loopback" in f.lower() or "restricted" in f.lower() for f in res["findings"]))

    def test_dns_rebinding_blocked(self):
        res = NetworkBoundaryAuditor.audit_url("http://custom.127.0.0.1.nip.io:8080/")
        self.assertFalse(res["is_safe"])
        self.assertTrue(any("dns rebinding" in f.lower() for f in res["findings"]))

    def test_cloud_metadata_blocked(self):
        res = NetworkBoundaryAuditor.audit_url("http://169.254.169.254/latest/meta-data/")
        self.assertFalse(res["is_safe"])
        self.assertTrue(any("cloud instance metadata" in f.lower() or "restricted" in f.lower() for f in res["findings"]))

    def test_private_rfc1918_blocked(self):
        for priv_ip in ["10.0.0.1", "172.16.5.10", "192.168.1.1"]:
            res = NetworkBoundaryAuditor.audit_url(f"http://{priv_ip}/admin")
            self.assertFalse(res["is_safe"])
            self.assertTrue(any("private" in f.lower() or "restricted" in f.lower() for f in res["findings"]))

    def test_sensitive_internal_ports_blocked(self):
        for port in [22, 2375, 6379, 27017]:
            res = NetworkBoundaryAuditor.audit_url(f"http://example.com:{port}/")
            self.assertFalse(res["is_safe"])
            self.assertTrue(any("sensitive internal service" in f.lower() for f in res["findings"]))

    def test_disallowed_schemes(self):
        for scheme in ["file:///etc/passwd", "gopher://127.0.0.1:6379/_", "dict://127.0.0.1:11211/"]:
            res = NetworkBoundaryAuditor.audit_url(scheme)
            self.assertFalse(res["is_safe"])
            self.assertTrue(any("disallowed url scheme" in f.lower() for f in res["findings"]))


class TestEnvironmentBoundaryAuditor(unittest.TestCase):
    """Test environment secrets redaction and auditing."""

    def test_secret_detection_and_redaction(self):
        env_dict = {
            "HOME": "/home/user",
            "OPENAI_API_KEY": "sk-proj-123456789012345678901234567890",
            "DB_PASSWORD": "SuperSecretPassword123!",
            "GITHUB_TOKEN": "ghp_123456789012345678901234567890123456",
        }
        res = EnvironmentBoundaryAuditor.audit_environment(env_dict)
        self.assertFalse(res["is_safe"])
        self.assertEqual(res["secret_count"], 3)
        self.assertIn("OPENAI_API_KEY", res["leaked_keys"])
        self.assertIn("DB_PASSWORD", res["leaked_keys"])
        self.assertIn("GITHUB_TOKEN", res["leaked_keys"])

        # Check sanitization
        sanitized = res["sanitized_preview"]
        self.assertEqual(sanitized["HOME"], "/home/user")
        self.assertEqual(sanitized["OPENAI_API_KEY"], "[REDACTED_SECRET]")
        self.assertEqual(sanitized["DB_PASSWORD"], "[REDACTED_SECRET]")
        self.assertEqual(sanitized["GITHUB_TOKEN"], "[REDACTED_SECRET]")


class TestStateIntegrityAuditor(unittest.TestCase):
    """Test state serialization and prototype pollution checks."""

    def test_valid_state_json(self):
        valid = {"version": "1.0", "status": "active", "items": [1, 2, 3]}
        res = StateIntegrityAuditor.audit_state_json(valid)
        self.assertTrue(res["is_safe"])
        self.assertEqual(len(res["findings"]), 0)

    def test_prototype_pollution_blocked(self):
        malicious = {"user": "admin", "__proto__": {"isAdmin": True}}
        res = StateIntegrityAuditor.audit_state_json(malicious)
        self.assertFalse(res["is_safe"])
        self.assertTrue(any("prototype pollution" in f.lower() for f in res["findings"]))


class TestFullAudit(unittest.TestCase):
    """Test end-to-end full audit report generation."""

    def test_full_security_audit_run(self):
        report = run_full_security_audit(str(Path(__file__).resolve().parent))
        self.assertEqual(report["status"], "PASS")
        self.assertTrue(report["filesystem_audit"]["traversal_blocked"])
        self.assertTrue(len(report["network_audit"]) > 0)
        self.assertTrue(report["environment_audit"]["sanitized_safe"])


if __name__ == "__main__":
    unittest.main()
