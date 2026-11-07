"""Unit tests for SQLite database repository and models."""

import os
from pathlib import Path
import tempfile
import unittest

from app.database.models import FindingRecord, ScanRecord, ServiceRecord
from app.database.repository import DatabaseRepository


class TestDatabase(unittest.TestCase):
    def test_database_lifecycle(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            db_path = Path(tmp_dir) / "test.db"
            repo = DatabaseRepository(db_path)

            # 1. Create Scan
            scan = ScanRecord(
                scan_id="SCN-20261107-TEST1",
                target="example.com",
                target_type="domain",
                profile="quick",
                status="running",
                start_time="2026-11-07T12:00:00"
            )
            repo.create_scan(scan)

            fetched = repo.get_scan("SCN-20261107-TEST1")
            self.assertIsNotNone(fetched)
            self.assertEqual(fetched["target"], "example.com")
            self.assertEqual(fetched["status"], "running")

            # 2. Add Services
            repo.add_service(ServiceRecord(
                scan_id="SCN-20261107-TEST1",
                port=443,
                protocol="tcp",
                state="open",
                service_name="https",
                service_version="nginx 1.18"
            ))
            services = repo.get_services("SCN-20261107-TEST1")
            self.assertEqual(len(services), 1)
            self.assertEqual(services[0]["port"], 443)

            # 3. Add Finding
            repo.add_finding(FindingRecord(
                scan_id="SCN-20261107-TEST1",
                title="TLS Weak Cipher",
                severity="medium",
                confidence="confirmed",
                source_tool="Nuclei",
                cve_id=None
            ))
            findings = repo.get_findings("SCN-20261107-TEST1")
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0]["severity"], "medium")

            # 4. Update Status
            repo.update_scan_status("SCN-20261107-TEST1", status="completed", finding_count=1)
            updated = repo.get_scan("SCN-20261107-TEST1")
            self.assertEqual(updated["status"], "completed")
            self.assertEqual(updated["finding_count"], 1)

            # 5. AI Conversation
            repo.add_ai_message("CONV-1", "SCN-20261107-TEST1", "user", "What is the weak cipher?")
            repo.add_ai_message("CONV-1", "SCN-20261107-TEST1", "assistant", "It is 3DES.")
            messages = repo.get_ai_conversation("SCN-20261107-TEST1")
            self.assertEqual(len(messages), 2)
            self.assertEqual(messages[0]["role"], "user")

            # 6. Delete Scan (cascades)
            deleted = repo.delete_scan("SCN-20261107-TEST1")
            self.assertTrue(deleted)
            self.assertIsNone(repo.get_scan("SCN-20261107-TEST1"))
            self.assertEqual(repo.get_services("SCN-20261107-TEST1"), [])


if __name__ == "__main__":
    unittest.main()

