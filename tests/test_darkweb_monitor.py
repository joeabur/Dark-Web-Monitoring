import tempfile
import unittest
from email import policy
from email.parser import BytesParser
from pathlib import Path

import darkweb_monitor as monitor


class DarkwebMonitorTests(unittest.TestCase):
    def test_domain_normalization_and_url_rejection(self):
        self.assertEqual(monitor.normalize_domain("Exämple.COM."), "xn--exmple-cua.com")
        for value in ("https://example.com", "example.com/path", "-bad.example"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                monitor.normalize_domain(value)

    def test_parse_findings_rejects_empty_or_unexpected_output(self):
        for output in ("", "SpiderFoot failed", "Name,Value\nx,y\n"):
            with self.subTest(output=output), self.assertRaises(RuntimeError):
                monitor.parse_findings(output)

    def test_find_new_findings_deduplicates_scan_rows_and_ignores_timestamps(self):
        report = (
            "Type,Module,Data,Updated\n"
            "LEAKSITE,sfp_darkweb,example secret,2026-11-17\n"
            "LEAKSITE,sfp_darkweb,example secret,2026-11-18\n"
        )
        rows, _ = monitor.parse_findings(report)

        fresh, fingerprints = monitor.find_new_findings(rows, set())

        self.assertEqual(len(fresh), 1)
        self.assertEqual(len(fingerprints), 1)
        self.assertEqual(monitor.find_new_findings(rows, fingerprints), ([], set()))

    def test_email_attaches_the_full_scan_csv(self):
        report = (
            "Type,Module,Data\n"
            "LEAKSITE,sfp_darkweb,example secret\n"
            "PHISHING,sfp_openphish,example link\n"
        )
        rows, _ = monitor.parse_findings(report)
        config = {
            "target": "example.org",
            "sender": "monitor@example.org",
            "receivers": ["security@example.org"],
            "cc_emails": [],
        }

        message = monitor.build_email(rows[:1], report, config)
        parsed = BytesParser(policy=policy.default).parsebytes(message.as_bytes())
        csv_parts = [
            part for part in parsed.iter_attachments()
            if part.get_content_type() == "text/csv"
        ]

        self.assertEqual(len(csv_parts), 1)
        self.assertEqual(csv_parts[0].get_payload(decode=True).decode(), report)

    def test_state_file_round_trip_and_invalid_state_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            state_file = Path(directory) / "seen.json"
            monitor.save_seen({"abc", "def"}, state_file)
            self.assertEqual(monitor.load_seen(state_file), {"abc", "def"})

            state_file.write_text("{invalid", encoding="utf-8")
            with self.assertRaises(RuntimeError):
                monitor.load_seen(state_file)

    def test_process_lock_rejects_a_concurrent_run(self):
        with tempfile.TemporaryDirectory() as directory:
            state_file = Path(directory) / "seen.json"
            with monitor.process_lock(state_file):
                with self.assertRaisesRegex(RuntimeError, "already in progress"):
                    with monitor.process_lock(state_file):
                        pass


if __name__ == "__main__":
    unittest.main()
