import csv
import os
import tempfile
import unittest

from main import (
    build_evidence_bundle,
    build_email_section,
    build_relationship_map,
    build_suspicious_indicator_map,
    count_domain_mentions,
    classify_domain_history,
    export_timeline_csv,
    export_evidence_bundle,
    build_timeline_rows,
    extract_email_addresses,
    parse_whois_text,
    parse_domain_input,
    destination_for_domain,
)


class TestDomainForensics(unittest.TestCase):
    def test_parse_domain_input_accepts_multiple_domains(self):
        domains = parse_domain_input("Example.com, example.org example.com")
        self.assertEqual(domains, ["example.com", "example.org"])

    def test_parse_domain_input_rejects_blank_input(self):
        with self.assertRaises(ValueError):
            parse_domain_input("   ")

    def test_destination_for_domain_uses_domain_datetime_history_name(self):
        destination = destination_for_domain(None, "example.com", False, "20260920-214600")
        self.assertTrue(destination.endswith("example.com_20260920-214600_domain_history.csv"))

    def test_lapse_classifier_flags_after_expiration_reacquisition(self):
        data = {
            "events": [
                {"eventAction": "registration", "eventDate": "2015-01-01T00:00:00Z"},
                {"eventAction": "expiration", "eventDate": "2024-01-01T00:00:00Z"},
                {"eventAction": "transfer", "eventDate": "2024-01-15T00:00:00Z"},
                {"eventAction": "last changed", "eventDate": "2024-01-20T00:00:00Z"},
            ],
            "status": ["ok"],
            "nameservers": [{"ldhName": "NS1.AFTERNIC.COM"}],
            "entities": [{"roles": ["registrar"], "vcardArray": ["vcard", [["fn", {}, "text", "GoDaddy.com, LLC"]]]}],
        }
        verdict = classify_domain_history(data)
        self.assertIn("lapse", verdict["verdict"].lower())
        self.assertGreater(verdict["confidence"], 0.5)

    def test_theft_classifier_flags_unauthorized_transfer_during_active_period(self):
        data = {
            "events": [
                {"eventAction": "registration", "eventDate": "2022-01-01T00:00:00Z"},
                {"eventAction": "transfer", "eventDate": "2023-08-01T00:00:00Z"},
                {"eventAction": "expiration", "eventDate": "2026-01-01T00:00:00Z"},
            ],
            "status": ["client transfer prohibited"],
        }
        verdict = classify_domain_history(data)
        self.assertIn("theft", verdict["verdict"].lower())

    def test_export_timeline_csv_creates_file(self):
        data = {
            "events": [
                {"eventAction": "registration", "eventDate": "2024-01-01T00:00:00Z"},
                {"eventAction": "expiration", "eventDate": "2025-01-01T00:00:00Z"},
            ]
        }
        rows = build_timeline_rows(data)
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "history.csv")
            export_timeline_csv(rows, path)
            self.assertTrue(os.path.exists(path))
            with open(path, newline="", encoding="utf-8") as f:
                csv_rows = list(csv.reader(f))
            self.assertGreater(len(csv_rows), 2)
            self.assertEqual(csv_rows[0][0], "eventAction")

    def test_export_evidence_bundle_creates_json_and_csv(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            csv_path, json_path = export_evidence_bundle(
                "example.com",
                {"events": [], "status": [], "nameservers": [], "entities": []},
                "Registrant Email: owner@example.com",
                os.path.join(tmpdir, "report.csv"),
            )
            self.assertTrue(os.path.exists(csv_path))
            self.assertTrue(os.path.exists(json_path))

    def test_parse_whois_text_extracts_historical_fields(self):
        text = '''
Domain Name: example.com
Registry Domain ID: 12345
Registrar WHOIS Server: whois.godaddy.com
Registrar: GoDaddy.com, LLC
Updated Date: 2024-02-03T00:00:00Z
Creation Date: 2015-04-21T00:00:00Z
Registry Expiry Date: 2027-04-21T00:00:00Z
Registrant Organization: Elevate Craft
Name Server: NS1.AFTERNIC.COM
Name Server: NS2.AFTERNIC.COM
'''
        parsed = parse_whois_text(text)
        self.assertEqual(parsed["registrar"], "GoDaddy.com, LLC")
        self.assertEqual(parsed["creation_date"], "2015-04-21T00:00:00Z")
        self.assertEqual(parsed["registrant_organization"], "Elevate Craft")
        self.assertIn("NS1.AFTERNIC.COM", parsed["name_servers"])

    def test_extract_email_addresses_finds_candidates(self):
        text = '''
Registrant Email: admin@example.com
Tech Email: support@domain.com
Abuse Contact: abuse@godaddy.com
'''
        emails = extract_email_addresses(text)
        self.assertIn("admin@example.com", emails)
        self.assertIn("abuse@godaddy.com", emails)

    def test_build_evidence_bundle_includes_email_candidates(self):
        sample = {
            "events": [
                {"eventAction": "registration", "eventDate": "2015-01-01T00:00:00Z"},
                {"eventAction": "expiration", "eventDate": "2027-01-01T00:00:00Z"},
            ],
            "status": ["client transfer prohibited"],
            "nameservers": [{"ldhName": "NS1.AFTERNIC.COM"}],
        }
        bundle = build_evidence_bundle("example.com", sample, "Registrant Email: owner@example.com\nAbuse Contact: abuse@godaddy.com")
        self.assertIn("owner@example.com", bundle["associated_emails"])
        self.assertIn("abuse@godaddy.com", bundle["associated_emails"])
        self.assertIn("summary", bundle)
        self.assertIn("scan_metadata", bundle)
        self.assertIn("scan_started_at_utc", bundle["scan_metadata"])
        self.assertIn("report_created_at_utc", bundle["scan_metadata"])

    def test_build_suspicious_indicator_map_scores_counts(self):
        sample = {
            "events": [
                {"eventAction": "registration", "eventDate": "2022-01-01T00:00:00Z"},
                {"eventAction": "transfer", "eventDate": "2023-08-01T00:00:00Z"},
                {"eventAction": "expiration", "eventDate": "2026-01-01T00:00:00Z"},
            ],
            "status": ["client transfer prohibited"],
            "nameservers": [{"ldhName": "NS1.AFTERNIC.COM"}, {"ldhName": "NS1.DAN.COM"}],
            "entities": [{"roles": ["registrar"], "name": "GoDaddy.com, LLC"}],
        }
        whois_text = "Registrant Email: owner@brand.com\nAdmin Email: admin@elsewhere.net\nAbuse Contact: abuse@godaddy.com"
        indicators = build_suspicious_indicator_map("example.com", sample, whois_text)
        self.assertIn("aftermarket_nameservers", indicators)
        self.assertIn("count", indicators["aftermarket_nameservers"])
        self.assertGreaterEqual(indicators["aftermarket_nameservers"]["rating"], 0)

    def test_build_email_section_creates_mailto_payload(self):
        section = build_email_section("example.com", ["owner@example.com", "abuse@godaddy.com"])
        self.assertIn("subject", section)
        self.assertIn("mailto", section)
        self.assertIn("owner@example.com", section["recipients"])
        self.assertEqual(section["target_domain_emails"], ["owner@example.com"])
        self.assertEqual(section["external_emails"], ["abuse@godaddy.com"])

    def test_build_email_section_reports_redacted_target_contacts(self):
        section = build_email_section("example.com", ["abuse@godaddy.com"])
        self.assertEqual(section["target_domain_emails"], [])
        self.assertEqual(section["disclosure_status"], "no public target-domain email disclosed")

    def test_build_relationship_map_collects_mentions(self):
        sample = {
            "entities": [{"roles": ["registrar"], "name": "GoDaddy.com, LLC"}],
            "nameservers": [{"ldhName": "NS1.AFTERNIC.COM"}, {"ldhName": "NS2.AFTERNIC.COM"}],
        }
        relationship = build_relationship_map("example.com", sample, "Contact: owner@example.com\nAdmin: admin@brand.com")
        self.assertIn("registrar", relationship)
        self.assertIn("nameservers", relationship)
        self.assertIn("email_cluster", relationship)

    def test_email_records_include_associated_domains(self):
        sample = build_email_section("example.com", ["owner@example.com", "admin@elsewhere.net", "owner@example.com"])
        self.assertEqual(sample["email_records"][0]["associated_domain"], "elsewhere.net")
        self.assertEqual(sample["domain_counts"]["example.com"], 1)
        self.assertEqual(sample["domain_counts"]["elsewhere.net"], 1)

    def test_count_domain_mentions_counts_evidence_occurrences(self):
        counts = count_domain_mentions("owner@example.com admin@example.com NS1.example.com")
        self.assertEqual(counts["example.com"], 3)

if __name__ == "__main__":
    unittest.main()
