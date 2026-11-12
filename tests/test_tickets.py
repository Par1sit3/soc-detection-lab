"""Unit tests for the ticket queue logic. Run: python3 -m unittest discover tests"""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "tickets"))
import app  # noqa: E402


def alert(rule_id="5763", level=10, srcip="172.30.0.66", mitre=("T1110",), log="Failed password for root"):
    return {
        "rule": {"id": rule_id, "level": level, "description": "test alert", "mitre": {"id": list(mitre)}},
        "agent": {"name": "web01"},
        "data": {"srcip": srcip},
        "full_log": log,
    }


class TicketTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.conn = app.connect(os.path.join(self.dir.name, "t.db"))

    def tearDown(self):
        self.conn.close()
        self.dir.cleanup()

    def test_new_alert_creates_ticket(self):
        ticket_id, created = app.ingest(self.conn, alert())
        self.assertTrue(created)
        ticket = app.list_tickets(self.conn)[0]
        self.assertEqual((ticket["id"], ticket["status"], ticket["severity"]), (ticket_id, "open", "medium"))

    def test_repeat_alert_is_grouped(self):
        first, _ = app.ingest(self.conn, alert())
        second, created = app.ingest(self.conn, alert())
        self.assertEqual(first, second)
        self.assertFalse(created)
        self.assertEqual(app.list_tickets(self.conn)[0]["alert_count"], 2)

    def test_different_source_gets_own_ticket(self):
        app.ingest(self.conn, alert(srcip="172.30.0.66"))
        _, created = app.ingest(self.conn, alert(srcip="172.30.0.99"))
        self.assertTrue(created)
        self.assertEqual(len(app.list_tickets(self.conn)), 2)

    def test_closed_ticket_is_not_reused(self):
        first, _ = app.ingest(self.conn, alert())
        self.assertTrue(app.set_status(self.conn, first, "closed"))
        second, created = app.ingest(self.conn, alert())
        self.assertTrue(created)
        self.assertNotEqual(first, second)

    def test_severity_mapping_and_escalation(self):
        self.assertEqual([app.severity(n) for n in (10, 12, 15)], ["medium", "high", "critical"])
        app.ingest(self.conn, alert(level=10))
        app.ingest(self.conn, alert(level=15))
        self.assertEqual(app.list_tickets(self.conn)[0]["severity"], "critical")

    def test_invalid_status_rejected(self):
        ticket_id, _ = app.ingest(self.conn, alert())
        self.assertFalse(app.set_status(self.conn, ticket_id, "deleted"))

    def test_playbook_matches_sub_technique(self):
        self.assertIn("account owner", app.triage_steps(["T1078.003"]))
        self.assertEqual(app.triage_steps(["T9999"]), app.DEFAULT_STEPS)

    def test_page_escapes_log_content(self):
        app.ingest(self.conn, alert(srcip="<script>alert(1)</script>"))
        page = app.render_page(app.list_tickets(self.conn))
        self.assertNotIn("<script>alert(1)</script>", page)
        self.assertIn("&lt;script&gt;", page)


if __name__ == "__main__":
    unittest.main()
