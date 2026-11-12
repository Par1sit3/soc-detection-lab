#!/usr/bin/env python3
"""Minimal ticket queue for the SOC lab.

Wazuh posts high-severity alerts here (see wazuh/custom-ticket). Repeated alerts
for the same rule, host and source are grouped into one open ticket instead of
flooding the queue. This is a lab stand-in for a real case-management tool such
as TheHive or Jira: no authentication, standard library only.
"""
import html
import json
import os
import re
import sqlite3
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

DB_PATH = os.environ.get("TICKET_DB", "/data/tickets.db")
MAX_BODY = 256 * 1024
STATUSES = ("open", "acknowledged", "closed")
LOCK = threading.Lock()

# First triage steps per MITRE ATT&CK technique (prefix match on the ID).
PLAYBOOK = {
    "T1110": "Check whether any login from this source succeeded. Confirm the source was blocked. Review the targeted accounts.",
    "T1078": "Confirm with the account owner. If not expected: disable the account, rotate its password, review what it did after login.",
    "T1136": "Verify the new account was authorised. If not: lock it, find which session created it, check for other persistence.",
    "T1098": "Compare the changed key or permission with the last known-good state. Remove unknown keys and rotate credentials.",
    "T1505": "Isolate the file, do not execute it. Check web logs for requests to it and how it was written.",
    "T1548": "Review the sudoers change and who made it. Revert if unauthorised.",
    "T1190": "Check the web server response codes for these requests. A 200 on an attack URL needs a closer look.",
    "T1046": "Scan only. Note the source; raise priority if it is followed by login attempts or web attacks.",
    "T1595": "Scanner traffic. Note the source; raise priority if it is followed by exploitation attempts.",
}
DEFAULT_STEPS = "Read the raw log, identify the source and affected account or file, and decide whether it was expected activity."


def now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def severity(level):
    if level >= 15:
        return "critical"
    if level >= 12:
        return "high"
    return "medium"


def triage_steps(mitre_ids):
    for technique in mitre_ids:
        for prefix, steps in PLAYBOOK.items():
            if technique.startswith(prefix):
                return steps
    return DEFAULT_STEPS


def extract(alert):
    """Pull the fields a ticket needs out of a Wazuh alert."""
    rule = alert.get("rule") or {}
    data = alert.get("data") or {}
    mitre = (rule.get("mitre") or {}).get("id") or []
    source = data.get("srcip") or data.get("src_ip") or (alert.get("syscheck") or {}).get("path") or "-"
    return {
        "rule_id": str(rule.get("id", "?")),
        "level": int(rule.get("level", 0)),
        "title": str(rule.get("description", "Wazuh alert"))[:200],
        "mitre": ",".join(mitre),
        "agent": str((alert.get("agent") or {}).get("name", "-")),
        "source": str(source)[:200],
        "sample": str(alert.get("full_log") or data.get("alert", {}).get("signature") or "")[:500],
        "steps": triage_steps(mitre),
    }


def connect(path=None):
    conn = sqlite3.connect(path or DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute(
        """CREATE TABLE IF NOT EXISTS tickets (
             id INTEGER PRIMARY KEY AUTOINCREMENT,
             status TEXT NOT NULL DEFAULT 'open',
             severity TEXT NOT NULL, level INTEGER NOT NULL,
             rule_id TEXT NOT NULL, title TEXT NOT NULL, mitre TEXT,
             agent TEXT, source TEXT, sample TEXT, steps TEXT,
             alert_count INTEGER NOT NULL DEFAULT 1,
             first_seen TEXT NOT NULL, last_seen TEXT NOT NULL)"""
    )
    return conn


def ingest(conn, alert):
    """Create a ticket, or add the alert to a matching ticket that is not closed.

    Returns (ticket_id, created).
    """
    f = extract(alert)
    with LOCK:
        row = conn.execute(
            "SELECT id, level FROM tickets WHERE rule_id=? AND agent=? AND source=? AND status!='closed'",
            (f["rule_id"], f["agent"], f["source"]),
        ).fetchone()
        if row:
            level = max(row["level"], f["level"])
            conn.execute(
                "UPDATE tickets SET alert_count=alert_count+1, last_seen=?, level=?, severity=? WHERE id=?",
                (now(), level, severity(level), row["id"]),
            )
            conn.commit()
            return row["id"], False
        cur = conn.execute(
            """INSERT INTO tickets (severity, level, rule_id, title, mitre, agent, source, sample, steps, first_seen, last_seen)
               VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
            (severity(f["level"]), f["level"], f["rule_id"], f["title"], f["mitre"], f["agent"],
             f["source"], f["sample"], f["steps"], now(), now()),
        )
        conn.commit()
        return cur.lastrowid, True


def set_status(conn, ticket_id, status):
    if status not in STATUSES:
        return False
    with LOCK:
        cur = conn.execute("UPDATE tickets SET status=? WHERE id=?", (status, ticket_id))
        conn.commit()
        return cur.rowcount == 1


def list_tickets(conn):
    rows = conn.execute(
        """SELECT * FROM tickets
           ORDER BY CASE status WHEN 'open' THEN 0 WHEN 'acknowledged' THEN 1 ELSE 2 END, level DESC, id DESC"""
    ).fetchall()
    return [dict(r) for r in rows]


def render_page(tickets):
    """HTML queue view. Every value is escaped: log content is attacker-controlled."""
    e = lambda v: html.escape(str(v if v is not None else ""))
    open_count = sum(1 for t in tickets if t["status"] != "closed")
    rows = "".join(
        f"""<tr class="{e(t['status'])}">
              <td>#{e(t['id'])}</td><td><span class="sev {e(t['severity'])}">{e(t['severity'])}</span></td>
              <td>{e(t['status'])}</td>
              <td><strong>{e(t['title'])}</strong><div class="steps">Triage: {e(t['steps'])}</div></td>
              <td>{e(t['rule_id'])}</td><td>{e(t['mitre'])}</td><td>{e(t['agent'])}</td><td>{e(t['source'])}</td>
              <td class="num">{e(t['alert_count'])}</td><td>{e(t['first_seen'])}</td><td>{e(t['last_seen'])}</td>
            </tr>"""
        for t in tickets
    ) or '<tr><td colspan="11">No tickets yet. Run an attack scenario.</td></tr>'
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta http-equiv="refresh" content="15">
<title>SOC Lab ticket queue</title>
<style>
  body {{ font: 14px/1.4 system-ui, sans-serif; margin: 24px; color: #1a1c21; background: #f7f8fa; }}
  h1 {{ font-size: 20px; margin: 0 0 4px; }} p {{ color: #5a6070; margin: 0 0 16px; }}
  .wrap {{ overflow-x: auto; }}
  table {{ border-collapse: collapse; width: 100%; background: #fff; }}
  th, td {{ text-align: left; padding: 8px 10px; border-bottom: 1px solid #e3e6ec; vertical-align: top; }}
  th {{ font-size: 12px; text-transform: uppercase; letter-spacing: .04em; color: #5a6070; }}
  .num {{ text-align: right; }} .steps {{ color: #5a6070; font-size: 12px; margin-top: 2px; max-width: 520px; }}
  .sev {{ padding: 2px 8px; border-radius: 10px; font-size: 12px; font-weight: 600; color: #fff; }}
  .critical {{ background: #b3261e; }} .high {{ background: #c2570c; }} .medium {{ background: #8a6d00; }}
  tr.closed {{ opacity: .5; }}
</style></head><body>
<h1>SOC Lab ticket queue</h1>
<p>{open_count} open or acknowledged, {len(tickets)} total. Created automatically from Wazuh alerts at level 10 and above.</p>
<div class="wrap"><table>
<tr><th>ID</th><th>Severity</th><th>Status</th><th>Alert</th><th>Rule</th><th>ATT&amp;CK</th><th>Host</th><th>Source</th><th>Alerts</th><th>First seen (UTC)</th><th>Last seen (UTC)</th></tr>
{rows}
</table></div></body></html>"""


class Handler(BaseHTTPRequestHandler):
    def _send(self, code, body, ctype="application/json"):
        data = body.encode() if isinstance(body, str) else json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype + "; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(data)

    def _json_body(self):
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0 or length > MAX_BODY:
            return None
        try:
            body = json.loads(self.rfile.read(length))
        except ValueError:
            return None
        return body if isinstance(body, dict) else None

    def do_GET(self):
        conn = connect()
        try:
            if self.path == "/":
                self._send(200, render_page(list_tickets(conn)), "text/html")
            elif self.path == "/api/tickets":
                self._send(200, list_tickets(conn))
            elif self.path == "/healthz":
                self._send(200, {"ok": True})
            else:
                self._send(404, {"error": "not found"})
        finally:
            conn.close()

    def do_POST(self):
        body = self._json_body()
        if body is None:
            return self._send(400, {"error": "expected a JSON object under 256 KB"})
        conn = connect()
        try:
            if self.path == "/api/alerts":
                ticket_id, created = ingest(conn, body)
                return self._send(201 if created else 200, {"ticket": ticket_id, "created": created})
            match = re.fullmatch(r"/api/tickets/(\d+)/status", self.path)
            if match:
                ok = set_status(conn, int(match.group(1)), str(body.get("status")))
                return self._send(200 if ok else 400, {"ok": ok})
            self._send(404, {"error": "not found"})
        finally:
            conn.close()

    def log_message(self, fmt, *args):
        print("%s %s" % (self.address_string(), fmt % args), flush=True)


if __name__ == "__main__":
    connect().close()
    ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
