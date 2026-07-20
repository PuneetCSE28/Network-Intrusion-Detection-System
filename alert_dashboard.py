#!/usr/bin/env python3
"""
alert_dashboard.py
====================
CodeAlpha Cyber Security Internship — Task 4 (Network IDS)

Reads Suricata's eve.json log and generates a single, self-contained
dashboard.html summarizing detected alerts: total counts, breakdown by
rule/signature, breakdown by severity, top source IPs, and a full alert
table. No external JS/CSS dependencies — safe to open completely offline.

Usage:
    python3 alert_dashboard.py <path/to/eve.json> <path/to/dashboard.html>
"""

import json
import sys
from collections import Counter
from html import escape


def load_alerts(eve_path):
    alerts = []
    with open(eve_path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if rec.get("event_type") == "alert":
                alerts.append(rec)
    return alerts


SEVERITY_LABEL = {1: "High", 2: "Medium", 3: "Low"}
SEVERITY_COLOR = {1: "#E63946", 2: "#F4A340", 3: "#4E8098"}


def bar_rows(counter, total, color_fn=lambda k: "#1E2761"):
    rows = []
    for key, count in counter.most_common():
        pct = (count / total * 100) if total else 0
        rows.append(f"""
        <div class="bar-row">
          <div class="bar-label">{escape(str(key))}</div>
          <div class="bar-track"><div class="bar-fill" style="width:{pct:.1f}%; background:{color_fn(key)};"></div></div>
          <div class="bar-count">{count}</div>
        </div>""")
    return "\n".join(rows)


def build_dashboard(alerts, title="Network IDS — Alert Dashboard"):
    total = len(alerts)
    sig_counter = Counter(a["alert"]["signature"] for a in alerts)
    sev_counter = Counter(SEVERITY_LABEL.get(a["alert"].get("severity"), "Unknown") for a in alerts)
    src_counter = Counter(a.get("src_ip", "unknown") for a in alerts)
    proto_counter = Counter(a.get("proto", "unknown") for a in alerts)

    sev_color_map = {"High": "#E63946", "Medium": "#F4A340", "Low": "#4E8098", "Unknown": "#8A8A8A"}

    table_rows = []
    for a in sorted(alerts, key=lambda x: x.get("timestamp", "")):
        sev = SEVERITY_LABEL.get(a["alert"].get("severity"), "Unknown")
        table_rows.append(f"""
        <tr>
          <td>{escape(a.get("timestamp", "")[:19].replace("T", " "))}</td>
          <td class="mono">{escape(a.get("src_ip", "-"))}:{escape(str(a.get("src_port", "-")))}</td>
          <td class="mono">{escape(a.get("dest_ip", "-"))}:{escape(str(a.get("dest_port", "-")))}</td>
          <td>{escape(a.get("proto", "-"))}</td>
          <td>{escape(a["alert"]["signature"])}</td>
          <td><span class="pill" style="background:{sev_color_map[sev]}22; color:{sev_color_map[sev]};">{sev}</span></td>
        </tr>""")

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>{escape(title)}</title>
<style>
  :root {{ --navy:#1E2761; --ice:#CADCFC; --red:#E63946; --gray:#5A6472; --bg:#F7F9FC; }}
  * {{ box-sizing: border-box; }}
  body {{ font-family: -apple-system, Calibri, Arial, sans-serif; margin:0; background:var(--bg); color:#222; }}
  header {{ background: var(--navy); color:white; padding: 28px 40px; }}
  header h1 {{ margin:0; font-size: 26px; }}
  header p {{ margin:6px 0 0; color: var(--ice); font-size: 14px; }}
  .container {{ max-width: 1100px; margin: 0 auto; padding: 30px 40px 60px; }}
  .cards {{ display:flex; gap:20px; margin-bottom: 30px; flex-wrap: wrap; }}
  .card {{ background:white; border:1px solid #E1E6EF; border-radius:10px; padding:20px 24px; flex:1; min-width:160px; }}
  .card .num {{ font-size: 32px; font-weight:bold; color: var(--navy); }}
  .card .lbl {{ font-size: 13px; color: var(--gray); margin-top:4px; }}
  .panel {{ background:white; border:1px solid #E1E6EF; border-radius:10px; padding:24px; margin-bottom:24px; }}
  .panel h2 {{ margin:0 0 16px; font-size:16px; color:var(--navy); }}
  .bar-row {{ display:flex; align-items:center; gap:12px; margin-bottom:10px; }}
  .bar-label {{ width: 260px; font-size:13px; flex-shrink:0; }}
  .bar-track {{ flex:1; background:#EDEFF4; border-radius:6px; height:14px; overflow:hidden; }}
  .bar-fill {{ height:100%; border-radius:6px; }}
  .bar-count {{ width:36px; text-align:right; font-size:13px; color:var(--gray); flex-shrink:0; }}
  table {{ width:100%; border-collapse: collapse; font-size:13px; }}
  th {{ text-align:left; padding:10px 12px; background:#EDEFF4; color:var(--navy); font-size:12px; text-transform:uppercase; letter-spacing:0.03em; }}
  td {{ padding:10px 12px; border-bottom:1px solid #EEF1F6; }}
  .mono {{ font-family: "Courier New", monospace; }}
  .pill {{ padding:3px 10px; border-radius:12px; font-size:12px; font-weight:bold; }}
  .two-col {{ display:flex; gap:24px; flex-wrap:wrap; }}
  .two-col .panel {{ flex:1; min-width:400px; }}
</style>
</head>
<body>
<header>
  <h1>🛡 Network IDS — Alert Dashboard</h1>
  <p>CodeAlpha Cyber Security Internship — Task 4 · Suricata custom rule set</p>
</header>
<div class="container">

  <div class="cards">
    <div class="card"><div class="num">{total}</div><div class="lbl">Total Alerts</div></div>
    <div class="card"><div class="num">{len(sig_counter)}</div><div class="lbl">Unique Signatures Triggered</div></div>
    <div class="card"><div class="num">{len(src_counter)}</div><div class="lbl">Unique Source IPs</div></div>
    <div class="card"><div class="num">{sev_counter.get("High", 0)}</div><div class="lbl">High Severity Alerts</div></div>
  </div>

  <div class="two-col">
    <div class="panel">
      <h2>Alerts by Signature</h2>
      {bar_rows(sig_counter, total)}
    </div>
    <div class="panel">
      <h2>Alerts by Severity</h2>
      {bar_rows(sev_counter, total, color_fn=lambda k: sev_color_map.get(k, "#8A8A8A"))}
      <h2 style="margin-top:24px;">Alerts by Protocol</h2>
      {bar_rows(proto_counter, total)}
    </div>
  </div>

  <div class="panel">
    <h2>Top Source IPs</h2>
    {bar_rows(src_counter, total)}
  </div>

  <div class="panel">
    <h2>All Alerts ({total})</h2>
    <table>
      <tr><th>Time</th><th>Source</th><th>Destination</th><th>Proto</th><th>Signature</th><th>Severity</th></tr>
      {"".join(table_rows)}
    </table>
  </div>

</div>
</body>
</html>"""
    return html


if __name__ == "__main__":
    eve_path = sys.argv[1] if len(sys.argv) > 1 else "eve.json"
    out_path = sys.argv[2] if len(sys.argv) > 2 else "dashboard.html"
    alerts = load_alerts(eve_path)
    html = build_dashboard(alerts)
    with open(out_path, "w") as f:
        f.write(html)
    print(f"Parsed {len(alerts)} alerts -> wrote {out_path}")
