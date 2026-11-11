#!/usr/bin/env python3
"""Interactive Local Hospital Download Portal Demo (http://127.0.0.1:8080).

Lets you test the exact Hospital Surgeon browser experience:
  - Mint fresh 5-minute keyless V4 Signed URLs with x-goog-custom-audit-* tags
  - Click "Download Surgical Video (.mp4)" directly in your browser (streams straight from GCS)
  - Toggle the KMS Kill Switch for Stanford (Hospital A) vs. Mayo (Hospital B)
  - View live correlated GCS DATA_READ & Cloud KMS Decrypt audit logs
"""

from __future__ import annotations

import html
import json
from flask import Flask, jsonify, redirect, request, Response

from e2e_verify import find_custom_audit_tags
from hipaa_video_service import HipaaVideoService, PocConfig

app = Flask(__name__)
CFG = PocConfig.from_terraform()
SVC = HipaaVideoService(CFG)

TENANTS = {
    "stanford": {
        "name": "Hospital A — Stanford Health",
        "tenant_id": "hosp-stanford",
        "object_name": "sessions/hosp-stanford/davinci-sess-1001.mp4",
        "session_id": "davinci-sess-1001",
        "default_uid": "uid_stanford_dr_smith_8821",
        "kms_key_id": CFG.hospital_a_kms_key_id,
    },
    "mayo": {
        "name": "Hospital B — Mayo Clinic",
        "tenant_id": "hosp-mayo",
        "object_name": "sessions/hosp-mayo/davinci-sess-2002.mp4",
        "session_id": "davinci-sess-2002",
        "default_uid": "uid_mayo_dr_patel_4410",
        "kms_key_id": CFG.hospital_b_kms_key_id,
    },
}


@app.post("/api/seed")
def seed_videos() -> Response:
    out = {}
    for key, t in TENANTS.items():
        out[key] = SVC.upload_surgical_video(
            object_name=t["object_name"],
            kms_key_id=t["kms_key_id"],
            session_id=t["session_id"],
            tenant_id=t["tenant_id"],
        )
    return jsonify({"status": "ok", "uploaded": out})


@app.post("/api/mint/<hospital>")
def mint_url(hospital: str) -> Response:
    t = TENANTS[hospital]
    payload = request.get_json(silent=True) or {}
    uid = payload.get("uid") or t["default_uid"]
    ttl = int(payload.get("ttl", 5))
    signed_url = SVC.generate_download_signed_url(
        object_name=t["object_name"],
        user_uid=uid,
        tenant_id=t["tenant_id"],
        session_id=t["session_id"],
        ttl_minutes=ttl,
    )
    return jsonify({"signed_url": signed_url, "uid": uid, "ttl_minutes": ttl})


@app.post("/api/kms/<hospital>/<action>")
def toggle_kms(hospital: str, action: str) -> Response:
    t = TENANTS[hospital]
    enabled = action == "enable"
    state = SVC.set_kms_key_enabled(t["kms_key_id"], enabled=enabled)
    return jsonify({"hospital": hospital, "kms_state": state})


@app.get("/api/status")
def status() -> Response:
    return jsonify(
        {
            "project_id": CFG.project_id,
            "bucket": CFG.video_bucket_name,
            "signer_sa": CFG.url_signer_sa_email,
            "gcs_service_agent": CFG.gcs_service_agent,
            "kms_states": {
                k: SVC.get_kms_key_state(v["kms_key_id"]) for k, v in TENANTS.items()
            },
        }
    )


@app.get("/api/audit-logs")
def audit_logs() -> Response:
    logs = SVC.query_dual_audit_logs(lookback_minutes=30, max_entries=15)
    gcs_clean = []
    for e in logs["gcs_data_read"]:
        p = e["protoPayload"]
        gcs_clean.append(
            {
                "timestamp": e["timestamp"],
                "resource": p.get("resourceName"),
                "callerIp": p.get("requestMetadata", {}).get("callerIp"),
                "signerPrincipal": p.get("authenticationInfo", {}).get("principalEmail"),
                "status": p.get("status", {}),
                "customAudit": find_custom_audit_tags(p),
            }
        )
    kms_clean = []
    for e in logs["kms_decrypt"]:
        p = e["protoPayload"]
        kms_clean.append(
            {
                "timestamp": e["timestamp"],
                "kmsKeyVersion": p.get("resourceName"),
                "serviceAgent": p.get("authenticationInfo", {}).get("principalEmail"),
                "status": p.get("status", {}),
            }
        )
    return jsonify({"gcs_data_read": gcs_clean, "kms_decrypt": kms_clean})


@app.get("/")
def index() -> str:
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Intuitive Surgical — HIPAA V4 Signed URL + CMEK Demo</title>
  <style>
    body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; margin: 2rem auto; max-width: 1080px; padding: 0 1rem; background: #f8fafc; color: #0f172a; }}
    h1 {{ margin-bottom: 0.25rem; }}
    .meta {{ background: #e2e8f0; padding: 0.75rem 1rem; border-radius: 8px; font-size: 0.88rem; margin-bottom: 1.5rem; }}
    .grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 1.25rem; margin-bottom: 1.5rem; }}
    .card {{ background: #fff; border: 1px solid #cbd5e1; border-radius: 10px; padding: 1.25rem; box-shadow: 0 1px 2px rgba(0,0,0,0.04); }}
    button, a.btn {{ display: inline-block; padding: 0.5rem 0.9rem; border-radius: 6px; border: none; cursor: pointer; font-weight: 600; font-size: 0.88rem; text-decoration: none; margin-right: 0.4rem; margin-top: 0.4rem; }}
    .primary {{ background: #2563eb; color: #fff; }}
    .success {{ background: #059669; color: #fff; }}
    .danger {{ background: #dc2626; color: #fff; }}
    .neutral {{ background: #475569; color: #fff; }}
    pre {{ background: #0f172a; color: #e2e8f0; padding: 0.85rem; border-radius: 8px; overflow-x: auto; font-size: 0.78rem; max-height: 280px; }}
    input {{ padding: 0.4rem 0.6rem; border: 1px solid #cbd5e1; border-radius: 6px; width: 70%; font-family: monospace; }}
    .badge {{ padding: 0.2rem 0.55rem; border-radius: 999px; font-size: 0.75rem; font-weight: 700; }}
    .ENABLED {{ background: #dcfce7; color: #166534; }}
    .DISABLED {{ background: #fee2e2; color: #991b1b; }}
  </style>
</head>
<body>
  <h1>Intuitive Surgical — HIPAA V4 Signed URL + Per-Hospital CMEK PoC</h1>
  <div class="meta">
    <strong>Project:</strong> <code>{html.escape(CFG.project_id)}</code> &nbsp;|&nbsp;
    <strong>Shared Bucket:</strong> <code>gs://{html.escape(CFG.video_bucket_name)}</code> &nbsp;|&nbsp;
    <strong>URL Signer SA:</strong> <code>{html.escape(CFG.url_signer_sa_email)}</code>
    <div style="margin-top:0.5rem;">
      <button class="neutral" onclick="seedVideos()">Re-Upload Sample Surgical Videos (.mp4)</button>
      <button class="neutral" onclick="refreshLogs()">Refresh Dual Audit Logs</button>
    </div>
  </div>

  <div class="grid">
    <div class="card">
      <h3>Hospital A — Stanford Health <span id="state-stanford" class="badge">...</span></h3>
      <p><small>Object: <code>sessions/hosp-stanford/davinci-sess-1001.mp4</code><br>KMS Key: <code>hospital-a-stanford-key</code></small></p>
      <label>Audit UID: <input id="uid-stanford" value="uid_stanford_dr_smith_8821"></label><br>
      <button class="primary" onclick="mint('stanford')">1. Mint 5-Min V4 Signed URL</button>
      <a id="dl-stanford" class="btn success" style="display:none;" target="_blank" rel="noopener">2. Download .mp4 Direct from GCS</a>
      <hr>
      <button class="danger" onclick="toggleKms('stanford','disable')">Kill Switch: Disable Stanford KMS Key</button>
      <button class="neutral" onclick="toggleKms('stanford','enable')">Re-Enable Key</button>
      <pre id="url-stanford">Mint a V4 Signed URL to inspect signed query parameters...</pre>
    </div>

    <div class="card">
      <h3>Hospital B — Mayo Clinic <span id="state-mayo" class="badge">...</span></h3>
      <p><small>Object: <code>sessions/hosp-mayo/davinci-sess-2002.mp4</code><br>KMS Key: <code>hospital-b-mayo-key</code></small></p>
      <label>Audit UID: <input id="uid-mayo" value="uid_mayo_dr_patel_4410"></label><br>
      <button class="primary" onclick="mint('mayo')">1. Mint 5-Min V4 Signed URL</button>
      <a id="dl-mayo" class="btn success" style="display:none;" target="_blank" rel="noopener">2. Download .mp4 Direct from GCS</a>
      <hr>
      <button class="danger" onclick="toggleKms('mayo','disable')">Kill Switch: Disable Mayo KMS Key</button>
      <button class="neutral" onclick="toggleKms('mayo','enable')">Re-Enable Key</button>
      <pre id="url-mayo">Mint a V4 Signed URL to inspect signed query parameters...</pre>
    </div>
  </div>

  <div class="card">
    <h3>Correlated Dual Audit Trail (GCS <code>DATA_READ</code> + Cloud KMS <code>Decrypt</code>)</h3>
    <pre id="logs">Click "Refresh Dual Audit Logs" after downloading...</pre>
  </div>

  <script>
    async function refreshStatus() {{
      const res = await fetch('/api/status');
      const data = await res.json();
      for (const h of ['stanford', 'mayo']) {{
        const el = document.getElementById('state-' + h);
        el.textContent = data.kms_states[h];
        el.className = 'badge ' + data.kms_states[h];
      }}
    }}
    async function seedVideos() {{
      const res = await fetch('/api/seed', {{method: 'POST'}});
      alert('Uploaded both sample .mp4 surgical videos with per-hospital CMEK keys!');
    }}
    async function mint(h) {{
      const uid = document.getElementById('uid-' + h).value;
      const res = await fetch('/api/mint/' + h, {{
        method: 'POST',
        headers: {{'Content-Type': 'application/json'}},
        body: JSON.stringify({{uid, ttl: 5}})
      }});
      const data = await res.json();
      document.getElementById('url-' + h).textContent = data.signed_url.split('&').join('\\n&');
      const dl = document.getElementById('dl-' + h);
      dl.href = data.signed_url;
      dl.style.display = 'inline-block';
    }}
    async function toggleKms(h, action) {{
      await fetch(`/api/kms/${{h}}/${{action}}`, {{method: 'POST'}});
      await refreshStatus();
    }}
    async function refreshLogs() {{
      document.getElementById('logs').textContent = 'Querying Cloud Audit Logs...';
      const res = await fetch('/api/audit-logs');
      const data = await res.json();
      document.getElementById('logs').textContent = JSON.stringify(data, null, 2);
    }}
    refreshStatus();
    refreshLogs();
  </script>
</body>
</html>"""


if __name__ == "__main__":
    print("Starting Hospital Download Portal Demo on http://127.0.0.1:8080 ...")
    app.run(host="127.0.0.1", port=8080, debug=False)
