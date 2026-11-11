#!/usr/bin/env python3
"""Automated End-to-End Verification Suite for Intuitive Surgical HIPAA Signed URL + CMEK PoC.

Proves all 6 architectural pillars against the live Argolis deployment:
  1. Per-Hospital CMEK Ingestion in a Shared Bucket (Stanford vs. Mayo KMS keys)
  2. Keyless V4 Signed URL Generation via IAM signBlob + 4 x-goog-custom-audit-* Parameters
  3. Zero-Friction Browser/HTTPS Download (No KMS IAM or Auth Headers Required) + Cache-Control Verification
  4. Cryptographic Tamper Rejection on x-goog-custom-audit-* Query Parameters (403 SignatureDoesNotMatch)
  5. Instant Per-Hospital KMS Kill Switch (Disabling Hospital A blocks Hospital A's active Signed URL
     while Hospital B's video in the exact same bucket continues downloading 200 OK; then restores Key A)
  6. Dual Audit Trail Correlation (GCS DATA_READ custom audit tags + Cloud KMS Decrypt by GCS Service Agent)
"""

from __future__ import annotations

import hashlib
import json
import sys
import time
import urllib.parse
from typing import Any, Dict

import requests

from hipaa_video_service import HipaaVideoService, PocConfig


def banner(step: int, title: str) -> None:
    print(f"\n{'=' * 88}")
    print(f"[STEP {step}/6] {title}")
    print(f"{'=' * 88}")


def find_custom_audit_tags(obj: Any) -> Dict[str, str]:
    """Recursively extract all x-goog-custom-audit-* fields from a Cloud Audit Log payload."""
    found: Dict[str, str] = {}
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k.startswith("x-goog-custom-audit-"):
                found[k] = str(v)
            else:
                found.update(find_custom_audit_tags(v))
    elif isinstance(obj, list):
        for item in obj:
            found.update(find_custom_audit_tags(item))
    return found


def main() -> int:
    print("Loading Argolis Terraform outputs...")
    cfg = PocConfig.from_terraform()
    svc = HipaaVideoService(cfg)

    print(f"  Project ID         : {cfg.project_id} (#{cfg.project_number})")
    print(f"  Shared Video Bucket: gs://{cfg.video_bucket_name}")
    print(f"  URL Signer SA      : {cfg.url_signer_sa_email}")
    print(f"  GCS Service Agent  : {cfg.gcs_service_agent}")
    print(f"  Hospital A KMS Key : {cfg.hospital_a_kms_key_id}")
    print(f"  Hospital B KMS Key : {cfg.hospital_b_kms_key_id}")
    print(f"  Audit Vault Bucket : {cfg.hipaa_audit_log_bucket}")

    # Ensure both hospital keys start ENABLED in case a prior run was interrupted
    svc.set_kms_key_enabled(cfg.hospital_a_kms_key_id, True)
    svc.set_kms_key_enabled(cfg.hospital_b_kms_key_id, True)

    # -------------------------------------------------------------------------
    # STEP 1: Per-Hospital CMEK Ingestion into the Same Bucket
    # -------------------------------------------------------------------------
    banner(1, "Ingest Surgical Videos with Per-Hospital CMEK Keys (Hospital A vs. Hospital B)")
    hosp_a_obj = "sessions/hosp-stanford/davinci-sess-1001.mp4"
    hosp_a_killswitch_obj = "sessions/hosp-stanford/davinci-sess-1002-killswitch.mp4"
    hosp_b_obj = "sessions/hosp-mayo/davinci-sess-2002.mp4"

    meta_a = svc.upload_surgical_video(
        object_name=hosp_a_obj,
        kms_key_id=cfg.hospital_a_kms_key_id,
        session_id="davinci-sess-1001",
        tenant_id="hosp-stanford",
    )
    existing_ks_blob = svc.storage_admin_client.bucket(cfg.video_bucket_name).get_blob(
        hosp_a_killswitch_obj
    )
    if existing_ks_blob is None:
        svc.upload_surgical_video(
            object_name=hosp_a_killswitch_obj,
            kms_key_id=cfg.hospital_a_kms_key_id,
            session_id="davinci-sess-1002-killswitch",
            tenant_id="hosp-stanford",
        )
    meta_b = svc.upload_surgical_video(
        object_name=hosp_b_obj,
        kms_key_id=cfg.hospital_b_kms_key_id,
        session_id="davinci-sess-2002",
        tenant_id="hosp-mayo",
    )

    assert cfg.hospital_a_kms_key_id in meta_a["kms_key_name"], "Hospital A KMS key mismatch!"
    assert cfg.hospital_b_kms_key_id in meta_b["kms_key_name"], "Hospital B KMS key mismatch!"
    assert meta_a["kms_key_name"] != meta_b["kms_key_name"], "Keys must be cryptographically isolated!"

    print(f"  [PASS] Hospital A uploaded: {hosp_a_obj}")
    print(f"         Encrypted with KEK : {meta_a['kms_key_name']}")
    print(f"         SHA-256            : {meta_a['sha256']}")
    print(f"  [PASS] Hospital B uploaded: {hosp_b_obj}")
    print(f"         Encrypted with KEK : {meta_b['kms_key_name']}")
    print(f"         SHA-256            : {meta_b['sha256']}")

    # -------------------------------------------------------------------------
    # STEP 2: Keyless V4 Signed URL Generation (IAM signBlob + Custom Audit Tags)
    # -------------------------------------------------------------------------
    banner(2, "Mint Keyless V4 Signed URLs (5-min TTL + 4 Signed x-goog-custom-audit-* Tags)")
    url_a = svc.generate_download_signed_url(
        object_name=hosp_a_obj,
        user_uid="uid_stanford_dr_smith_8821",
        tenant_id="hosp-stanford",
        session_id="davinci-sess-1001",
        ttl_minutes=5,
    )
    # Pre-mint a valid unexpired V4 Signed URL for Hospital A's second session BEFORE disabling KMS
    url_a_killswitch = svc.generate_download_signed_url(
        object_name=hosp_a_killswitch_obj,
        user_uid="uid_stanford_dr_smith_8821",
        tenant_id="hosp-stanford",
        session_id="davinci-sess-1002-killswitch",
        ttl_minutes=5,
    )
    url_b = svc.generate_download_signed_url(
        object_name=hosp_b_obj,
        user_uid="uid_mayo_dr_patel_4410",
        tenant_id="hosp-mayo",
        session_id="davinci-sess-2002",
        ttl_minutes=5,
    )

    parsed_qs = urllib.parse.parse_qs(urllib.parse.urlparse(url_a).query)
    assert parsed_qs["X-Goog-Algorithm"] == ["GOOG4-RSA-SHA256"]
    assert parsed_qs["X-Goog-Expires"] == ["300"]
    assert parsed_qs["x-goog-custom-audit-uid"] == ["uid_stanford_dr_smith_8821"]
    assert parsed_qs["x-goog-custom-audit-tenant"] == ["hosp-stanford"]
    assert parsed_qs["x-goog-custom-audit-session"] == ["davinci-sess-1001"]
    assert parsed_qs["x-goog-custom-audit-action"] == ["download"]

    print("  [PASS] Minted keyless V4 Signed URLs via IAM Credentials API (signBlob).")
    print(f"         Signer Principal : {parsed_qs['X-Goog-Credential'][0].split('/')[0]}")
    print(f"         TTL              : {parsed_qs['X-Goog-Expires'][0]} seconds (5 min)")
    print("         Signed Audit Tags: uid, tenant, session, action")

    # -------------------------------------------------------------------------
    # STEP 3: Unauthenticated Browser-Equivalent HTTPS Download + HIPAA Headers
    # -------------------------------------------------------------------------
    banner(3, "Verify Zero-Friction HTTPS Download & HIPAA Response Guardrails")
    resp_a = requests.get(url_a, timeout=30)
    resp_b = requests.get(url_b, timeout=30)

    assert resp_a.status_code == 200, f"Expected 200 for Hospital A, got {resp_a.status_code}: {resp_a.text}"
    assert resp_b.status_code == 200, f"Expected 200 for Hospital B, got {resp_b.status_code}: {resp_b.text}"
    assert hashlib.sha256(resp_a.content).hexdigest() == meta_a["sha256"], "Hospital A payload SHA-256 mismatch!"
    assert hashlib.sha256(resp_b.content).hexdigest() == meta_b["sha256"], "Hospital B payload SHA-256 mismatch!"
    assert meta_a["cache_control"] == "private, no-store", "Object metadata Cache-Control must be 'private, no-store'"
    assert "no-store" in resp_a.headers.get("Cache-Control", ""), (
        f"Expected no-store in Cache-Control header, got: {resp_a.headers.get('Cache-Control')}"
    )
    assert "attachment" in resp_a.headers.get("Content-Disposition", "")

    print(f"  [PASS] Hospital A Download -> HTTP {resp_a.status_code} ({len(resp_a.content)} bytes, SHA-256 verified)")
    print(f"         Stored Metadata    : Cache-Control={meta_a['cache_control']}")
    print(f"         HTTP Cache-Control : {resp_a.headers.get('Cache-Control')}")
    print(f"         Content-Disposition: {resp_a.headers.get('Content-Disposition')}")
    print(f"  [PASS] Hospital B Download -> HTTP {resp_b.status_code} ({len(resp_b.content)} bytes, SHA-256 verified)")

    # -------------------------------------------------------------------------
    # STEP 4: Cryptographic Tamper-Proofing of x-goog-custom-audit-* Parameters
    # -------------------------------------------------------------------------
    banner(4, "Test Tamper Resistance on x-goog-custom-audit-* Query Parameters")
    tampered_url_a = url_a.replace(
        "uid_stanford_dr_smith_8821", "uid_attacker_spoofed_9999"
    )
    tampered_resp = requests.get(tampered_url_a, timeout=20)
    assert tampered_resp.status_code == 403 and "SignatureDoesNotMatch" in tampered_resp.text, (
        f"Expected 403 SignatureDoesNotMatch, got {tampered_resp.status_code}: {tampered_resp.text}"
    )
    print(
        f"  [PASS] Tampering with x-goog-custom-audit-uid rejected by GCS -> "
        f"HTTP {tampered_resp.status_code} (SignatureDoesNotMatch)"
    )

    # -------------------------------------------------------------------------
    # STEP 5: Instant Per-Hospital KMS Kill Switch (Overrides Unexpired Signed URL)
    # -------------------------------------------------------------------------
    banner(5, "Test Per-Hospital KMS Kill Switch (Disable Hospital A Key While Signed URL Is Active)")
    try:
        t0 = time.time()
        new_state = svc.set_kms_key_enabled(cfg.hospital_a_kms_key_id, enabled=False)
        print(f"  Hospital A KMS Key Version 1 set to: {new_state}")

        blocked_status = None
        blocked_body = ""
        # Note: Cloud KMS key-state changes have up to a ~60s propagation/cache window in GCS.
        for attempt in range(1, 35):
            r_check = requests.get(
                url_a_killswitch, headers={"Connection": "close"}, timeout=20
            )
            if r_check.status_code != 200:
                blocked_status = r_check.status_code
                blocked_body = r_check.text
                elapsed = time.time() - t0
                print(
                    f"  [PASS] Hospital A pre-minted V4 Signed URL revoked in {elapsed:.2f}s -> "
                    f"HTTP {blocked_status} (CloudKmsDisabledKey)"
                )
                break
            if attempt == 1 or attempt % 5 == 0:
                print(
                    f"         Waiting for Cloud KMS ~60s key-state cache propagation ({int(time.time() - t0)}s elapsed)..."
                )
            time.sleep(3)

        assert blocked_status in (400, 403, 412) and "CloudKmsDisabledKey" in blocked_body, (
            f"Expected Hospital A download to fail with CloudKmsDisabledKey, got {blocked_status}: {blocked_body}"
        )

        # Simultaneously verify Hospital B in the SAME bucket is completely unaffected!
        resp_b_during_outage = requests.get(url_b, timeout=30)
        assert resp_b_during_outage.status_code == 200, (
            f"Hospital B should still succeed! Got {resp_b_during_outage.status_code}"
        )
        print(
            f"  [PASS] Tenant Isolation Confirmed: Hospital B's video in the SAME bucket still "
            f"downloads cleanly -> HTTP {resp_b_during_outage.status_code}"
        )
    finally:
        restored_state = svc.set_kms_key_enabled(cfg.hospital_a_kms_key_id, enabled=True)
        print(f"  Hospital A KMS Key Version 1 restored to: {restored_state}")

    # Verify that the exact same Hospital A V4 Signed URL immediately works once KMS is re-enabled
    recovered = False
    for _ in range(10):
        if requests.get(url_a_killswitch, timeout=20).status_code == 200:
            recovered = True
            print("  [PASS] Hospital A V4 Signed URL recovered cleanly after KMS re-enablement -> HTTP 200")
            break
        time.sleep(2)
    assert recovered, "Hospital A Signed URL did not recover after re-enabling KMS key!"

    # -------------------------------------------------------------------------
    # STEP 6: Dual Audit Trail Verification (GCS DATA_READ + KMS Decrypt)
    # -------------------------------------------------------------------------
    banner(6, "Verify Correlated Dual Audit Logs (GCS Custom Audit Tags + KMS Decrypt)")
    print("  Waiting up to 45s for Cloud Audit Logs ingestion...")
    matched_gcs_log = None
    matched_kms_log = None

    for _ in range(9):
        logs = svc.query_dual_audit_logs(lookback_minutes=15, max_entries=40)
        for entry in logs["gcs_data_read"]:
            tags = find_custom_audit_tags(entry["protoPayload"])
            if tags.get("x-goog-custom-audit-uid") == "uid_stanford_dr_smith_8821":
                matched_gcs_log = (entry, tags)
                break

        for entry in logs["kms_decrypt"]:
            res_name = entry["protoPayload"].get("resourceName", "")
            principal = (
                entry["protoPayload"]
                .get("authenticationInfo", {})
                .get("principalEmail", "")
            )
            if "hospital-a-stanford-key" in res_name and principal == cfg.gcs_service_agent:
                matched_kms_log = entry
                break

        if matched_gcs_log and matched_kms_log:
            break
        time.sleep(5)

    assert matched_gcs_log is not None, "Did not find GCS DATA_READ log with x-goog-custom-audit-uid!"
    assert matched_kms_log is not None, "Did not find correlated Cloud KMS Decrypt DATA_READ log!"

    gcs_entry, audit_tags = matched_gcs_log
    caller_ip = (
        gcs_entry["protoPayload"].get("requestMetadata", {}).get("callerIp", "unknown")
    )
    print("  [PASS] GCS DATA_READ Audit Log Verified:")
    print(f"         Timestamp   : {gcs_entry['timestamp']}")
    print(f"         Resource    : {gcs_entry['protoPayload'].get('resourceName')}")
    print(f"         Caller IP   : {caller_ip}")
    print(f"         Custom Audit: {json.dumps(audit_tags, indent=2)}")

    print("  [PASS] Correlated Cloud KMS Decrypt Audit Log Verified:")
    print(f"         Timestamp   : {matched_kms_log['timestamp']}")
    print(f"         KMS Key     : {matched_kms_log['protoPayload'].get('resourceName')}")
    print(
        f"         ServiceAgent: "
        f"{matched_kms_log['protoPayload'].get('authenticationInfo', {}).get('principalEmail')}"
    )

    print(f"\n{'=' * 88}")
    print("ALL 6 HIPAA ARCHITECTURE CHECKS PASSED END-TO-END IN ARGOLIS!")
    print(f"{'=' * 88}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
