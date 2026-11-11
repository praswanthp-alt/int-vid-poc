#!/usr/bin/env python3
"""Core service helper for Intuitive Surgical HIPAA V4 Signed URL + CMEK PoC."""

from __future__ import annotations

import datetime
import hashlib
import json
import os
import pathlib
import shutil
import subprocess
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

# Suppress benign macOS gRPC C-core poll-fd info logs after subprocess calls
os.environ.setdefault("GRPC_VERBOSITY", "ERROR")

import google.auth
from google.auth import impersonated_credentials
from google.cloud import kms_v1, logging_v2, storage
from google.protobuf.field_mask_pb2 import FieldMask
from google.protobuf.json_format import MessageToDict

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
TF_DIR = REPO_ROOT / "terraform"


@dataclass
class PocConfig:
    project_id: str
    project_number: str
    region: str
    gcs_service_agent: str
    video_bucket_name: str
    url_signer_sa_email: str
    hospital_a_kms_key_id: str
    hospital_b_kms_key_id: str
    default_fallback_kms_key_id: str
    hipaa_audit_log_bucket: str

    @classmethod
    def from_terraform(cls, tf_dir: pathlib.Path = TF_DIR) -> "PocConfig":
        tf_bin = (
            shutil.which("terraform")
            or ("/opt/homebrew/bin/terraform" if pathlib.Path("/opt/homebrew/bin/terraform").exists() else "terraform")
        )
        proc = subprocess.run(
            [tf_bin, f"-chdir={tf_dir}", "output", "-json"],
            check=True,
            capture_output=True,
            text=True,
        )
        raw = json.loads(proc.stdout)
        val = lambda key: raw[key]["value"]
        return cls(
            project_id=val("project_id"),
            project_number=val("project_number"),
            region=val("region"),
            gcs_service_agent=val("gcs_service_agent"),
            video_bucket_name=val("video_bucket_name"),
            url_signer_sa_email=val("url_signer_sa_email"),
            hospital_a_kms_key_id=val("hospital_a_kms_key_id"),
            hospital_b_kms_key_id=val("hospital_b_kms_key_id"),
            default_fallback_kms_key_id=val("default_fallback_kms_key_id"),
            hipaa_audit_log_bucket=val("hipaa_audit_log_bucket"),
        )


def build_sample_mp4_bytes(session_label: str) -> bytes:
    """Create valid minimal ISO-BMFF (.mp4) container bytes with deterministic session payload."""
    # ftyp box (24 bytes): major_brand=mp42, minor_version=0, compatible_brands=[mp42, isom]
    ftyp = (
        b"\x00\x00\x00\x18"
        b"ftyp"
        b"mp42"
        b"\x00\x00\x00\x00"
        b"mp42isom"
    )
    payload = (
        f"INTUITIVE-DAVINCI-SURGICAL-VIDEO|{session_label}|"
        f"SIMULATED-ENCRYPTED-STREAM|"
    ).encode("utf-8") * 512
    mdat_len = (8 + len(payload)).to_bytes(4, byteorder="big")
    mdat = mdat_len + b"mdat" + payload
    return ftyp + mdat


class HipaaVideoService:
    """Manages CMEK video ingestion, keyless V4 URL signing, KMS kill switch, and audit log queries."""

    def __init__(self, config: PocConfig) -> None:
        self.config = config
        base_creds, _ = google.auth.default(
            scopes=["https://www.googleapis.com/auth/cloud-platform"]
        )
        # Route quota/billing checks directly to the PoC project
        if hasattr(base_creds, "with_quota_project"):
            base_creds = base_creds.with_quota_project(config.project_id)
        self.operator_creds = base_creds

        # Keyless V4 signing credentials via IAM Credentials API (signBlob)
        # Uses intuitive-url-signer SA which ONLY has storage.objects.get (zero KMS roles)
        self.signer_creds = impersonated_credentials.Credentials(
            source_credentials=self.operator_creds,
            target_principal=config.url_signer_sa_email,
            target_scopes=["https://www.googleapis.com/auth/devstorage.read_only"],
            lifetime=900,
        )

        self.storage_admin_client = storage.Client(
            project=config.project_id, credentials=self.operator_creds
        )
        self.storage_signer_client = storage.Client(
            project=config.project_id, credentials=self.signer_creds
        )
        self.kms_client = kms_v1.KeyManagementServiceClient(
            credentials=self.operator_creds
        )
        self.logging_client = logging_v2.Client(
            project=config.project_id, credentials=self.operator_creds
        )

    def upload_surgical_video(
        self,
        object_name: str,
        kms_key_id: str,
        session_id: str,
        tenant_id: str,
    ) -> Dict[str, Any]:
        """Ingest a surgical .mp4 object encrypted under a specific hospital's Cloud KMS key."""
        bucket = self.storage_admin_client.bucket(self.config.video_bucket_name)
        blob = bucket.blob(object_name, kms_key_name=kms_key_id)

        # HIPAA Guardrail: prevent browser or intermediate proxy caching on object metadata
        blob.cache_control = "private, no-store"
        blob.content_type = "video/mp4"
        blob.metadata = {
            "davinci-session-id": session_id,
            "hospital-tenant": tenant_id,
        }

        video_bytes = build_sample_mp4_bytes(f"{tenant_id}:{session_id}")
        sha256_hex = hashlib.sha256(video_bytes).hexdigest()

        blob.upload_from_string(video_bytes, content_type="video/mp4")
        blob.reload()

        return {
            "bucket": self.config.video_bucket_name,
            "object_name": object_name,
            "size_bytes": len(video_bytes),
            "sha256": sha256_hex,
            "kms_key_name": blob.kms_key_name,
            "cache_control": blob.cache_control,
            "generation": blob.generation,
        }

    def generate_download_signed_url(
        self,
        object_name: str,
        user_uid: str,
        tenant_id: str,
        session_id: str,
        ttl_minutes: int = 5,
        download_filename: Optional[str] = None,
    ) -> str:
        """Mint a keyless V4 Signed URL with 4 tamper-proof x-goog-custom-audit-* parameters."""
        if not (1 <= ttl_minutes <= 15):
            raise ValueError("HIPAA guardrail requires short Signed URL TTL (1-15 minutes).")

        filename = download_filename or f"{session_id}.mp4"
        bucket = self.storage_signer_client.bucket(self.config.video_bucket_name)
        blob = bucket.blob(object_name)

        # All query parameters below are included in the V4 CanonicalQueryString and signed:
        # altering or stripping any parameter invalidates X-Goog-Signature (403 SignatureDoesNotMatch).
        signed_query_params = {
            "response-cache-control": "private, no-store",
            "x-goog-custom-audit-uid": user_uid,
            "x-goog-custom-audit-tenant": tenant_id,
            "x-goog-custom-audit-session": session_id,
            "x-goog-custom-audit-action": "download",
        }

        return blob.generate_signed_url(
            version="v4",
            expiration=datetime.timedelta(minutes=ttl_minutes),
            method="GET",
            credentials=self.signer_creds,
            response_disposition=f'attachment; filename="{filename}"',
            response_type="video/mp4",
            query_parameters=signed_query_params,
        )

    def set_kms_key_enabled(self, crypto_key_id: str, enabled: bool, version: int = 1) -> str:
        """Toggle a hospital's Cloud KMS CryptoKeyVersion between ENABLED and DISABLED (Kill Switch)."""
        version_name = f"{crypto_key_id}/cryptoKeyVersions/{version}"
        target_state = (
            kms_v1.CryptoKeyVersion.CryptoKeyVersionState.ENABLED
            if enabled
            else kms_v1.CryptoKeyVersion.CryptoKeyVersionState.DISABLED
        )
        updated = self.kms_client.update_crypto_key_version(
            request={
                "crypto_key_version": {
                    "name": version_name,
                    "state": target_state,
                },
                "update_mask": FieldMask(paths=["state"]),
            }
        )
        return updated.state.name

    def get_kms_key_state(self, crypto_key_id: str, version: int = 1) -> str:
        version_name = f"{crypto_key_id}/cryptoKeyVersions/{version}"
        ckv = self.kms_client.get_crypto_key_version(name=version_name)
        return ckv.state.name

    def query_dual_audit_logs(
        self, lookback_minutes: int = 20, max_entries: int = 30
    ) -> Dict[str, List[Dict[str, Any]]]:
        """Fetch correlated GCS DATA_READ logs (with x-goog-custom-audit-*) and KMS Decrypt logs."""
        since = (
            datetime.datetime.now(datetime.timezone.utc)
            - datetime.timedelta(minutes=lookback_minutes)
        ).strftime("%Y-%m-%dT%H:%M:%SZ")

        gcs_filter = (
            f'logName="projects/{self.config.project_id}/logs/cloudaudit.googleapis.com%2Fdata_access" '
            f'AND protoPayload.serviceName="storage.googleapis.com" '
            f'AND protoPayload.methodName="storage.objects.get" '
            f'AND timestamp>="{since}"'
        )
        kms_filter = (
            f'logName="projects/{self.config.project_id}/logs/cloudaudit.googleapis.com%2Fdata_access" '
            f'AND protoPayload.serviceName="cloudkms.googleapis.com" '
            f'AND protoPayload.methodName:"Decrypt" '
            f'AND timestamp>="{since}"'
        )

        def collect(flt: str) -> List[Dict[str, Any]]:
            results: List[Dict[str, Any]] = []
            for entry in self.logging_client.list_entries(
                filter_=flt, order_by=logging_v2.DESCENDING, page_size=max_entries
            ):
                payload = entry.payload
                if hasattr(payload, "_pb"):
                    payload = MessageToDict(payload._pb)
                elif not isinstance(payload, dict):
                    payload = {"raw": str(payload)}
                results.append(
                    {
                        "timestamp": entry.timestamp.isoformat() if entry.timestamp else None,
                        "log_name": entry.log_name,
                        "protoPayload": payload,
                    }
                )
                if len(results) >= max_entries:
                    break
            return results

        return {
            "gcs_data_read": collect(gcs_filter),
            "kms_decrypt": collect(kms_filter),
        }
