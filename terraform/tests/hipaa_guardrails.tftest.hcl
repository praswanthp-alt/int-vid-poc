mock_provider "google" {}

mock_provider "google" {
  alias = "scoped"
}

mock_provider "random" {}
mock_provider "time" {}

variables {
  billing_account      = "012345-6789AB-CDEF01"
  org_id               = "123456789012"
  folder_id            = "987654321098"
  project_prefix       = "isrg-hipaa-vid"
  region               = "us-central1"
  operator_email       = "admin@example.altostrat.com"
  audit_retention_days = 2190
  lock_audit_bucket    = false
}

run "verify_hipaa_storage_and_cmek_guardrails" {
  command = plan

  assert {
    condition     = google_storage_bucket.surgical_videos.uniform_bucket_level_access == true
    error_message = "HIPAA guardrail violation: Uniform Bucket-Level Access (UBLA) must be enabled."
  }

  assert {
    condition     = google_storage_bucket.surgical_videos.public_access_prevention == "enforced"
    error_message = "HIPAA guardrail violation: Public Access Prevention must be enforced."
  }

  assert {
    condition     = google_kms_crypto_key.hospital_a_key.name != google_kms_crypto_key.hospital_b_key.name
    error_message = "Hospital A and Hospital B must have distinct per-hospital KMS CryptoKeys."
  }

  assert {
    condition     = google_kms_crypto_key.hospital_a_key.version_template[0].protection_level == "HSM" && google_kms_crypto_key.hospital_b_key.version_template[0].protection_level == "HSM"
    error_message = "Hospital CMEK keys must use Cloud HSM (FIPS 140-2 Level 3) protection level."
  }
}

run "verify_least_privilege_keyless_url_signer" {
  command = plan

  assert {
    condition     = tolist(google_project_iam_custom_role.signed_url_object_getter.permissions) == tolist(["storage.objects.get"])
    error_message = "URL signer custom role must hold strictly ['storage.objects.get'] and no list/write/KMS permissions."
  }

  assert {
    condition     = google_service_account.url_signer.account_id == "intuitive-url-signer"
    error_message = "Dedicated URL signer service account must be provisioned."
  }
}

run "verify_dual_audit_logs_and_6yr_vault" {
  command = plan

  assert {
    condition     = contains([for c in google_project_iam_audit_config.storage_audit.audit_log_config : c.log_type], "DATA_READ")
    error_message = "DATA_READ audit logging must be enabled on storage.googleapis.com."
  }

  assert {
    condition     = contains([for c in google_project_iam_audit_config.kms_audit.audit_log_config : c.log_type], "DATA_READ")
    error_message = "DATA_READ audit logging must be enabled on cloudkms.googleapis.com."
  }

  assert {
    condition     = google_logging_project_bucket_config.hipaa_audit_vault.retention_days >= 2190
    error_message = "HIPAA audit log vault retention must be at least 2190 days (6 years)."
  }
}
