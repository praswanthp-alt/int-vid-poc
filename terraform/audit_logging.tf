# 1. Enable DATA_READ, DATA_WRITE, and ADMIN_READ Audit Logs on Cloud Storage
# Captures storage.objects.get + custom x-goog-custom-audit-* metadata + callerIp
resource "google_project_iam_audit_config" "storage_audit" {
  provider = google.scoped
  project  = google_project.hipaa_poc.project_id
  service  = "storage.googleapis.com"

  audit_log_config {
    log_type = "ADMIN_READ"
  }
  audit_log_config {
    log_type = "DATA_READ"
  }
  audit_log_config {
    log_type = "DATA_WRITE"
  }

  depends_on = [time_sleep.wait_for_apis]
}

# 2. Enable DATA_READ, DATA_WRITE, and ADMIN_READ Audit Logs on Cloud KMS
# Captures CloudKms.Decrypt / Encrypt calls made by the GCS Service Agent per hospital key
resource "google_project_iam_audit_config" "kms_audit" {
  provider = google.scoped
  project  = google_project.hipaa_poc.project_id
  service  = "cloudkms.googleapis.com"

  audit_log_config {
    log_type = "ADMIN_READ"
  }
  audit_log_config {
    log_type = "DATA_READ"
  }
  audit_log_config {
    log_type = "DATA_WRITE"
  }

  depends_on = [time_sleep.wait_for_apis]
}

# 3. Dedicated HIPAA 6-Year (2,190-Day) Regional Cloud Logging Vault
# NOTE: var.lock_audit_bucket defaults to false in Argolis so you can cleanly delete the test project.
# In production, set lock_audit_bucket = true for WORM immutability (45 CFR § 164.316(b)(2)(i)).
resource "google_logging_project_bucket_config" "hipaa_audit_vault" {
  provider       = google.scoped
  project        = google_project.hipaa_poc.project_id
  location       = var.region
  bucket_id      = "hipaa-6yr-audit-vault"
  description    = "HIPAA 6+ year (2190-day) audit log bucket for GCS V4 Signed URL & KMS Decrypt events"
  retention_days = var.audit_retention_days
  locked         = var.lock_audit_bucket

  depends_on = [time_sleep.wait_for_apis]
}

# 4. Log Sink routing all GCS and KMS Admin + Data Access Audit Logs into the 6-year vault
# Note: Same-project Cloud Logging bucket destinations route internally without a separate writer_identity SA.
resource "google_logging_project_sink" "hipaa_dual_audit_sink" {
  provider    = google.scoped
  project     = google_project.hipaa_poc.project_id
  name        = "hipaa-gcs-kms-dual-audit-sink"
  destination = "logging.googleapis.com/projects/${google_project.hipaa_poc.project_id}/locations/${var.region}/buckets/${google_logging_project_bucket_config.hipaa_audit_vault.bucket_id}"
  filter      = <<-EOT
    logName:("cloudaudit.googleapis.com%2Fdata_access" OR "cloudaudit.googleapis.com%2Factivity")
    AND protoPayload.serviceName=("storage.googleapis.com" OR "cloudkms.googleapis.com")
  EOT
}
