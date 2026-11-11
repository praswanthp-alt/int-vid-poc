locals {
  operator_member = "user:${var.operator_email}"
}

# Dedicated, least-privilege Service Account used strictly for keyless V4 URL signing (signBlob).
# Note: Zero Service Account keys are created (compliant with Argolis iam.disableServiceAccountKeyCreation).
resource "google_service_account" "url_signer" {
  provider     = google.scoped
  project      = google_project.hipaa_poc.project_id
  account_id   = "intuitive-url-signer"
  display_name = "Intuitive V4 Signed URL Signer (Keyless signBlob)"
  description  = "Holds strictly storage.objects.get on surgical video bucket; zero KMS permissions."
  depends_on   = [time_sleep.wait_for_apis]
}

# Minimal custom role: ONLY storage.objects.get (cannot even list objects in the bucket!)
resource "google_project_iam_custom_role" "signed_url_object_getter" {
  provider    = google.scoped
  project     = google_project.hipaa_poc.project_id
  role_id     = "intuitiveSignedUrlObjectGetter"
  title       = "Intuitive Signed URL Object Getter"
  description = "Least-privilege role granting only storage.objects.get for V4 Signed URL downloads"
  permissions = ["storage.objects.get"]
  depends_on  = [time_sleep.wait_for_apis]
}

resource "google_storage_bucket_iam_member" "signer_object_getter" {
  provider = google.scoped
  bucket   = google_storage_bucket.surgical_videos.name
  role     = google_project_iam_custom_role.signed_url_object_getter.id
  member   = "serviceAccount:${google_service_account.url_signer.email}"
}

# Allow the PoC operator (or Cloud Run backend SA in prod) to call iam.serviceAccounts.signBlob
resource "google_service_account_iam_member" "operator_token_creator" {
  provider           = google.scoped
  service_account_id = google_service_account.url_signer.name
  role               = "roles/iam.serviceAccountTokenCreator"
  member             = local.operator_member
}

# PoC Operator permissions to simulate:
# 1. Intuitive da Vinci upload ingestion pipeline (uploading videos with per-hospital kmsKeyName)
# 2. Intuitive Security Admin (toggling KMS key state for the Kill Switch test & reading Private Data Access Audit Logs)
resource "google_storage_bucket_iam_member" "operator_ingestion_admin" {
  provider = google.scoped
  bucket   = google_storage_bucket.surgical_videos.name
  role     = "roles/storage.objectAdmin"
  member   = local.operator_member
}

resource "google_project_iam_member" "operator_kms_admin" {
  provider   = google.scoped
  project    = google_project.hipaa_poc.project_id
  role       = "roles/cloudkms.admin"
  member     = local.operator_member
  depends_on = [time_sleep.wait_for_apis]
}

resource "google_project_iam_member" "operator_audit_viewer" {
  provider   = google.scoped
  project    = google_project.hipaa_poc.project_id
  role       = "roles/logging.privateLogViewer"
  member     = local.operator_member
  depends_on = [time_sleep.wait_for_apis]
}
