# Shared multi-hospital HIPAA surgical video bucket.
# Per-hospital cryptographic isolation is enforced per object via kmsKeyName metadata
# (hospital-a-stanford-key vs. hospital-b-mayo-key), backed by a bucket-level CMEK fallback.
resource "google_storage_bucket" "surgical_videos" {
  provider      = google.scoped
  project       = google_project.hipaa_poc.project_id
  name          = "${google_project.hipaa_poc.project_id}-davinci-videos"
  location      = var.region
  storage_class = "STANDARD"
  force_destroy = true

  # HIPAA Guardrail: Uniform Bucket-Level Access (disables legacy per-object ACLs)
  uniform_bucket_level_access = true

  # HIPAA Guardrail: Block all public/anonymous bucket policies
  public_access_prevention = "enforced"

  versioning {
    enabled = true
  }

  encryption {
    default_kms_key_name = google_kms_crypto_key.default_fallback_key.id
  }

  labels = {
    data_classification = "ephi"
    hipaa_baa           = "covered"
  }

  depends_on = [time_sleep.wait_for_kms_iam]
}
