# Provision / fetch the Google-managed Cloud Storage Service Agent:
# service-<PROJECT_NUMBER>@gs-project-accounts.iam.gserviceaccount.com
data "google_storage_project_service_account" "gcs_account" {
  provider   = google.scoped
  project    = google_project.hipaa_poc.project_id
  depends_on = [time_sleep.wait_for_apis]
}

resource "google_kms_key_ring" "surgical_video_ring" {
  provider   = google.scoped
  project    = google_project.hipaa_poc.project_id
  name       = "davinci-hospital-cmek-ring-${random_id.suffix.hex}"
  location   = var.region
  depends_on = [time_sleep.wait_for_apis]
}

# Fallback default CMEK key for the shared bucket (ensures no object ever defaults to GMEK)
# Uses Cloud HSM (FIPS 140-2 Level 3) + AES-256-GCM to satisfy HIPAA & strict enterprise Org Policies
resource "google_kms_crypto_key" "default_fallback_key" {
  provider                   = google.scoped
  name                       = "intuitive-default-fallback-key"
  key_ring                   = google_kms_key_ring.surgical_video_ring.id
  purpose                    = "ENCRYPT_DECRYPT"
  rotation_period            = "7776000s" # 90 days
  destroy_scheduled_duration = "86400s"   # 24h minimum scheduled destruction window

  version_template {
    algorithm        = "GOOGLE_SYMMETRIC_ENCRYPTION"
    protection_level = "HSM"
  }
}

# Per-Hospital Key A: Stanford Health (Cloud HSM AES-256-GCM)
resource "google_kms_crypto_key" "hospital_a_key" {
  provider                   = google.scoped
  name                       = "hospital-a-stanford-key"
  key_ring                   = google_kms_key_ring.surgical_video_ring.id
  purpose                    = "ENCRYPT_DECRYPT"
  rotation_period            = "7776000s"
  destroy_scheduled_duration = "86400s"

  version_template {
    algorithm        = "GOOGLE_SYMMETRIC_ENCRYPTION"
    protection_level = "HSM"
  }

  labels = {
    tenant = "hosp-stanford"
  }
}

# Per-Hospital Key B: Mayo Clinic (Cloud HSM AES-256-GCM)
resource "google_kms_crypto_key" "hospital_b_key" {
  provider                   = google.scoped
  name                       = "hospital-b-mayo-key"
  key_ring                   = google_kms_key_ring.surgical_video_ring.id
  purpose                    = "ENCRYPT_DECRYPT"
  rotation_period            = "7776000s"
  destroy_scheduled_duration = "86400s"

  version_template {
    algorithm        = "GOOGLE_SYMMETRIC_ENCRYPTION"
    protection_level = "HSM"
  }

  labels = {
    tenant = "hosp-mayo"
  }
}

# ONLY the GCS Service Agent gets Encrypter/Decrypter on the KMS keys.
# Neither the Signed-URL Service Account nor hospital end users receive any KMS permissions.
resource "google_kms_crypto_key_iam_member" "gcs_default_key" {
  provider      = google.scoped
  crypto_key_id = google_kms_crypto_key.default_fallback_key.id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = data.google_storage_project_service_account.gcs_account.member
}

resource "google_kms_crypto_key_iam_member" "gcs_hospital_a_key" {
  provider      = google.scoped
  crypto_key_id = google_kms_crypto_key.hospital_a_key.id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = data.google_storage_project_service_account.gcs_account.member
}

resource "google_kms_crypto_key_iam_member" "gcs_hospital_b_key" {
  provider      = google.scoped
  crypto_key_id = google_kms_crypto_key.hospital_b_key.id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = data.google_storage_project_service_account.gcs_account.member
}

resource "time_sleep" "wait_for_kms_iam" {
  create_duration = "15s"
  depends_on = [
    google_kms_crypto_key_iam_member.gcs_default_key,
    google_kms_crypto_key_iam_member.gcs_hospital_a_key,
    google_kms_crypto_key_iam_member.gcs_hospital_b_key,
  ]
}
