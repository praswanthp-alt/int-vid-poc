output "project_id" {
  description = "Newly created Argolis GCP Project ID"
  value       = google_project.hipaa_poc.project_id
}

output "project_number" {
  description = "Newly created Argolis GCP Project Number"
  value       = google_project.hipaa_poc.number
}

output "region" {
  description = "Deployed GCP region"
  value       = var.region
}

output "gcs_service_agent" {
  description = "Cloud Storage Service Agent holding KMS Encrypter/Decrypter permissions"
  value       = data.google_storage_project_service_account.gcs_account.email_address
}

output "video_bucket_name" {
  description = "Shared HIPAA surgical video GCS bucket name"
  value       = google_storage_bucket.surgical_videos.name
}

output "url_signer_sa_email" {
  description = "Keyless V4 Signed URL Service Account (zero KMS roles, only storage.objects.get)"
  value       = google_service_account.url_signer.email
}

output "hospital_a_kms_key_id" {
  description = "Cloud KMS CryptoKey ID for Hospital A (Stanford Health)"
  value       = google_kms_crypto_key.hospital_a_key.id
}

output "hospital_b_kms_key_id" {
  description = "Cloud KMS CryptoKey ID for Hospital B (Mayo Clinic)"
  value       = google_kms_crypto_key.hospital_b_key.id
}

output "default_fallback_kms_key_id" {
  description = "Default fallback Cloud KMS CryptoKey ID on the shared bucket"
  value       = google_kms_crypto_key.default_fallback_key.id
}

output "hipaa_audit_log_bucket" {
  description = "6-year HIPAA Cloud Logging vault resource path"
  value       = google_logging_project_bucket_config.hipaa_audit_vault.id
}
