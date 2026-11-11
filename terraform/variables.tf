variable "billing_account" {
  description = "Argolis Billing Account ID (e.g. 012345-6789AB-CDEF01)"
  type        = string
}

variable "org_id" {
  description = "Argolis Organization ID (used when folder_id is empty)"
  type        = string
  default     = ""
}

variable "folder_id" {
  description = "Optional Argolis Folder ID (takes precedence over org_id if non-empty)"
  type        = string
  default     = ""
}

variable "project_prefix" {
  description = "Prefix for the new Argolis test project ID"
  type        = string
  default     = "isrg-hipaa-vid"
}

variable "region" {
  description = "GCP region for Cloud Storage, Cloud KMS, and Cloud Logging vault"
  type        = string
  default     = "us-central1"
}

variable "operator_email" {
  description = "Argolis user email running the PoC (granted TokenCreator on URL signer SA and KMS/Storage admin for testing)"
  type        = string
}

variable "audit_retention_days" {
  description = "Retention period in days for the HIPAA Audit Log Bucket (6 years = 2190 days)"
  type        = number
  default     = 2190
}

variable "lock_audit_bucket" {
  description = "Whether to permanently lock the Cloud Logging bucket retention policy. Keep FALSE in Argolis test projects so the project/bucket can be deleted cleanly; set TRUE in production."
  type        = bool
  default     = false
}
