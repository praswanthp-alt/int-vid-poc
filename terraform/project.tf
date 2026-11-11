resource "random_id" "suffix" {
  byte_length = 2
}

locals {
  project_id = "${var.project_prefix}-${random_id.suffix.hex}"
  required_apis = toset([
    "cloudresourcemanager.googleapis.com",
    "serviceusage.googleapis.com",
    "iam.googleapis.com",
    "iamcredentials.googleapis.com",
    "cloudkms.googleapis.com",
    "storage.googleapis.com",
    "logging.googleapis.com",
  ])
}

resource "google_project" "hipaa_poc" {
  name            = "Intuitive HIPAA Video PoC"
  project_id      = local.project_id
  billing_account = var.billing_account
  org_id          = var.folder_id == "" && var.org_id != "" ? var.org_id : null
  folder_id       = var.folder_id != "" ? var.folder_id : null
  deletion_policy = "DELETE"

  labels = {
    environment = "poc"
    compliance  = "hipaa-baa"
    architecture = "v4-signed-url-cmek"
  }
}

resource "google_project_service" "apis" {
  for_each           = local.required_apis
  project            = google_project.hipaa_poc.project_id
  service            = each.value
  disable_on_destroy = false
}

# Allow API enablement to propagate globally before provisioning KMS, Storage, and Logging resources
resource "time_sleep" "wait_for_apis" {
  create_duration = "30s"
  depends_on      = [google_project_service.apis]
}
