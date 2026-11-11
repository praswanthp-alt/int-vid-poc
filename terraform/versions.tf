terraform {
  required_version = ">= 1.5.0"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = ">= 5.30.0, < 7.0.0"
    }
    random = {
      source  = "hashicorp/random"
      version = ">= 3.5.0"
    }
    time = {
      source  = "hashicorp/time"
      version = ">= 0.9.0"
    }
  }
}

# Bootstrap provider: used to create the Argolis project and enable initial APIs
# without sending X-Goog-User-Project against a brand-new project before Service Usage is active.
provider "google" {
  region                = var.region
  user_project_override = false
}

# Project-scoped provider: routes quota/billing checks (needed for KMS & Logging with user ADC)
# directly to the newly created PoC project once APIs are enabled.
provider "google" {
  alias                 = "scoped"
  project               = google_project.hipaa_poc.project_id
  region                = var.region
  billing_project       = google_project.hipaa_poc.project_id
  user_project_override = true
}
