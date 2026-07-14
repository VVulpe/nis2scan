variable "project_id" {
  description = "GCP Project ID for integration test infrastructure"
  type        = string
}

variable "region" {
  description = "GCP region"
  type        = string
  default     = "europe-west1"
}

variable "run_id" {
  description = "Unique run identifier (GitHub Actions run ID or 'local')"
  type        = string
  default     = "local"
}
