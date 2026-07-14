variable "region" {
  description = "AWS region for integration test infrastructure"
  type        = string
  default     = "eu-central-1"
}

variable "run_id" {
  description = "Unique run identifier (GitHub Actions run ID or 'local')"
  type        = string
  default     = "local"
}
