variable "location" {
  description = "Azure region for integration test infrastructure"
  type        = string
  default     = "westeurope"
}

variable "run_id" {
  description = "Unique run identifier (GitHub Actions run ID or 'local')"
  type        = string
  default     = "local"
}
