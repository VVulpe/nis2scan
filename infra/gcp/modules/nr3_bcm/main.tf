# NR3: Business Continuity Management — GCS Buckets

resource "google_storage_bucket" "compliant" {
  name                        = "nis2-nr3-ok-${var.suffix}"
  location                    = var.region
  force_destroy               = true
  uniform_bucket_level_access = true
  labels                      = var.labels

  versioning {
    enabled = true
  }
}

resource "google_storage_bucket" "non_compliant" {
  name                        = "nis2-nr3-bad-${var.suffix}"
  location                    = var.region
  force_destroy               = true
  uniform_bucket_level_access = true
  labels                      = var.labels

  versioning {
    enabled = false
  }
}
