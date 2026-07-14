# NR8: Kryptographie — KMS Key Ring and Keys

resource "google_kms_key_ring" "test" {
  name     = "nis2-nr8-${var.suffix}"
  location = var.region
}

resource "google_kms_crypto_key" "compliant" {
  name            = "nis2-nr8-ok-${var.suffix}"
  key_ring        = google_kms_key_ring.test.id
  rotation_period = "7776000s" # 90 days
  labels          = var.labels
}

resource "google_kms_crypto_key" "non_compliant" {
  name     = "nis2-nr8-bad-${var.suffix}"
  key_ring = google_kms_key_ring.test.id
  labels   = var.labels
  # No rotation period — non-compliant
}
