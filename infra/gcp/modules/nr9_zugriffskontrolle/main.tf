# NR9: Zugriffskontrolle — VPC and Firewall Rules

resource "google_compute_network" "test" {
  name                    = "nis2-nr9-${var.suffix}"
  auto_create_subnetworks = false
  project                 = var.project_id
}

resource "google_compute_firewall" "compliant" {
  name    = "nis2-nr9-ok-${var.suffix}"
  network = google_compute_network.test.name
  project = var.project_id

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }

  source_ranges = ["10.0.0.0/8"] # Restricted — compliant
}

resource "google_compute_firewall" "non_compliant" {
  name    = "nis2-nr9-bad-${var.suffix}"
  network = google_compute_network.test.name
  project = var.project_id

  allow {
    protocol = "tcp"
    ports    = ["22"]
  }

  source_ranges = ["0.0.0.0/0"] # Open to world — non-compliant
}
