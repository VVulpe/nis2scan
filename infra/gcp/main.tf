resource "random_id" "suffix" {
  byte_length = 4
}

locals {
  suffix = random_id.suffix.hex
  name   = "nis2scan"
  labels = {
    project     = "nis2scan"
    environment = "integration-test"
    run-id      = var.run_id
    managed-by  = "terraform"
  }
}

# ---------- NR3: Business Continuity Management ----------

module "nr3_bcm" {
  source = "./modules/nr3_bcm"

  project_id = var.project_id
  region     = var.region
  suffix     = local.suffix
  labels     = local.labels
}

# ---------- NR8: Kryptographie ----------

module "nr8_kryptographie" {
  source = "./modules/nr8_kryptographie"

  project_id = var.project_id
  region     = var.region
  suffix     = local.suffix
  labels     = local.labels
}

# ---------- NR9: Zugriffskontrolle ----------

module "nr9_zugriffskontrolle" {
  source = "./modules/nr9_zugriffskontrolle"

  project_id = var.project_id
  region     = var.region
  suffix     = local.suffix
  labels     = local.labels
}
