# ============================================================================
# Nr. 3 — Aufrechterhaltung des Betriebs (Business Continuity)
# ============================================================================
# NR3-001: RDS Backup Retention — uses existing NR8 RDS instances (retention=0)
# NR3-002: S3 Versioning
# ============================================================================

# ---------------------------------------------------------------------------
# NR3-002: S3 Versioning
# ---------------------------------------------------------------------------

# --- Compliant: Versioning enabled ---
resource "aws_s3_bucket" "versioning_compliant" {
  bucket        = "${var.name}-versioning-c-${var.suffix}"
  force_destroy = true

  tags = {
    Name  = "${var.name}-versioning-compliant-${var.suffix}"
    Check = "NR3-002"
    Role  = "compliant"
  }
}

resource "aws_s3_bucket_versioning" "compliant" {
  bucket = aws_s3_bucket.versioning_compliant.id

  versioning_configuration {
    status = "Enabled"
  }
}

# --- Non-compliant: Versioning disabled ---
resource "aws_s3_bucket" "versioning_non_compliant" {
  bucket        = "${var.name}-versioning-nc-${var.suffix}"
  force_destroy = true

  tags = {
    Name  = "${var.name}-versioning-non-compliant-${var.suffix}"
    Check = "NR3-002"
    Role  = "non_compliant"
  }
}

# No versioning configuration = Disabled (non-compliant)

# ---------------------------------------------------------------------------
# NR3-003: S3 Object Lock
# ---------------------------------------------------------------------------

# --- Compliant: Object Lock enabled ---
resource "aws_s3_bucket" "object_lock_compliant" {
  bucket        = "${var.name}-objlock-c-${var.suffix}"
  force_destroy = true

  object_lock_enabled = true

  tags = {
    Name  = "${var.name}-object-lock-compliant-${var.suffix}"
    Check = "NR3-003"
    Role  = "compliant"
  }
}

resource "aws_s3_bucket_object_lock_configuration" "compliant" {
  bucket = aws_s3_bucket.object_lock_compliant.id

  rule {
    default_retention {
      mode = "GOVERNANCE"
      days = 1
    }
  }
}

# --- Non-compliant: No Object Lock ---
# The non-compliant S3 versioning bucket (above) serves double duty:
# it has no Object Lock, which is the non-compliant case for NR3-003.

# ---------------------------------------------------------------------------
# NR3-006: EBS Snapshots (encrypted)
# ---------------------------------------------------------------------------

data "aws_region" "current" {}

# --- Compliant: Encrypted volume with an encrypted snapshot ---
resource "aws_ebs_volume" "snapshot_compliant" {
  availability_zone = "${data.aws_region.current.name}a"
  size              = 1
  encrypted         = true

  tags = {
    Name  = "${var.name}-snap-compliant-${var.suffix}"
    Check = "NR3-006"
    Role  = "compliant"
  }
}

resource "aws_ebs_snapshot" "compliant" {
  volume_id = aws_ebs_volume.snapshot_compliant.id

  tags = {
    Name  = "${var.name}-snap-compliant-${var.suffix}"
    Check = "NR3-006"
    Role  = "compliant"
  }
}

# --- Non-compliant: Volume with NO snapshot ---
resource "aws_ebs_volume" "snapshot_non_compliant" {
  availability_zone = "${data.aws_region.current.name}a"
  size              = 1
  encrypted         = false

  tags = {
    Name  = "${var.name}-snap-nc-${var.suffix}"
    Check = "NR3-006"
    Role  = "non_compliant"
  }
}
