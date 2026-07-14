# --- Identity ---
output "account_id" {
  value = data.aws_caller_identity.current.account_id
}

output "region" {
  value = data.aws_region.current.name
}

# --- Nr. 8 Kryptographie ---
output "compliant_s3_bucket" {
  value = module.nr8_kryptographie.compliant_s3_bucket
}

output "non_compliant_s3_bucket" {
  value = module.nr8_kryptographie.non_compliant_s3_bucket
}

output "compliant_ebs_volume_id" {
  value = module.nr8_kryptographie.compliant_ebs_volume_id
}

output "non_compliant_ebs_volume_id" {
  value = module.nr8_kryptographie.non_compliant_ebs_volume_id
}

output "compliant_rds_id" {
  value = module.nr8_kryptographie.compliant_rds_id
}

output "non_compliant_rds_id" {
  value = module.nr8_kryptographie.non_compliant_rds_id
}

output "compliant_kms_key_id" {
  value = module.nr8_kryptographie.compliant_kms_key_id
}

output "non_compliant_kms_key_id" {
  value = module.nr8_kryptographie.non_compliant_kms_key_id
}

output "compliant_alb_arn" {
  value = module.nr8_kryptographie.compliant_alb_arn
}

output "non_compliant_alb_arn" {
  value = module.nr8_kryptographie.non_compliant_alb_arn
}

# --- Nr. 9 Zugriffskontrolle ---
output "iam_user_with_mfa" {
  value = module.nr9_zugriffskontrolle.iam_user_with_mfa
}

output "iam_user_without_mfa" {
  value = module.nr9_zugriffskontrolle.iam_user_without_mfa
}

output "compliant_sg_id" {
  value = module.nr9_zugriffskontrolle.compliant_sg_id
}

output "non_compliant_sg_id" {
  value = module.nr9_zugriffskontrolle.non_compliant_sg_id
}

output "s3_public_access_block_set" {
  value = module.nr9_zugriffskontrolle.s3_public_access_block_set
}

# --- Nr. 9 Zugriffskontrolle (additional) ---
output "non_compliant_iam_policy_arn" {
  value = module.nr9_zugriffskontrolle.non_compliant_iam_policy_arn
}

# --- Nr. 10 MFA & Kommunikation ---
output "iam_console_user_no_mfa" {
  value = module.nr10_mfa_kommunikation.iam_console_user_no_mfa
}

# --- Nr. 1 Risikoanalyse ---
output "compliant_trail_name" {
  value = module.nr1_risikoanalyse.compliant_trail_name
}

output "compliant_trail_arn" {
  value = module.nr1_risikoanalyse.compliant_trail_arn
}

output "non_compliant_trail_name" {
  value = module.nr1_risikoanalyse.non_compliant_trail_name
}

output "non_compliant_trail_arn" {
  value = module.nr1_risikoanalyse.non_compliant_trail_arn
}

# --- Nr. 3 BCM ---
output "compliant_s3_versioning_bucket" {
  value = module.nr3_bcm.compliant_s3_versioning_bucket
}

output "non_compliant_s3_versioning_bucket" {
  value = module.nr3_bcm.non_compliant_s3_versioning_bucket
}

# --- Nr. 2 Vorfallsbewältigung ---
output "alarm_name" {
  value = module.nr2_vorfallsbewaltigung.alarm_name
}

output "alarm_arn" {
  value = module.nr2_vorfallsbewaltigung.alarm_arn
}

# --- Nr. 5 Schwachstellenmanagement ---
output "compliant_ecr_repo_arn" {
  value = module.nr5_schwachstellen.compliant_ecr_repo_arn
}

output "compliant_ecr_repo_name" {
  value = module.nr5_schwachstellen.compliant_ecr_repo_name
}

output "non_compliant_ecr_repo_arn" {
  value = module.nr5_schwachstellen.non_compliant_ecr_repo_arn
}

output "non_compliant_ecr_repo_name" {
  value = module.nr5_schwachstellen.non_compliant_ecr_repo_name
}

# --- Nr. 7 Cyberhygiene ---
output "password_policy_set" {
  value = module.nr7_cyberhygiene.password_policy_set
}

# --- Nr. 3 BCM (additional) ---
output "compliant_object_lock_bucket" {
  value = module.nr3_bcm.compliant_object_lock_bucket
}

output "non_compliant_object_lock_bucket" {
  value = module.nr3_bcm.non_compliant_object_lock_bucket
}

output "compliant_snapshot_volume_id" {
  value = module.nr3_bcm.compliant_snapshot_volume_id
}

output "compliant_snapshot_id" {
  value = module.nr3_bcm.compliant_snapshot_id
}

output "non_compliant_snapshot_volume_id" {
  value = module.nr3_bcm.non_compliant_snapshot_volume_id
}

# --- Nr. 5 Schwachstellenmanagement (additional) ---
output "compliant_lambda_arn" {
  value = module.nr5_schwachstellen.compliant_lambda_arn
}

output "compliant_lambda_name" {
  value = module.nr5_schwachstellen.compliant_lambda_name
}

output "non_compliant_lambda_arn" {
  value = module.nr5_schwachstellen.non_compliant_lambda_arn
}

output "non_compliant_lambda_name" {
  value = module.nr5_schwachstellen.non_compliant_lambda_name
}

# --- Nr. 6 Wirksamkeit ---
output "compliant_log_group_name" {
  value = module.nr6_wirksamkeit.compliant_log_group_name
}

output "compliant_log_group_arn" {
  value = module.nr6_wirksamkeit.compliant_log_group_arn
}

output "non_compliant_log_group_name" {
  value = module.nr6_wirksamkeit.non_compliant_log_group_name
}

output "non_compliant_log_group_arn" {
  value = module.nr6_wirksamkeit.non_compliant_log_group_arn
}
