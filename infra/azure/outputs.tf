# --- Identity ---
output "subscription_id" {
  value = data.azurerm_subscription.current.subscription_id
}

output "tenant_id" {
  value = data.azurerm_client_config.current.tenant_id
}

output "resource_group_name" {
  value = azurerm_resource_group.test.name
}

# --- Nr. 3 BCM ---
output "compliant_storage_account_grs" {
  value = module.nr3_bcm.compliant_storage_account_name
}

output "non_compliant_storage_account_lrs" {
  value = module.nr3_bcm.non_compliant_storage_account_name
}

# --- Nr. 8 Kryptographie ---
output "compliant_storage_account_cmk" {
  value = module.nr8_kryptographie.compliant_storage_account_name
}

output "non_compliant_storage_account_pmk" {
  value = module.nr8_kryptographie.non_compliant_storage_account_name
}

output "compliant_keyvault_name" {
  value = module.nr8_kryptographie.compliant_keyvault_name
}

output "non_compliant_keyvault_name" {
  value = module.nr8_kryptographie.non_compliant_keyvault_name
}

# --- Nr. 9 Zugriffskontrolle ---
output "compliant_nsg_name" {
  value = module.nr9_zugriffskontrolle.compliant_nsg_name
}

output "non_compliant_nsg_name" {
  value = module.nr9_zugriffskontrolle.non_compliant_nsg_name
}

output "compliant_storage_private" {
  value = module.nr9_zugriffskontrolle.compliant_storage_account_name
}

output "non_compliant_storage_public" {
  value = module.nr9_zugriffskontrolle.non_compliant_storage_account_name
}

# --- Nr. 5 Schwachstellen ---
output "compliant_acr_name" {
  value = module.nr5_schwachstellen.compliant_acr_name
}

output "non_compliant_acr_name" {
  value = module.nr5_schwachstellen.non_compliant_acr_name
}

# --- Nr. 6 Wirksamkeit ---
output "compliant_log_analytics_name" {
  value = module.nr6_wirksamkeit.compliant_workspace_name
}

output "non_compliant_log_analytics_name" {
  value = module.nr6_wirksamkeit.non_compliant_workspace_name
}
