output "compliant_storage_account_name" {
  value = azurerm_storage_account.compliant.name
}

output "non_compliant_storage_account_name" {
  value = azurerm_storage_account.non_compliant.name
}

output "compliant_keyvault_name" {
  value = azurerm_key_vault.compliant.name
}

output "non_compliant_keyvault_name" {
  value = azurerm_key_vault.non_compliant.name
}

output "compliant_app_name" {
  value = azurerm_linux_web_app.compliant.name
}

output "non_compliant_app_name" {
  value = azurerm_linux_web_app.non_compliant.name
}
