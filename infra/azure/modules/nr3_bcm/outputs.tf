output "compliant_storage_account_name" {
  value = azurerm_storage_account.compliant_grs.name
}

output "non_compliant_storage_account_name" {
  value = azurerm_storage_account.non_compliant_lrs.name
}
