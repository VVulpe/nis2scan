output "compliant_nsg_name" {
  value = azurerm_network_security_group.compliant.name
}

output "non_compliant_nsg_name" {
  value = azurerm_network_security_group.non_compliant.name
}

output "compliant_storage_account_name" {
  value = azurerm_storage_account.compliant.name
}

output "non_compliant_storage_account_name" {
  value = azurerm_storage_account.non_compliant.name
}
