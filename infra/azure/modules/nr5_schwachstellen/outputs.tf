output "compliant_acr_name" {
  value = azurerm_container_registry.compliant.name
}

output "non_compliant_acr_name" {
  value = azurerm_container_registry.non_compliant.name
}
