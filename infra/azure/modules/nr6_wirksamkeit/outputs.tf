output "compliant_workspace_name" {
  value = azurerm_log_analytics_workspace.compliant.name
}

output "non_compliant_workspace_name" {
  value = azurerm_log_analytics_workspace.non_compliant.name
}
