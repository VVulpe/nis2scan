###############################################################################
# NR6-003: Log Retention >= 365 days
###############################################################################

# Compliant: 365-day retention
resource "azurerm_log_analytics_workspace" "compliant" {
  name                = "${var.name}-la-c-${var.suffix}"
  location            = var.location
  resource_group_name = var.resource_group_name
  sku                 = "PerGB2018"
  retention_in_days   = 365

  tags = merge(var.tags, {
    Check = "NR6-003"
    Role  = "compliant"
  })
}

# Non-compliant: 30-day retention (default minimum)
resource "azurerm_log_analytics_workspace" "non_compliant" {
  name                = "${var.name}-la-nc-${var.suffix}"
  location            = var.location
  resource_group_name = var.resource_group_name
  sku                 = "PerGB2018"
  retention_in_days   = 30

  tags = merge(var.tags, {
    Check = "NR6-003"
    Role  = "non_compliant"
  })
}

###############################################################################
# NR6-004: Diagnostic Settings on critical resources
###############################################################################

# A Key Vault WITHOUT diagnostic settings — for the check to flag
resource "azurerm_key_vault" "no_diagnostics" {
  name                       = "n2skvnd${var.suffix}"
  location                   = var.location
  resource_group_name        = var.resource_group_name
  tenant_id                  = data.azurerm_client_config.current.tenant_id
  sku_name                   = "standard"
  soft_delete_retention_days = 7
  purge_protection_enabled   = false

  tags = merge(var.tags, {
    Check = "NR6-004"
    Role  = "non_compliant"
  })
}

data "azurerm_client_config" "current" {}
