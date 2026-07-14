###############################################################################
# NR5-003: Container Registry Image Scan
###############################################################################

# Compliant: Standard SKU (supports scanning)
resource "azurerm_container_registry" "compliant" {
  name                = "n2sacrc${var.suffix}"
  resource_group_name = var.resource_group_name
  location            = var.location
  sku                 = "Standard"

  tags = merge(var.tags, {
    Check = "NR5-003"
    Role  = "compliant"
  })
}

# Non-compliant: Basic SKU (limited scanning)
resource "azurerm_container_registry" "non_compliant" {
  name                = "n2sacrnc${var.suffix}"
  resource_group_name = var.resource_group_name
  location            = var.location
  sku                 = "Basic"

  tags = merge(var.tags, {
    Check = "NR5-003"
    Role  = "non_compliant"
  })
}
