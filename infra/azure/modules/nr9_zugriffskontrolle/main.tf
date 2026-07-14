###############################################################################
# NR9-003: NSG Rules — no open inbound from Internet
###############################################################################

# Compliant: Only allow HTTPS from internal range
resource "azurerm_network_security_group" "compliant" {
  name                = "${var.name}-nsg-c-${var.suffix}"
  location            = var.location
  resource_group_name = var.resource_group_name

  security_rule {
    name                       = "AllowHTTPSInternal"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "443"
    source_address_prefix      = "10.0.0.0/8"
    destination_address_prefix = "*"
  }

  tags = merge(var.tags, {
    Check = "NR9-003"
    Role  = "compliant"
  })
}

# Non-compliant: SSH open to the entire internet
resource "azurerm_network_security_group" "non_compliant" {
  name                = "${var.name}-nsg-nc-${var.suffix}"
  location            = var.location
  resource_group_name = var.resource_group_name

  security_rule {
    name                       = "AllowSSHAnywhere"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "22"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }

  tags = merge(var.tags, {
    Check = "NR9-003"
    Role  = "non_compliant"
  })
}

###############################################################################
# NR9-004: Storage Account — Private Access Only
###############################################################################

# Compliant: Public access disabled, default deny
resource "azurerm_storage_account" "compliant" {
  name                          = "n2sprv${var.suffix}"
  resource_group_name           = var.resource_group_name
  location                      = var.location
  account_tier                  = "Standard"
  account_replication_type      = "LRS"
  public_network_access_enabled = false

  network_rules {
    default_action = "Deny"
  }

  tags = merge(var.tags, {
    Check = "NR9-004"
    Role  = "compliant"
  })
}

# Non-compliant: Public access enabled, default allow
resource "azurerm_storage_account" "non_compliant" {
  name                          = "n2spub${var.suffix}"
  resource_group_name           = var.resource_group_name
  location                      = var.location
  account_tier                  = "Standard"
  account_replication_type      = "LRS"
  public_network_access_enabled = true

  network_rules {
    default_action = "Allow"
  }

  tags = merge(var.tags, {
    Check = "NR9-004"
    Role  = "non_compliant"
  })
}
