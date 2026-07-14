###############################################################################
# NR3-003: Geo-Redundant Storage (GRS)
###############################################################################

# Compliant: GRS replication
resource "azurerm_storage_account" "compliant_grs" {
  name                     = "n2sgrs${var.suffix}"
  resource_group_name      = var.resource_group_name
  location                 = var.location
  account_tier             = "Standard"
  account_replication_type = "GRS"

  tags = merge(var.tags, {
    Check = "NR3-003"
    Role  = "compliant"
  })
}

# Non-compliant: LRS only (no geo-redundancy)
resource "azurerm_storage_account" "non_compliant_lrs" {
  name                     = "n2slrs${var.suffix}"
  resource_group_name      = var.resource_group_name
  location                 = var.location
  account_tier             = "Standard"
  account_replication_type = "LRS"

  tags = merge(var.tags, {
    Check = "NR3-003"
    Role  = "non_compliant"
  })
}

###############################################################################
# NR3-006: Immutable Blob Storage
###############################################################################

# Compliant: Storage account with immutable container
resource "azurerm_storage_container" "immutable" {
  name                  = "immutable"
  storage_account_id    = azurerm_storage_account.compliant_grs.id
  container_access_type = "private"
}

resource "azurerm_storage_management_policy" "immutable" {
  storage_account_id = azurerm_storage_account.compliant_grs.id

  rule {
    name    = "immutability"
    enabled = true

    filters {
      prefix_match = ["immutable/"]
      blob_types   = ["blockBlob"]
    }

    actions {
      base_blob {
        delete_after_days_since_modification_greater_than = 365
      }
    }
  }
}
