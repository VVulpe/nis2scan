###############################################################################
# NR8-001: Storage Account Encryption (CMK preferred)
###############################################################################

# Compliant: Storage with CMK (via Key Vault)
resource "azurerm_key_vault" "compliant" {
  name                       = "n2skvc${var.suffix}"
  location                   = var.location
  resource_group_name        = var.resource_group_name
  tenant_id                  = var.tenant_id
  sku_name                   = "standard"
  soft_delete_retention_days = 7
  purge_protection_enabled   = true

  access_policy {
    tenant_id = var.tenant_id
    object_id = var.object_id

    key_permissions = [
      "Create", "Delete", "Get", "List", "Purge", "Recover",
      "UnwrapKey", "WrapKey", "GetRotationPolicy",
    ]

    secret_permissions = ["Get", "List", "Set", "Delete", "Purge"]
  }

  tags = merge(var.tags, {
    Check = "NR8-004"
    Role  = "compliant"
  })
}

resource "azurerm_key_vault_key" "storage_cmk" {
  name         = "storage-cmk"
  key_vault_id = azurerm_key_vault.compliant.id
  key_type     = "RSA"
  key_size     = 2048
  key_opts     = ["unwrapKey", "wrapKey"]
}

resource "azurerm_storage_account" "compliant" {
  name                     = "n2scmk${var.suffix}"
  resource_group_name      = var.resource_group_name
  location                 = var.location
  account_tier             = "Standard"
  account_replication_type = "LRS"

  identity {
    type = "SystemAssigned"
  }

  tags = merge(var.tags, {
    Check = "NR8-001"
    Role  = "compliant"
  })
}

# Non-compliant: Storage with platform-managed keys only
resource "azurerm_storage_account" "non_compliant" {
  name                     = "n2spmk${var.suffix}"
  resource_group_name      = var.resource_group_name
  location                 = var.location
  account_tier             = "Standard"
  account_replication_type = "LRS"

  tags = merge(var.tags, {
    Check = "NR8-001"
    Role  = "non_compliant"
  })
}

###############################################################################
# NR8-004: Key Vault — soft-delete + purge protection
###############################################################################

# Non-compliant: Key Vault without purge protection
resource "azurerm_key_vault" "non_compliant" {
  name                       = "n2skvnc${var.suffix}"
  location                   = var.location
  resource_group_name        = var.resource_group_name
  tenant_id                  = var.tenant_id
  sku_name                   = "standard"
  soft_delete_retention_days = 7
  purge_protection_enabled   = false

  access_policy {
    tenant_id = var.tenant_id
    object_id = var.object_id

    key_permissions    = ["Get", "List"]
    secret_permissions = ["Get", "List"]
  }

  tags = merge(var.tags, {
    Check = "NR8-004"
    Role  = "non_compliant"
  })
}

###############################################################################
# NR8-005: App Service HTTPS-Only + TLS 1.2
###############################################################################

resource "azurerm_service_plan" "test" {
  name                = "${var.name}-asp-${var.suffix}"
  location            = var.location
  resource_group_name = var.resource_group_name
  os_type             = "Linux"
  sku_name            = "B1"

  tags = var.tags
}

# Compliant: HTTPS-only with TLS 1.2
resource "azurerm_linux_web_app" "compliant" {
  name                = "n2s-app-c-${var.suffix}"
  location            = var.location
  resource_group_name = var.resource_group_name
  service_plan_id     = azurerm_service_plan.test.id
  https_only          = true

  site_config {
    minimum_tls_version = "1.2"
  }

  tags = merge(var.tags, {
    Check = "NR8-005"
    Role  = "compliant"
  })
}

# Non-compliant: HTTP allowed, TLS 1.0
resource "azurerm_linux_web_app" "non_compliant" {
  name                = "n2s-app-nc-${var.suffix}"
  location            = var.location
  resource_group_name = var.resource_group_name
  service_plan_id     = azurerm_service_plan.test.id
  https_only          = false

  site_config {
    minimum_tls_version = "1.0"
  }

  tags = merge(var.tags, {
    Check = "NR8-005"
    Role  = "non_compliant"
  })
}
