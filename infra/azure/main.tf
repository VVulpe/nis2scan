# ============================================================================
# nis2scan — Integration Test Infrastructure (Azure)
# ============================================================================
# Creates compliant AND non-compliant resources for each implemented check.
# Designed to be created and destroyed within a single CI pipeline run.
# ============================================================================

# --- Random suffix for unique resource names ---
resource "random_id" "suffix" {
  byte_length = 4
}

locals {
  suffix = random_id.suffix.hex
  name   = "nis2scan-${local.suffix}"
  tags = {
    Project     = "nis2scan"
    Environment = "integration-test"
    RunId       = var.run_id
    ManagedBy   = "terraform"
  }
}

# --- Identity ---
data "azurerm_client_config" "current" {}
data "azurerm_subscription" "current" {}

# --- Shared Resource Group ---
resource "azurerm_resource_group" "test" {
  name     = "${local.name}-rg"
  location = var.location
  tags     = local.tags
}

# --- Shared VNet for network-dependent resources ---
resource "azurerm_virtual_network" "test" {
  name                = "${local.name}-vnet"
  location            = azurerm_resource_group.test.location
  resource_group_name = azurerm_resource_group.test.name
  address_space       = ["10.0.0.0/16"]
  tags                = local.tags
}

resource "azurerm_subnet" "default" {
  name                 = "default"
  resource_group_name  = azurerm_resource_group.test.name
  virtual_network_name = azurerm_virtual_network.test.name
  address_prefixes     = ["10.0.1.0/24"]
}

resource "azurerm_subnet" "secondary" {
  name                 = "secondary"
  resource_group_name  = azurerm_resource_group.test.name
  virtual_network_name = azurerm_virtual_network.test.name
  address_prefixes     = ["10.0.2.0/24"]
}

# --- Module: Nr. 3 Aufrechterhaltung des Betriebs (BCM) ---
module "nr3_bcm" {
  source = "./modules/nr3_bcm"

  suffix              = local.suffix
  name                = local.name
  resource_group_name = azurerm_resource_group.test.name
  location            = azurerm_resource_group.test.location
  tags                = local.tags
}

# --- Module: Nr. 8 Kryptographie ---
module "nr8_kryptographie" {
  source = "./modules/nr8_kryptographie"

  suffix              = local.suffix
  name                = local.name
  resource_group_name = azurerm_resource_group.test.name
  location            = azurerm_resource_group.test.location
  subnet_id           = azurerm_subnet.default.id
  tenant_id           = data.azurerm_client_config.current.tenant_id
  object_id           = data.azurerm_client_config.current.object_id
  tags                = local.tags
}

# --- Module: Nr. 9 Zugriffskontrolle ---
module "nr9_zugriffskontrolle" {
  source = "./modules/nr9_zugriffskontrolle"

  suffix              = local.suffix
  name                = local.name
  resource_group_name = azurerm_resource_group.test.name
  location            = azurerm_resource_group.test.location
  vnet_id             = azurerm_virtual_network.test.id
  tags                = local.tags
}

# --- Module: Nr. 5 Schwachstellen ---
module "nr5_schwachstellen" {
  source = "./modules/nr5_schwachstellen"

  suffix              = local.suffix
  name                = local.name
  resource_group_name = azurerm_resource_group.test.name
  location            = azurerm_resource_group.test.location
  tags                = local.tags
}

# --- Module: Nr. 6 Wirksamkeit ---
module "nr6_wirksamkeit" {
  source = "./modules/nr6_wirksamkeit"

  suffix              = local.suffix
  name                = local.name
  resource_group_name = azurerm_resource_group.test.name
  location            = azurerm_resource_group.test.location
  tags                = local.tags
}
