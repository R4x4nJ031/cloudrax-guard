resource "azurerm_storage_account" "appdata" {
  name                     = "myappdata"
  resource_group_name      = "my-rg"
  location                 = "eastus"
  account_tier             = "Standard"
  account_replication_type = "LRS"
  allow_blob_public_access = true
  public_network_access_enabled = true
  min_tls_version          = "TLS1_0"
}
