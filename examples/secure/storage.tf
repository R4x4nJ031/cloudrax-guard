resource "azurerm_storage_account" "appdata" {
  name                           = "mysecureappdata"
  resource_group_name            = "my-rg"
  location                       = "eastus"
  account_tier                   = "Standard"
  account_replication_type       = "LRS"
  allow_blob_public_access       = false
  public_network_access_enabled  = false
  min_tls_version                = "TLS1_2"
}
