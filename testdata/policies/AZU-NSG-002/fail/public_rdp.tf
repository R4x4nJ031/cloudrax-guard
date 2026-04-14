resource "azurerm_network_security_rule" "public_rdp" {
  name                        = "public-rdp"
  priority                    = 110
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "3389"
  source_address_prefix       = "0.0.0.0/0"
  destination_address_prefix  = "*"
  resource_group_name         = "my-rg"
  network_security_group_name = "my-nsg"
}
