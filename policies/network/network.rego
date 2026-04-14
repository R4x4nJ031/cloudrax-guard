package cloudrax.network

import rego.v1

public_sources := {"0.0.0.0/0", "*", "Internet", "internet"}
ssh_ports := {"22", "*"}
rdp_ports := {"3389", "*"}

# AZU-NSG-001: SSH open to the internet
deny contains finding if {
    resource := input.resources[_]
    resource.type == "azurerm_network_security_rule"

    lower(resource.properties.direction) == "inbound"
    lower(resource.properties.access) == "allow"
    resource.properties.source_address in public_sources
    resource.properties.destination_port in ssh_ports

    finding := {
        "rule_id": "AZU-NSG-001",
        "resource": resource.id,
        "file": resource.file,
        "severity": "critical",
        "title": "SSH open to the internet",
        "message": "Network security rule allows inbound SSH access from the public internet.",
        "fix": "Restrict source_address_prefix to trusted IP ranges or remove public SSH access."
    }
}

# AZU-NSG-002: RDP open to the internet
deny contains finding if {
    resource := input.resources[_]
    resource.type == "azurerm_network_security_rule"

    lower(resource.properties.direction) == "inbound"
    lower(resource.properties.access) == "allow"
    resource.properties.source_address in public_sources
    resource.properties.destination_port in rdp_ports

    finding := {
        "rule_id": "AZU-NSG-002",
        "resource": resource.id,
        "file": resource.file,
        "severity": "critical",
        "title": "RDP open to the internet",
        "message": "Network security rule allows inbound RDP access from the public internet.",
        "fix": "Restrict source_address_prefix to trusted IP ranges or remove public RDP access."
    }
}
