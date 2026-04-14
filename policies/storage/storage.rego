package cloudrax.storage

import rego.v1

# AZU-STOR-001: Public blob access enabled
deny contains finding if {
    resource := input.resources[_]
    resource.type == "azurerm_storage_account"
    resource.properties.public_blob_access == true

    finding := {
        "rule_id": "AZU-STOR-001",
        "resource": resource.id,
        "file": resource.file,
        "severity": "critical",
        "title": "Public blob access enabled",
        "message": "Storage account allows public blob access which can expose sensitive data to the internet.",
        "fix": "Set allow_blob_public_access = false in your azurerm_storage_account block."
    }
}

# AZU-STOR-002: Public network access enabled
deny contains finding if {
    resource := input.resources[_]
    resource.type == "azurerm_storage_account"
    resource.properties.public_network_access == true

    finding := {
        "rule_id": "AZU-STOR-002",
        "resource": resource.id,
        "file": resource.file,
        "severity": "medium",
        "title": "Public network access enabled on storage account",
        "message": "Storage account is accessible from public networks.",
        "fix": "Set public_network_access_enabled = false and use private endpoints."
    }
}

# AZU-STOR-003: Weak TLS version
deny contains finding if {
    resource := input.resources[_]
    resource.type == "azurerm_storage_account"
    resource.properties.min_tls_version == "TLS1_0"

    finding := {
        "rule_id": "AZU-STOR-003",
        "resource": resource.id,
        "file": resource.file,
        "severity": "medium",
        "title": "Weak TLS version on storage account",
        "message": "Storage account allows TLS 1.0 which is deprecated and insecure.",
        "fix": "Set min_tls_version = TLS1_2 in your azurerm_storage_account block."
    }
}