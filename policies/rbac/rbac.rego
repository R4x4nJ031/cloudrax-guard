package cloudrax.rbac

import rego.v1

# AZU-RBAC-001: Owner role assignment
deny contains finding if {
    resource := input.resources[_]
    resource.type == "azurerm_role_assignment"
    lower(resource.properties.role) == "owner"

    finding := {
        "rule_id": "AZU-RBAC-001",
        "resource": resource.id,
        "file": resource.file,
        "severity": "medium",
        "title": "Owner role assignment detected",
        "message": "Role assignment grants Owner privileges, which can lead to excessive administrative access.",
        "fix": "Replace Owner with a narrower built-in or custom role following least privilege."
    }
}
