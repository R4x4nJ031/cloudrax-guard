from typing import List, Dict, Any


def normalize_storage_account(resource: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize azurerm_storage_account into clean security-relevant properties."""
    config = resource["config"]

    return {
        "id": resource["id"],
        "type": resource["type"],
        "file": resource["file"],
        "properties": {
            "public_blob_access": config.get("allow_blob_public_access", False),
            "public_network_access": config.get("public_network_access_enabled", True),
            "encryption_enabled": config.get("enable_https_traffic_only", True),
            "diagnostic_settings_enabled": config.get("diagnostic_settings_enabled", False),
            "min_tls_version": config.get("min_tls_version", "TLS1_0"),
        }
    }


def normalize_nsg_rule(resource: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize azurerm_network_security_rule into clean security-relevant properties."""
    config = resource["config"]

    return {
        "id": resource["id"],
        "type": resource["type"],
        "file": resource["file"],
        "properties": {
            "direction": config.get("direction", ""),
            "access": config.get("access", ""),
            "protocol": config.get("protocol", ""),
            "source_address": config.get("source_address_prefix", ""),
            "destination_port": config.get("destination_port_range", ""),
        }
    }


def normalize_role_assignment(resource: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize azurerm_role_assignment into clean security-relevant properties."""
    config = resource["config"]

    return {
        "id": resource["id"],
        "type": resource["type"],
        "file": resource["file"],
        "properties": {
            "role": config.get("role_definition_name", ""),
            "scope": config.get("scope", ""),
        }
    }


def normalize_diagnostic_setting(resource: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize azurerm_monitor_diagnostic_setting."""
    config = resource["config"]

    return {
        "id": resource["id"],
        "type": resource["type"],
        "file": resource["file"],
        "properties": {
            "target_resource": config.get("target_resource_id", ""),
            "log_analytics_workspace": config.get("log_analytics_workspace_id", ""),
        }
    }


# Registry — maps resource type to its normalizer function
NORMALIZERS = {
    "azurerm_storage_account": normalize_storage_account,
    "azurerm_network_security_rule": normalize_nsg_rule,
    "azurerm_role_assignment": normalize_role_assignment,
    "azurerm_monitor_diagnostic_setting": normalize_diagnostic_setting,
}


def normalize_resources(raw_resources: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Normalize all parsed resources. Skip unsupported types."""
    normalized = []

    for resource in raw_resources:
        resource_type = resource["type"]
        normalizer_fn = NORMALIZERS.get(resource_type)

        if normalizer_fn:
            normalized.append(normalizer_fn(resource))
        else:
            # unsupported type — skip silently for now
            pass

    return normalized