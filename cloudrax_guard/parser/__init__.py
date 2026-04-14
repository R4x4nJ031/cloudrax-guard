import os
from pathlib import Path
from typing import List, Dict, Any
import hcl2

def clean_value(value):
    """Strip extra quotes and convert strings to proper Python types."""
    if isinstance(value, str):
        # strip surrounding quotes that hcl2 preserves
        value = value.strip('"').strip("'")
        # convert string booleans to real booleans
        if value.lower() == 'true':
            return True
        if value.lower() == 'false':
            return False
        return value
    if isinstance(value, dict):
        return {clean_value(k): clean_value(v) for k, v in value.items()}
    if isinstance(value, list):
        return [clean_value(i) for i in value]
    return value

def find_tf_files(directory: str) -> List[str]:
    """Recursively find all .tf files in a directory."""
    tf_files = []
    for path in Path(directory).rglob("*.tf"):
        tf_files.append(str(path))
    return sorted(tf_files)


def parse_tf_file(filepath: str) -> Dict[str, Any]:
    """Parse a single .tf file into a Python dictionary."""
    with open(filepath, "r") as f:
        return hcl2.load(f)


def extract_resources(parsed: Dict[str, Any], filepath: str) -> List[Dict[str, Any]]:
    resources = []
    resource_list = parsed.get("resource", [])

    for resource_block in resource_list:
        for resource_type, resource_instances in resource_block.items():
            # clean the type name
            clean_type = clean_value(resource_type)
            for resource_name, resource_config in resource_instances.items():
                # clean the name and all config values
                clean_name = clean_value(resource_name)
                clean_config = clean_value(resource_config)
                # remove hcl2 internal key
                clean_config.pop("__is_block__", None)

                resources.append({
                    "type": clean_type,
                    "name": clean_name,
                    "id": f"{clean_type}.{clean_name}",
                    "file": filepath,
                    "config": clean_config
                })

    return resources


def parse_directory(directory: str):
    """Parse all Terraform files in a directory and return raw resources."""
    tf_files = find_tf_files(directory)
    all_resources = []

    for filepath in tf_files:
        parsed = parse_tf_file(filepath)
        resources = extract_resources(parsed, filepath)
        all_resources.extend(resources)

    return tf_files, all_resources
