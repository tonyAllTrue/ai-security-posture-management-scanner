# Wrapper around inventory.select_with_scope for LLM endpoints.

from __future__ import annotations
from typing import Dict, List, Tuple
import src.alltrue_scanner.api as api
from src.alltrue_scanner.inventory import select_with_scope


def select_llm_endpoints(jwt: str) -> Tuple[List[str], Dict[str, str], Dict[str, str]]:
    """
    Returns:
        - List of resource IDs
        - Dict mapping resource_id -> resource_name
        - Dict mapping resource_id -> resource_type
    """
    selected_ids, resource_mapping, full_resources = select_with_scope(
        jwt=jwt,
        entity_label="LLM endpoints",
        list_fn=api.list_llm_endpoints,
        dedupe_fn=api.dedupe_resources,
        valid_predicate=lambda r: r.get("has_valid_pentest_connection_details", False),
        pass_valid_only_to_api=True,
        return_full_resources=True,  # Request full resource objects to extract types
    )
    
    # Build resource_type mapping from full resources
    resource_type_mapping = {}
    for r in full_resources:
        rid = r.get("resource_instance_id")
        if rid:
            resource_type_mapping[rid] = r.get("resource_type", "")
    
    return selected_ids, resource_mapping, resource_type_mapping


