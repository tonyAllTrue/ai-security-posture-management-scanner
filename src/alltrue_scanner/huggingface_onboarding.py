# HuggingFace model onboarding functionality
# Adds HuggingFace models to inventory before scanning

from __future__ import annotations
from typing import Any, Dict, List
import time

import requests

import src.alltrue_scanner.api as api
import src.alltrue_scanner.config as config


def _verify_onboarded_resources(
    jwt: str,
    requested_resources: List[dict],
    project_id: str
) -> List[str]:
    """
    Check inventory for recently onboarded resources after a 504 timeout.
    
    When the onboarding API times out (504), the resources may still have been
    created on the backend. This function queries inventory to verify if they exist.
    
    Args:
        jwt: JWT authentication token
        requested_resources: List of resource configs that were submitted
        project_id: Project ID where resources should exist
        
    Returns:
        List of resource_instance_ids for resources found in inventory
    """
    try:
        print(f"[HF-Onboard] Querying inventory for {len(requested_resources)} model(s)...")
        
        # Get recent model resources in the project
        # Use model and model_assets categories to catch all HuggingFace models
        recent_models = api.list_resources(
            jwt,
            categories=["model", "model_assets"],
            project_id=project_id,
        )
        
        print(f"[HF-Onboard] Found {len(recent_models)} total model(s) in project inventory")
        
        resource_ids = []
        resource_name_map = {r["display_name"]: r for r in requested_resources}
        
        # Match by display_name (exact match)
        for req_display_name, req_config in resource_name_map.items():
            for model in recent_models:
                model_display_name = model.get("display_name", "")
                
                # Exact match on display name
                if model_display_name == req_display_name:
                    rid = model.get("resource_instance_id")
                    if rid:
                        resource_ids.append(rid)
                        print(f"[HF-Onboard] OK Verified: {req_display_name}")
                        print(f"              Resource ID: {rid}")
                        break
        
        if not resource_ids:
            print(f"[HF-Onboard] [!]  No matching resources found in inventory")
        
        return resource_ids
        
    except Exception as e:
        print(f"[HF-Onboard] [!]  Error verifying resources: {e}")
        return []


def onboard_huggingface_models(jwt: str, models: List[Dict[str, Any]], project_id: str) -> List[str]:
    """
    Onboard one or more HuggingFace models to inventory.

    Args:
        jwt: JWT authentication token
        models: List of model configs, each containing:
            - organization_id: HuggingFace organization/user (e.g., "IHasFarms")
            - repo_name: HuggingFace repository name (e.g., "MaliciousModel")
            - revision: Git revision (default: "main")
            - display_name: Optional custom display name
        project_id: Project ID to associate models with

    Returns:
        List of resource instance IDs for the onboarded models
    """
    if not models:
        print("[HF-Onboard] No models to onboard")
        return []

    print(f"\n{'='*80}")
    print(f"ONBOARDING {len(models)} HUGGINGFACE MODEL(S) TO INVENTORY")
    print(f"{'='*80}")

    # Build the resources payload
    resources = []
    for model in models:
        org_id = model.get("organization_id")
        repo_name = model.get("repo_name")
        revision = model.get("revision", "main")
        display_name = model.get("display_name")

        if not org_id or not repo_name:
            print(f"[HF-Onboard] [!]  Skipping model: missing organization_id or repo_name")
            continue

        # Auto-generate display name if not provided
        if not display_name:
            display_name = f"{org_id}/{repo_name}"

        print(f"[HF-Onboard] Preparing: {display_name} (revision: {revision})")

        resources.append({
            "display_name": display_name,
            "cloud_provider_account_id": None,
            "resource_type": "ModelPackage",
            "resource_data": {
                "storage_source": "HUGGINGFACE",
                "credentials": {
                    "revision": revision,
                    "organization_id": org_id,
                    "repo_name": repo_name,
                    "storage_source": "HUGGINGFACE"
                }
            },
            "technology_types": ["ModelPackage"],
            "project_ids": [project_id],
            "reviewed": "approved"
        })

    if not resources:
        print("[HF-Onboard] No valid models to onboard")
        return []

    # Make the API request
    endpoint = "/v1/inventory/resources"
    params = {"resource_source_type": "MANUAL_UPLOAD"}
    data = {
        "resources": resources,
        "cloud_provider_account_id": None,
        "region": None
    }

    try:
        print(f"[HF-Onboard] Calling inventory API to onboard {len(resources)} model(s)...")
        response = api.make_api_request(
            endpoint,
            token=jwt,
            method="POST",
            data=data,
            params=params,
            timeout=60,
        )
        
        # Parse JSON response
        response_data = response.json()
        
        # API returns: {"num_resources_added": N, "added_resources": [{resource_instance_id, resource_identifier}, ...]}
        added_resources = response_data.get("added_resources", [])
        resource_ids = []
        
        # Build a map of resource_identifier to display_name for better logging
        resource_name_map = {r["resource_data"]["credentials"]["repo_name"]: r["display_name"] for r in resources}
        
        for res in added_resources:
            res_id = res.get("resource_instance_id")
            res_identifier = res.get("resource_identifier", "")
            
            # Try to find a friendly name from our original request
            res_name = "Unknown"
            for repo_name, display_name in resource_name_map.items():
                if repo_name in res_identifier:
                    res_name = display_name
                    break
            
            if res_id:
                resource_ids.append(res_id)
                print(f"[HF-Onboard] OK Onboarded: {res_name}")
                print(f"              Resource ID: {res_id}")
            else:
                print(f"[HF-Onboard] [!]  No resource_instance_id returned for: {res_identifier}")

        if resource_ids:
            print(f"\n[HF-Onboard] Successfully onboarded {len(resource_ids)} model(s)")

            # Wait a moment for resources to be fully indexed
            if config.HUGGINGFACE_ONBOARDING_WAIT_SECS > 0:
                print(f"[HF-Onboard] Waiting {config.HUGGINGFACE_ONBOARDING_WAIT_SECS}s for indexing...")
                time.sleep(config.HUGGINGFACE_ONBOARDING_WAIT_SECS)

        return resource_ids
        
    except requests.HTTPError as e:
        # Handle 504 Gateway Timeout - resources may have been created despite timeout
        if e.response.status_code == 504:
            print(f"[HF-Onboard] [TIMEOUT]  Gateway timeout (504) - resource creation may have succeeded")
            print(f"[HF-Onboard] Waiting 10s for backend to complete processing...")
            time.sleep(10)
            
            # Query inventory to verify if resources were actually created
            resource_ids = _verify_onboarded_resources(jwt, resources, project_id)
            
            if resource_ids:
                print(f"\n[HF-Onboard] OK Successfully verified {len(resource_ids)} model(s) were created despite timeout")
                
                # Wait for indexing as we would normally
                if config.HUGGINGFACE_ONBOARDING_WAIT_SECS > 0:
                    print(f"[HF-Onboard] Waiting {config.HUGGINGFACE_ONBOARDING_WAIT_SECS}s for indexing...")
                    time.sleep(config.HUGGINGFACE_ONBOARDING_WAIT_SECS)
                
                return resource_ids
            else:
                print(f"[HF-Onboard] X Gateway timeout and resources not found in inventory")
                print(f"[HF-Onboard]    This may indicate the backend failed to create the resources")
                return []
        else:
            # Other HTTP errors - print and return empty
            print(f"[HF-Onboard] X Error onboarding models: {e}")
            return []
            
    except Exception as e:
        print(f"[HF-Onboard] X Error onboarding models: {e}")
        return []


def parse_huggingface_models_from_config() -> List[Dict[str, Any]]:
    """
    Parse HuggingFace model specifications from config.

    Supports two formats:
    1. Simple format (comma-separated): "org1/repo1,org2/repo2"
    2. JSON format with full details: '[{"organization_id":"org1","repo_name":"repo1","revision":"main"}]'

    Returns:
        List of model config dicts
    """
    models_str = config.HUGGINGFACE_MODELS_TO_ONBOARD
    if not models_str:
        return []

    models = []

    # Try to parse as JSON first (full format)
    try:
        import json
        parsed = json.loads(models_str)
        if isinstance(parsed, list):
            return parsed
        elif isinstance(parsed, dict):
            return [parsed]
    except (json.JSONDecodeError, ValueError):
        pass

    # Parse simple format: "org/repo,org/repo"
    for item in models_str.split(","):
        item = item.strip()
        if not item:
            continue

        if "/" in item:
            parts = item.split("/", 1)
            org_id = parts[0].strip()
            repo_name = parts[1].strip()

            # Handle optional @revision suffix
            revision = "main"
            if "@" in repo_name:
                repo_name, revision = repo_name.split("@", 1)
                repo_name = repo_name.strip()
                revision = revision.strip()

            models.append({
                "organization_id": org_id,
                "repo_name": repo_name,
                "revision": revision,
            })
        else:
            print(f"[HF-Parse] [!]  Invalid model format: '{item}' (expected 'org/repo' or 'org/repo@revision')")

    return models