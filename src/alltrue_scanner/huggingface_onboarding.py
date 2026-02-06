# HuggingFace repository code scanning functionality
# Uses code scanning approach to discover and add HuggingFace models to inventory

from __future__ import annotations
from typing import Any, Dict, List, Optional
import time

import requests

import src.alltrue_scanner.api as api
import src.alltrue_scanner.config as config


def _find_existing_repository(
    jwt: str,
    organization: str,
    repo_name: str,
    project_id: Optional[str] = None
) -> Optional[str]:
    """
    Search for existing repository configuration via GraphQL.
    
    Args:
        jwt: JWT authentication token
        organization: HuggingFace organization/user
        repo_name: HuggingFace repository name
        project_id: Optional project ID to filter by
        
    Returns:
        repository_config_id if found, None otherwise
    """
    try:
        query = """
        query FindRepository($customerId: UUID!, $organizationId: UUID) {
            repositories: getRepositories(
                filter: {customerId: $customerId, organizationId: $organizationId}
            ) {
                id
                name
                organization
                project {
                    id
                }
                vcs
            }
        }
        """
        
        variables = {
            "customerId": config.CUSTOMER_ID,
            "organizationId": getattr(config, "ORGANIZATION_ID", None)
        }
        
        data = api.run_graphql(
            jwt_token=jwt,
            query=query,
            variables=variables,
            version="v1",
            timeout=30
        )
        
        repositories = data.get("repositories", [])
        
        # Find matching repository
        for repo in repositories:
            # Match on organization and repo name
            if (repo.get("organization") == organization and 
                repo.get("name") == repo_name and
                repo.get("vcs") == "huggingface_hub"):
                
                repo_id = repo.get("id")
                # Project is an object with 'id' field - extract the ID
                project_obj = repo.get("project")
                repo_project_id = project_obj.get("id") if project_obj else None
                
                # Log match details
                print(f"[HF-CodeScan] Found existing repository config: {repo_id}")
                if repo_project_id:
                    print(f"              Associated with project: {repo_project_id}")
                else:
                    print(f"              No project association")
                
                # Accept repository if:
                # 1. No project_id specified (we don't care about project match)
                # 2. Project IDs match
                # 3. Existing repo has no project (will work for any project)
                if project_id is None or repo_project_id == project_id or repo_project_id is None:
                    return repo_id
                else:
                    print(f"              [!] Project mismatch (wanted: {project_id}, found: {repo_project_id})")
        
        return None
        
    except Exception as e:
        print(f"[HF-CodeScan] [!]  Error searching for existing repository: {e}")
        return None


def _create_repository_config(
    jwt: str,
    organization: str,
    repo_name: str,
    project_id: str,
    api_key: str = ""
) -> Optional[str]:
    """
    Create a repository configuration for code scanning.
    If repository already exists (409 Conflict), find and return existing config.
    
    POST /v1/code-scanning/customer/{customer_id}/repositories
    
    Args:
        jwt: JWT authentication token
        organization: HuggingFace organization/user (e.g., "PaddlePaddle")
        repo_name: HuggingFace repository name (e.g., "PaddleOCR-VL-1.5")
        project_id: Project ID to associate repository with
        api_key: Optional HuggingFace API key for private repos
        
    Returns:
        repository_config_id if successful, None otherwise
    """
    # Step 1: Check if repository already exists (proactive check)
    print(f"[HF-CodeScan] Checking for existing repository config: {organization}/{repo_name}...")
    existing_repo_id = _find_existing_repository(
        jwt=jwt,
        organization=organization,
        repo_name=repo_name,
        project_id=project_id
    )
    
    if existing_repo_id:
        print(f"[HF-CodeScan] OK Using existing repository config: {existing_repo_id}")
        return existing_repo_id
    
    # Step 2: No existing repository found, create new one
    endpoint = f"/v1/code-scanning/customer/{config.CUSTOMER_ID}/repositories"
    data = {
        "vcs": "huggingface_hub",
        "organization": organization,
        "repo_name": repo_name,
        "api_key": api_key,
        "project_id": project_id
    }
    
    try:
        print(f"[HF-CodeScan] Creating new repository config for {organization}/{repo_name}...")
        response = api.make_api_request(
            endpoint,
            token=jwt,
            method="POST",
            data=data,
            timeout=60
        )
        
        response_data = response.json()
        repo_config_id = response_data.get("repository_config_id")
        
        if repo_config_id:
            print(f"[HF-CodeScan] OK Repository config created: {repo_config_id}")
            return repo_config_id
        else:
            print(f"[HF-CodeScan] X No repository_config_id returned")
            return None
            
    except requests.HTTPError as e:
        # Handle 409 Conflict specifically (race condition case)
        if e.response.status_code == 409:
            print(f"[HF-CodeScan] Repository already exists (409 Conflict), searching for existing config...")
            # Try to find it via GraphQL
            existing_repo_id = _find_existing_repository(
                jwt=jwt,
                organization=organization,
                repo_name=repo_name,
                project_id=project_id
            )
            if existing_repo_id:
                print(f"[HF-CodeScan] OK Found existing repository after 409: {existing_repo_id}")
                return existing_repo_id
            else:
                print(f"[HF-CodeScan] X Could not find existing repository after 409 Conflict")
                print(f"[HF-CodeScan]    This may indicate a project mismatch or permission issue")
                return None
        else:
            print(f"[HF-CodeScan] X Error creating repository config ({e.response.status_code}): {e}")
            return None
            
    except Exception as e:
        print(f"[HF-CodeScan] X Error creating repository config: {e}")
        return None


def _create_scan_job(
    jwt: str,
    repository_config_id: str
) -> Optional[str]:
    """
    Create a code scanning job with discovery specifications.
    
    Note: This only creates the job - you must call _start_scan_job to actually run it.
    
    POST /v1/code-scanning/customer/{customer_id}/repositories/{repo_config_id}/jobs
    
    Args:
        jwt: JWT authentication token
        repository_config_id: Repository configuration ID
        
    Returns:
        code_scan_job_id if successful, None otherwise
    """
    endpoint = f"/v1/code-scanning/customer/{config.CUSTOMER_ID}/repositories/{repository_config_id}/jobs"
    
    # Discovery specs that will find HuggingFace models and other resources
    data = {
        "scan_specs": [
            {
                "scan_type": "discover-requirements-files",
                "identifier_pattern": "{repo_name}-{path}"
            },
            {
                "scan_type": "discover-urls",
                "url_whitelist": None,
                "url_blacklist": None
            },
            {
                "scan_type": "discover-huggingface-models",
                "model_whitelist": None,
                "model_blacklist": None
            },
            {
                "scan_type": "discover-jupyter-notebooks",
                "exclude_checkpoints": True
            },
            {
                "scan_type": "discover-ai-agents"
            },
            {
                "scan_type": "model-discovery"
            }
        ]
    }
    
    try:
        print(f"[HF-CodeScan] Creating scan job for repository {repository_config_id}...")
        response = api.make_api_request(
            endpoint,
            token=jwt,
            method="POST",
            data=data,
            timeout=60
        )
        
        response_data = response.json()
        code_scan_job_id = response_data.get("code_scan_job_id")
        
        if code_scan_job_id:
            print(f"[HF-CodeScan] OK Scan job created: {code_scan_job_id}")
            return code_scan_job_id
        else:
            print(f"[HF-CodeScan] X No code_scan_job_id returned")
            return None
            
    except Exception as e:
        print(f"[HF-CodeScan] X Error creating scan job: {e}")
        return None


def _start_scan_job(
    jwt: str,
    code_scan_job_id: str
) -> bool:
    """
    Start a previously created code scanning job.
    
    POST /v1/code-scanning/start-job/{code_scan_job_id}
    
    Args:
        jwt: JWT authentication token
        code_scan_job_id: Code scan job ID to start
        
    Returns:
        True if started successfully, False otherwise
    """
    endpoint = f"/v1/code-scanning/start-job/{code_scan_job_id}"
    
    # Query parameters based on the API documentation
    params = {
        "callback_control_plane": True,
        "is_optional": False
    }
    
    try:
        print(f"[HF-CodeScan] Starting scan job {code_scan_job_id}...")
        response = api.make_api_request(
            endpoint,
            token=jwt,
            method="POST",
            params=params,
            data={},  # Empty body for POST
            timeout=60
        )
        
        response_data = response.json()
        job_id = response_data.get("job_id")
        status = response_data.get("status")
        
        if status == "RUNNING":
            print(f"[HF-CodeScan] OK Scan job started (job_id: {job_id})")
            return True
        else:
            print(f"[HF-CodeScan] [!] Unexpected status: {status}")
            return False
            
    except Exception as e:
        print(f"[HF-CodeScan] X Error starting scan job: {e}")
        return False


def _poll_via_graphql(
    jwt: str,
    repository_config_id: str,
    organization_id: Optional[str] = None,
    poll_interval_secs: float = 10.0,
    timeout_secs: float = 600.0
) -> tuple[bool, List[str]]:
    """
    Poll repository status via GraphQL until scan completes.
    
    This mimics what the UI does - query the repository and check if
    resourceInstances have been discovered.
    
    Args:
        jwt: JWT authentication token
        repository_config_id: Repository configuration ID to monitor
        organization_id: Optional organization ID for filtering
        poll_interval_secs: Seconds between polls
        timeout_secs: Maximum time to wait
        
    Returns:
        Tuple of (success, resource_ids)
    """
    query = """
    query MonitorRepositoryScan($customerId: UUID!, $organizationId: UUID) {
        repositories: getRepositories(
            filter: {customerId: $customerId, organizationId: $organizationId}
        ) {
            id
            name
            organization
            lastVerified
            lastVerifiedSuccess
            lastVerifiedFailedReason
            resourceInstances {
                id
                type
                name
                registeredAt
            }
        }
    }
    """
    
    variables = {
        "customerId": config.CUSTOMER_ID
    }
    
    if organization_id:
        variables["organizationId"] = organization_id
    
    start_time = time.time()
    poll_count = 0
    last_resource_count = 0
    stable_count = 0  # Count of consecutive polls with same resource count
    
    print(f"[HF-CodeScan] Monitoring scan progress via GraphQL...")
    
    while True:
        elapsed = time.time() - start_time
        
        if elapsed >= timeout_secs:
            print(f"[HF-CodeScan] X Timeout after {timeout_secs}s waiting for scan completion")
            # Return whatever resources we have
            return (False, [])
        
        try:
            poll_count += 1
            
            data = api.run_graphql(
                jwt_token=jwt,
                query=query,
                variables=variables,
                version="v1",
                timeout=30
            )
            
            repositories = data.get("repositories", [])
            
            # Find our repository by ID
            for repo in repositories:
                if repo.get("id") == repository_config_id:
                    resource_instances = repo.get("resourceInstances", [])
                    current_count = len(resource_instances)
                    
                    # Check if resources have been discovered and are stable
                    if current_count > 0:
                        if current_count == last_resource_count:
                            stable_count += 1
                            # If count is stable for 3 consecutive polls, consider it complete
                            if stable_count >= 3:
                                resource_ids = [r.get("id") for r in resource_instances if r.get("id")]
                                print(f"[HF-CodeScan] OK Scan completed after {elapsed:.1f}s ({poll_count} polls)")
                                print(f"[HF-CodeScan]    Discovered {len(resource_ids)} resource(s)")
                                return (True, resource_ids)
                        else:
                            # Count changed, reset stability counter
                            stable_count = 0
                            print(f"[HF-CodeScan]    Discovered {current_count} resource(s) so far...")
                        
                        last_resource_count = current_count
                    
                    # Log progress periodically
                    if poll_count % 6 == 0:  # Every minute at 10s intervals
                        print(f"[HF-CodeScan]    Still scanning... (elapsed: {elapsed:.1f}s, resources: {current_count})")
                    
                    break
            else:
                print(f"[HF-CodeScan] [!]  Repository {repository_config_id} not found in GraphQL results")
            
            time.sleep(poll_interval_secs)
            
        except Exception as e:
            print(f"[HF-CodeScan] [!]  Error polling via GraphQL: {e}")
            time.sleep(poll_interval_secs)
            continue


def _query_discovered_resources(
    jwt: str,
    repository_config_id: str,
    organization_id: Optional[str] = None
) -> List[str]:
    """
    Query repository's discovered resources via GraphQL.
    
    This is a final check to get the complete list of resources after scanning completes.
    
    Args:
        jwt: JWT authentication token
        repository_config_id: Repository configuration ID
        organization_id: Optional organization ID for filtering
        
    Returns:
        List of resource_instance_ids
    """
    try:
        query = """
        query GetRepositoryResources($customerId: UUID!, $organizationId: UUID) {
            repositories: getRepositories(
                filter: {customerId: $customerId, organizationId: $organizationId}
            ) {
                id
                name
                organization
                resourceInstances {
                    id
                    type
                    name
                }
            }
        }
        """
        
        variables = {
            "customerId": config.CUSTOMER_ID
        }
        
        if organization_id:
            variables["organizationId"] = organization_id
        
        print(f"[HF-CodeScan] Querying final resource list via GraphQL...")
        
        data = api.run_graphql(
            jwt_token=jwt,
            query=query,
            variables=variables,
            version="v1",
            timeout=30
        )
        
        repositories = data.get("repositories", [])
        
        # Find our repository by ID
        for repo in repositories:
            if repo.get("id") == repository_config_id:
                resource_instances = repo.get("resourceInstances", [])
                
                if resource_instances:
                    resource_ids = []
                    for instance in resource_instances:
                        rid = instance.get("id")
                        rtype = instance.get("type", "")
                        rname = instance.get("name", "")
                        
                        if rid:
                            resource_ids.append(rid)
                            print(f"              - {rname} ({rtype})")
                    
                    print(f"[HF-CodeScan] OK Found {len(resource_ids)} resource(s) total")
                    return resource_ids
                else:
                    print(f"[HF-CodeScan] [!]  Repository found but no resources discovered")
                    return []
        
        print(f"[HF-CodeScan] [!]  Repository {repository_config_id} not found in GraphQL results")
        return []
        
    except Exception as e:
        print(f"[HF-CodeScan] [!]  Error querying via GraphQL: {e}")
        return []


def onboard_huggingface_models(jwt: str, models: List[Dict[str, Any]], project_id: str) -> List[str]:
    """
    Onboard HuggingFace repositories using code scanning approach.
    
    This replaces the deprecated manual inventory method with the new
    code scanning workflow that supports ongoing discovery and detection
    of model changes.
    
    Args:
        jwt: JWT authentication token
        models: List of model configs, each containing:
            - organization_id: HuggingFace organization/user (e.g., "PaddlePaddle")
            - repo_name: HuggingFace repository name (e.g., "PaddleOCR-VL-1.5")
            - revision: Git revision (default: "main") - NOTE: not used in code scanning
            - api_key: Optional HuggingFace API key for private repos
        project_id: Project ID to associate models with
    
    Returns:
        List of resource instance IDs for discovered models
    """
    if not models:
        print("[HF-CodeScan] No repositories to scan")
        return []
    
    print(f"\n{'='*80}")
    print(f"CODE SCANNING {len(models)} HUGGINGFACE REPOSITORY(IES)")
    print(f"Using new code scanning approach for model discovery")
    print(f"{'='*80}")
    
    all_resource_ids = []
    
    # Get organization_id if available for GraphQL queries
    org_id = getattr(config, "ORGANIZATION_ID", None)
    
    for model in models:
        organization = model.get("organization_id")
        repo_name = model.get("repo_name")
        api_key = model.get("api_key", "")
        revision = model.get("revision", "main")
        
        if not organization or not repo_name:
            print(f"[HF-CodeScan] [!]  Skipping: missing organization_id or repo_name")
            continue
        
        if revision != "main":
            print(f"[HF-CodeScan] [!]  Note: revision '{revision}' specified but code scanning uses default branch")
        
        print(f"\n[HF-CodeScan] Processing: {organization}/{repo_name}")
        
        # Step 1: Create or find repository configuration (handles 409 conflicts)
        repo_config_id = _create_repository_config(
            jwt=jwt,
            organization=organization,
            repo_name=repo_name,
            project_id=project_id,
            api_key=api_key
        )
        
        if not repo_config_id:
            print(f"[HF-CodeScan] X Failed to create/find repository config for {organization}/{repo_name}")
            continue
        
        # Step 1.5: Check if repository already has discovered resources
        print(f"[HF-CodeScan] Checking for previously discovered resources...")
        existing_resource_ids = _query_discovered_resources(
            jwt=jwt,
            repository_config_id=repo_config_id,
            organization_id=org_id
        )
        
        if existing_resource_ids:
            print(f"[HF-CodeScan] OK Found {len(existing_resource_ids)} existing resource(s) - skipping scan")
            all_resource_ids.extend(existing_resource_ids)
            continue
        
        print(f"[HF-CodeScan] No existing resources found, will initiate scan...")
        
        # Step 2: Create scan job
        code_scan_job_id = _create_scan_job(
            jwt=jwt,
            repository_config_id=repo_config_id
        )
        
        if not code_scan_job_id:
            print(f"[HF-CodeScan] X Failed to create scan job for {organization}/{repo_name}")
            continue
        
        # Step 2.5: Start the scan job
        started = _start_scan_job(
            jwt=jwt,
            code_scan_job_id=code_scan_job_id
        )
        
        if not started:
            print(f"[HF-CodeScan] X Failed to start scan job for {organization}/{repo_name}")
            continue
        
        # Step 3: Monitor via GraphQL (like the UI does)
        success, resource_ids = _poll_via_graphql(
            jwt=jwt,
            repository_config_id=repo_config_id,
            organization_id=org_id,
            poll_interval_secs=10.0,
            timeout_secs=1200.0  # 20 minutes per repository
        )
        
        if success and resource_ids:
            all_resource_ids.extend(resource_ids)
            print(f"[HF-CodeScan] OK Discovered {len(resource_ids)} resource(s) from {organization}/{repo_name}")
        elif not success:
            # Timeout - try one final query
            print(f"[HF-CodeScan] Scan monitoring timed out, attempting final resource query...")
            resource_ids = _query_discovered_resources(
                jwt=jwt,
                repository_config_id=repo_config_id,
                organization_id=org_id
            )
            if resource_ids:
                all_resource_ids.extend(resource_ids)
                print(f"[HF-CodeScan] OK Found {len(resource_ids)} resource(s) in final query")
            else:
                print(f"[HF-CodeScan] X No resources discovered for {organization}/{repo_name}")
        else:
            print(f"[HF-CodeScan] X No resources discovered for {organization}/{repo_name}")
    
    if all_resource_ids:
        print(f"\n{'='*80}")
        print(f"[HF-CodeScan] Successfully discovered {len(all_resource_ids)} total resource(s)")
        print(f"{'='*80}")
    else:
        print(f"\n[HF-CodeScan] X No resources discovered from any repository")
    
    return all_resource_ids


def parse_huggingface_models_from_config() -> List[Dict[str, Any]]:
    """
    Parse HuggingFace repository specifications from config.
    
    Supports two formats:
    1. Simple format (comma-separated): "org1/repo1,org2/repo2"
    2. JSON format with full details: '[{"organization_id":"org1","repo_name":"repo1","api_key":"..."}]'
    
    Note: The 'revision' field is now ignored as code scanning uses the default branch.
    
    Returns:
        List of repository config dicts
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
            
            # Handle optional @revision suffix (will be ignored with warning)
            revision = "main"
            if "@" in repo_name:
                repo_name, revision = repo_name.split("@", 1)
                repo_name = repo_name.strip()
                revision = revision.strip()
                if revision != "main":
                    print(f"[HF-Parse] [!]  Note: revision '@{revision}' will be ignored (code scanning uses default branch)")
            
            models.append({
                "organization_id": org_id,
                "repo_name": repo_name,
                "revision": revision,  # Keep for backward compatibility but not used
            })
        else:
            print(f"[HF-Parse] [!]  Invalid repository format: '{item}' (expected 'org/repo')")
    
    return models