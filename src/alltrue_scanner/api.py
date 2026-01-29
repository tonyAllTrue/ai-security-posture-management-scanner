import re
import threading
from typing import Any, Dict, List, Optional, Callable, TypeVar
from datetime import datetime, timezone
import time as _t

import requests
import src.alltrue_scanner.config as config
from src.alltrue_scanner.utils import parse_csv_string


# ---------- Masking / HTTP core ----------

def _mask(s: str, show: int = 4) -> str:
    if not s:
        return s
    return s[:show] + "..." if len(s) > show else "..."


def make_api_request(
    endpoint: str,
    token: str,
    method: str = "GET",
    data: Any = None,
    params: Dict[str, Any] | None = None,
    include_api_key: bool = False,
    accept: str = "application/json",
    content_type: str | None = "application/json",
    timeout: int | float | None = None,
) -> requests.Response:
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": accept,
    }
    if content_type:
        headers["Content-Type"] = content_type
    if include_api_key:
        headers["X-API-Key"] = config.API_KEY

    url = f"{config.API_URL}{endpoint}"
    resp = requests.request(method, url, headers=headers, params=params, json=data, timeout=timeout)
    try:
        resp.raise_for_status()
    except requests.HTTPError:
        safe_headers = {k: (v if k.lower() not in {"authorization", "x-api-key"} else _mask(v))
                        for k, v in headers.items()}
        print(f"[-] {method} {url} failed: {resp.status_code}")
        print(f"    Headers sent: {safe_headers}")
        print(f"    Response: {resp.text}")
        raise
    return resp


# ---------- Organization & Project Lookup ----------

# Cache for the org/project data to avoid repeated API calls
_org_project_cache: Optional[Dict[str, Any]] = None
_cache_lock = threading.Lock()


def _fetch_organizations_and_projects(jwt_token: str, force_refresh: bool = False) -> List[Dict[str, Any]]:
    """
    Fetch all organizations and their projects for the customer.
    Results are cached to avoid repeated API calls.

    Returns list of organization dicts, each containing:
    - organization_id
    - organization_name
    - projects: list of project dicts with project_id and project_name

    Raises exception on permission errors to allow caller to handle appropriately.
    """
    global _org_project_cache

    with _cache_lock:
        # Return cached data if available and not forcing refresh
        if _org_project_cache is not None and not force_refresh:
            return _org_project_cache

        endpoint = f"/v1/admin/customers/{config.CUSTOMER_ID}/organizations/projects"
        params = {
            "organization_status": "active",
            "project_status": "active"
        }

        try:
            resp = make_api_request(endpoint, token=jwt_token, method="GET", params=params, timeout=30)
            data = resp.json()
            orgs = data.get("organizations", [])

            # Cache the result
            _org_project_cache = orgs
            return orgs
        except requests.HTTPError as e:
            # Re-raise permission errors so caller can provide better context
            if e.response.status_code in (401, 403):
                raise
            print(f"[-] Error fetching organizations and projects: {e}")
            return []
        except Exception as e:
            print(f"[-] Error fetching organizations and projects: {e}")
            return []


def list_organizations(jwt_token: str) -> List[Dict[str, Any]]:
    """
    Fetch all organizations for the customer.
    Returns list of organization dicts with 'organization_id' and 'organization_name'.

    Note: This uses a cached fetch of the organizations/projects endpoint.
    """
    orgs_with_projects = _fetch_organizations_and_projects(jwt_token)

    # Return simplified view (just org info, no projects)
    return [
        {
            "organization_id": org.get("organization_id"),
            "organization_name": org.get("organization_name"),
        }
        for org in orgs_with_projects
    ]


def resolve_organization_name_to_id(jwt_token: str, org_name: str) -> Optional[str]:
    """
    Look up an organization by name and return its ID.
    Returns None if not found.

    Note: This uses a cached fetch of the organizations/projects endpoint.
    """
    orgs = _fetch_organizations_and_projects(jwt_token)
    org_name_lower = org_name.strip().lower()

    for org in orgs:
        if org.get("organization_name", "").strip().lower() == org_name_lower:
            return org.get("organization_id")

    return None


def list_projects_for_organization(jwt_token: str, organization_id: str) -> List[Dict[str, Any]]:
    """
    Fetch all projects for a specific organization.
    Returns list of project dicts with 'project_id' and 'project_name'.

    Note: This uses a cached fetch of the organizations/projects endpoint.
    """
    orgs = _fetch_organizations_and_projects(jwt_token)

    # Find the matching organization and return its projects
    for org in orgs:
        if org.get("organization_id") == organization_id:
            return org.get("projects", [])

    return []


def resolve_project_name_to_id(jwt_token: str, project_name: str, organization_id: Optional[str] = None) -> Optional[str]:
    """
    Look up a project by name and return its ID.
    If organization_id is provided, only search within that organization.
    Returns None if not found.

    Note: This uses a cached fetch of the organizations/projects endpoint.
    """
    orgs = _fetch_organizations_and_projects(jwt_token)
    project_name_lower = project_name.strip().lower()

    if organization_id:
        # Search within specific organization
        for org in orgs:
            if org.get("organization_id") == organization_id:
                for project in org.get("projects", []):
                    if project.get("project_name", "").strip().lower() == project_name_lower:
                        return project.get("project_id")
    else:
        # Search across all organizations
        for org in orgs:
            for project in org.get("projects", []):
                if project.get("project_name", "").strip().lower() == project_name_lower:
                    return project.get("project_id")

    return None


def resolve_organization_names_or_ids(jwt_token: str, values: List[str]) -> List[str]:
    """
    Resolve a list of organization names or IDs to IDs.
    If a value is already a valid UUID, it's kept as-is.
    If it's a name, it's resolved to an ID.
    Returns list of organization IDs.
    """
    import uuid

    resolved_ids = []
    for value in values:
        value = value.strip()
        if not value:
            continue

        # Check if it's already a UUID
        try:
            uuid.UUID(value)
            resolved_ids.append(value)
            print(f"[org-resolve] '{value}' is a valid UUID, using as-is")
            continue
        except ValueError:
            pass

        # Try to resolve as name
        org_id = resolve_organization_name_to_id(jwt_token, value)
        if org_id:
            resolved_ids.append(org_id)
            print(f"[org-resolve] Resolved organization name '{value}' -> {org_id}")
        else:
            print(f"[org-resolve] [!]  Could not resolve organization '{value}' (not found or invalid)")

    return resolved_ids


def resolve_project_names_or_ids(jwt_token: str, values: List[str], organization_id: Optional[str] = None) -> List[str]:
    """
    Resolve a list of project names or IDs to IDs.
    If a value is already a valid UUID, it's kept as-is.
    If it's a name, it's resolved to an ID.
    If organization_id is provided, searches within that org only.
    Returns list of project IDs.
    """
    import uuid

    resolved_ids = []
    for value in values:
        value = value.strip()
        if not value:
            continue

        # Check if it's already a UUID
        try:
            uuid.UUID(value)
            resolved_ids.append(value)
            print(f"[proj-resolve] '{value}' is a valid UUID, using as-is")
            continue
        except ValueError:
            pass

        # Try to resolve as name
        project_id = resolve_project_name_to_id(jwt_token, value, organization_id)
        if project_id:
            resolved_ids.append(project_id)
            org_context = f" (within org {organization_id})" if organization_id else ""
            print(f"[proj-resolve] Resolved project name '{value}'{org_context} -> {project_id}")
        else:
            org_context = f" within organization {organization_id}" if organization_id else ""
            print(f"[proj-resolve] [!]  Could not resolve project '{value}'{org_context} (not found or invalid)")

    return resolved_ids


# ---------- Shared utilities ----------

def sanitize_name(name: str) -> str:
    safe = "".join(c for c in name if c.isalnum() or c in (" ", "-", "_")).rstrip()
    safe = safe.replace(" ", "_")
    return re.sub(r"_+", "_", safe)


def download_results_csv(jwt_token: str, resource_name: str, resource_id: str, scan_execution_id: str) -> str | None:
    endpoint = f"/v2/llm-pentest/customer/{config.CUSTOMER_ID}/executions/{scan_execution_id}/download-csv"
    try:
        resp = make_api_request(
            endpoint,
            token=jwt_token,
            method="POST",
            accept="text/csv,application/octet-stream,*/*",
            content_type=None,
            timeout=60,
        )
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        fname = f"pentest_results_{sanitize_name(resource_name)}_{resource_id[:8]}_{scan_execution_id[:8]}_{ts}.csv"
        with open(fname, "wb") as f:
            f.write(resp.content)
        print(f"[Thread: {threading.current_thread().name}][+] CSV saved as {fname}")
        return fname
    except requests.HTTPError:
        # Re-raise HTTP errors so retry logic can handle them
        raise
    except Exception as e:
        print(f"[Thread: {threading.current_thread().name}][-] Error downloading results: {e}")
        return None


# ---------- Generic GraphQL runner ----------

def run_graphql(jwt_token: str, query: str, variables: dict, *, version: str = "v2", timeout: int = 30) -> dict:
    """
    Generic GraphQL executor that returns the `data` object or raises on errors.
    Consolidates repeated POST + error handling logic used by bespoke query_* functions.
    """
    endpoint = f"/{version}/graphql"
    resp = make_api_request(
        endpoint,
        token=jwt_token,
        method="POST",
        data={"query": query, "variables": variables},
        accept="application/json",
        content_type="application/json",
        timeout=timeout,
    )
    payload = resp.json() or {}
    if "errors" in payload:
        raise RuntimeError(payload["errors"])
    return payload.get("data", {})


# ---------- v2 GraphQL: Pentest full execution ----------

def query_pentest_execution_full(jwt_token: str, scan_execution_id: str) -> dict:
    """
    Fetches execution, resource, and per-category results (passed/failed/inconclusive).
    """
    graphql_query = """
    query LlmPentestScanExecutionResults($customerId: UUID!, $llmPentestScanExecutionId: UUID!) {
      llmPentestScanExecution(
        filter: { customerId: $customerId, llmPentestScanExecutionId: $llmPentestScanExecutionId }
      ) {
        startedAt
        outcomeLevel
        llmPentestScanExecutionId
        chosenLlmModel
      }
      resourceInstanceForLlmPentestScanExecution(
        filter: { customerId: $customerId, llmPentestScanExecutionId: $llmPentestScanExecutionId }
      ) {
        displayName
        resourceInstanceId
      }
      failedCategoriesResultsPerCategory(
        filter: { customerId: $customerId, llmPentestScanExecutionId: $llmPentestScanExecutionId }
      ) {
        llmPentestCustomerCategoryId
        severity
        categoryDisplayName
        totalTestCases
        passedTestCases
        failedTestCases
        failedTestCaseDetails {
          externalPrompt
          output
          failedReason
          llmPentestCustomerTestcaseId
        }
      }
    }"""
    data = run_graphql(
        jwt_token,
        graphql_query,
        {"customerId": config.CUSTOMER_ID, "llmPentestScanExecutionId": scan_execution_id},
        version="v2",
        timeout=60,
    )
    return data or {}


# ---------- v1 GraphQL: aiSpmGetPentestIssues ----------

def query_spm_pentest_issues(
    jwt_token: str,
    filters: Optional[Dict[str, Any]] = None,
) -> List[dict]:
    """
    Call /v1/graphql -> aiSpmGetPentestIssues(filter: PentestIssueFilter!)
    Returns the list under data.aiSpmGetPentestIssues.pentestFindings.

    Args:
        jwt_token: JWT authentication token
        filters: Optional dict of filter parameters to apply. Supported keys:
            - organizationId: str
            - projectId: str
            - issueStatus: List[str] - ["UNRESOLVED","REMEDIATED","DISMISSED","ARCHIVED","OVERDUE"]
            - issueSeverities: List[str] - ["CRITICAL","HIGH","MEDIUM","LOW","INFORMATIONAL"]
            - resourceDisplayNames: List[str]
            - pentestFindings: List[str] - policy/category names, e.g. ["Prompt Injection"]

    Returns:
        List of pentest findings

    Note:
        PentestIssueFilter does NOT include llmPentestScanExecutionId; match exec IDs client-side.
        Default issueStatus is ["UNRESOLVED"] if not specified in filters.
    """
    query = """
    query PentestIssues($filter: PentestIssueFilter!) {
      aiSpmGetPentestIssues(filter: $filter) {
        pentestFindings {
          llmPentestScanExecutionId
          inProgress
          inProgressAt
          issueCreatedDate
          issueId
          issueType
          numProjects
          policyName
          projectNames
          resourceDisplayName
          resourceType
          resourceTypeDisplayName
          scanId
          severity
          status
        }
      }
    }"""

    # Start with required fields and defaults
    filter_obj: Dict[str, Any] = {
        "customerId": config.CUSTOMER_ID,
        "issueStatus": ["UNRESOLVED"],  # default status
    }

    # Merge in user-provided filters (overwrites defaults)
    if filters:
        filter_obj.update(filters)

    data = run_graphql(jwt_token, query, {"filter": filter_obj}, version="v1", timeout=45)
    wrapper = data.get("aiSpmGetPentestIssues") or {}
    findings = wrapper.get("pentestFindings") or []
    return findings if isinstance(findings, list) else []


# ---------- Inventory helpers ----------

def build_scope_filters(
    organization_id: Optional[str | list] = None,
    project_id: Optional[str | list] = None,
) -> Dict[str, Any]:
    """
    Build scope filter dict based on INVENTORY_SCOPE and the provided IDs.
    - Accepts singular or plural vars from args; falls back to config.* if absent.
    - When INVENTORY_SCOPE='resource', at least one of org/project must be provided.
    - Returns a NEW dict (no mutation).
    """
    scope = (getattr(config, "INVENTORY_SCOPE", "") or "").lower()

    # Collect from args first, then config (singular or plural)
    orgs = parse_csv_string(organization_id)
    if not orgs:
        orgs = parse_csv_string(getattr(config, "ORGANIZATION_ID", None)) or \
               parse_csv_string(getattr(config, "ORGANIZATION_IDS", None))

    projs = parse_csv_string(project_id)
    if not projs:
        projs = parse_csv_string(getattr(config, "PROJECT_ID", None)) or \
                parse_csv_string(getattr(config, "PROJECT_IDS", None))

    params: Dict[str, Any] = {}

    if scope == "resource":
        if not orgs and not projs:
            raise ValueError(
                "When INVENTORY_SCOPE='resource', an organization_id or project_id is required."
            )
        if orgs:
            params["organization"] = orgs if len(orgs) > 1 else orgs[0]
        if projs:
            params["project"] = projs if len(projs) > 1 else projs[0]
        return params

    # Non-resource scope: still respect explicit args if provided
    if orgs:
        params["organization"] = orgs if len(orgs) > 1 else orgs[0]
    if projs:
        params["project"] = projs if len(projs) > 1 else projs[0]
    return params


def get_llm_pentest_models(jwt_token: str, resource_instance_id: str) -> List[str]:
    """
    Fetch available models for a specific LLM endpoint resource.
    Returns list of model names that can be used for pentesting this resource.
    """
    endpoint = f"/v2/llm-pentest/customer/{config.CUSTOMER_ID}/llm-pentest-models/{resource_instance_id}"
    try:
        resp = make_api_request(endpoint, token=jwt_token, method="GET", timeout=30)
        models = resp.json()
        return models if isinstance(models, list) else []
    except Exception as e:
        print(f"[-] Error fetching pentest models for resource {resource_instance_id}: {e}")
        return []


# ---------- LLM endpoint "additional config" helpers ----------
# This endpoint is used by the UI to set system prompt, dataset, and system description:
#   PATCH /v1/inventory/customer/resource/{resource_instance_id}/llm-endpoint-resource-additional-config
#
# Important: do NOT accidentally overwrite fields you didn't intend to change.
# We use a sentinel to distinguish:
#   - UNSET  : do not touch this field
#   - None/"" : explicitly clear (depending on backend expectations)
#   - str    : set to provided value
_UNSET = object()


def get_llm_endpoint_additional_config(jwt_token: str, resource_instance_id: str) -> dict:
    endpoint = f"/v1/inventory/customer/resource/{resource_instance_id}/llm-endpoint-resource-additional-config"
    resp = make_api_request(endpoint, token=jwt_token, method="GET", timeout=30)
    return resp.json()


def patch_llm_endpoint_additional_config(
    jwt_token: str,
    resource_instance_id: str,
    *,
    system_prompt: object = _UNSET,
    dataset_id: object = _UNSET,
    system_description: object = _UNSET,
) -> dict:
    """
    Safely PATCH LLM endpoint additional config without clobbering unrelated fields.

    Args:
      system_prompt:
        - _UNSET: don't touch
        - None or "": clear
        - str: set
      dataset_id:
        - _UNSET: don't touch
        - None: clear (sent as JSON null)  [recommended for UUID fields]
        - "": clear (may or may not be honored by backend for UUID fields)
        - str: set
      system_description:
        - _UNSET: don't touch
        - None or "": clear
        - str: set
    """
    endpoint = f"/v1/inventory/customer/resource/{resource_instance_id}/llm-endpoint-resource-additional-config"
    existing_config = get_llm_endpoint_additional_config(jwt_token, resource_instance_id)

    patch_data: dict = {
        "llm_endpoint_resource_config_id": existing_config.get("llm_endpoint_resource_config_id"),
        "customer_id": config.CUSTOMER_ID,
        "resource_instance_id": resource_instance_id,
    }

    # Only include fields we explicitly intend to change.
    if system_prompt is not _UNSET:
        patch_data["llm_endpoint_pentesting_system_prompt"] = system_prompt

    if dataset_id is not _UNSET:
        patch_data["llm_endpoint_pentesting_reference_capture_replay_dataset_id"] = dataset_id

    if system_description is not _UNSET:
        patch_data["llm_endpoint_resource_system_description"] = system_description

    resp = make_api_request(endpoint, token=jwt_token, method="PATCH", data=patch_data, timeout=30)
    return resp.json()


def configure_llm_endpoint_system_prompt(
    jwt_token: str,
    resource_instance_id: str,
    system_prompt: str | None = None,
) -> dict:
    """
    Configure ONLY the system prompt for an LLM endpoint resource.

    Safe behavior:
      - system_prompt is None  -> preserve existing prompt (no change)
      - system_prompt is ""    -> clear prompt
      - otherwise              -> set to provided value
    """
    if system_prompt is None:
        # Preserve (no-op): return current config for visibility.
        return get_llm_endpoint_additional_config(jwt_token, resource_instance_id)

    return patch_llm_endpoint_additional_config(
        jwt_token,
        resource_instance_id,
        system_prompt=system_prompt,
    )


def cleanup_llm_endpoint_system_prompt(jwt_token: str, resource_instance_id: str) -> dict:
    """
    Clear system prompt from resource after pentesting (optional cleanup).
    """
    return patch_llm_endpoint_additional_config(
        jwt_token,
        resource_instance_id,
        system_prompt="",
    )


def configure_llm_endpoint_system_description(
    jwt_token: str,
    resource_instance_id: str,
    system_description: str | None = None,
) -> dict:
    """
    Configure ONLY the resource system description for an LLM endpoint resource.

    Safe behavior:
      - system_description is None -> preserve existing description (no change)
      - system_description is ""   -> clear description
      - otherwise                  -> set to provided value
    """
    if system_description is None:
        # Preserve (no-op): return current config for visibility.
        return get_llm_endpoint_additional_config(jwt_token, resource_instance_id)

    return patch_llm_endpoint_additional_config(
        jwt_token,
        resource_instance_id,
        system_description=system_description,
    )


def cleanup_llm_endpoint_system_description(jwt_token: str, resource_instance_id: str) -> dict:
    """
    Clear resource system description from resource after pentesting (optional cleanup).
    """
    return patch_llm_endpoint_additional_config(
        jwt_token,
        resource_instance_id,
        system_description="",
    )


def list_importable_datasets(jwt_token: str, project_id: str) -> List[Dict[str, Any]]:
    """
    Fetch available datasets for a project that can be used for capture-replay pentesting.

    GET /v2/ai-validation/importable-datasets?project_id={project_id}

    Response format:
    {
        "datasets": [
            {
                "capture_replay_dataset_id": "uuid",
                "name": "Dataset Name",
                "description": "...",
                "request_count": 100,
                "importable_count": 100,
                "created_at": "2025-11-17T23:09:36.827825Z",
                "organization_id": "uuid",
                "project_id": "uuid"
            }
        ]
    }

    Args:
        jwt_token: JWT authentication token
        project_id: The project UUID

    Returns:
        List of dataset dicts
    """
    endpoint = f"/v2/ai-validation/importable-datasets"
    params = {"project_id": project_id}

    try:
        resp = make_api_request(
            endpoint,
            token=jwt_token,
            method="GET",
            params=params,
            timeout=30,
        )
        data = resp.json()
        datasets = data.get("datasets", [])
        return datasets if isinstance(datasets, list) else []
    except Exception as e:
        print(f"[-] Error fetching importable datasets for project {project_id}: {e}")
        return []


def resolve_dataset_name_to_id(
    jwt_token: str,
    dataset_name: str,
    project_id: str,
) -> Optional[str]:
    """
    Look up a dataset by name within a project and return its ID.
    Returns None if not found.

    Args:
        jwt_token: JWT authentication token
        dataset_name: Name to search for (case-insensitive match)
        project_id: Project UUID to search within

    Returns:
        Dataset UUID (capture_replay_dataset_id) if found, None otherwise
    """
    datasets = list_importable_datasets(jwt_token, project_id)
    dataset_name_lower = dataset_name.strip().lower()

    for ds in datasets:
        if ds.get("name", "").strip().lower() == dataset_name_lower:
            return ds.get("capture_replay_dataset_id")

    return None


def configure_llm_endpoint_dataset(
    jwt_token: str,
    resource_instance_id: str,
    dataset_id: str | None,
) -> dict:
    """
    Configure ONLY the capture-replay dataset for an LLM endpoint resource.

    Safe behavior:
      - dataset_id is None -> preserve existing dataset (no change)
      - dataset_id is ""   -> clear dataset (not recommended for UUID fields; may not be honored)
      - otherwise          -> set to provided dataset UUID
    """
    if dataset_id is None:
        # Preserve (no-op): return current config for visibility.
        return get_llm_endpoint_additional_config(jwt_token, resource_instance_id)

    return patch_llm_endpoint_additional_config(
        jwt_token,
        resource_instance_id,
        dataset_id=dataset_id,
    )


def cleanup_llm_endpoint_dataset(jwt_token: str, resource_instance_id: str) -> dict:
    """
    Clear dataset from resource after pentesting (optional cleanup).

    IMPORTANT:
      - We use JSON null (Python None) for UUID clear semantics.
      - Do NOT call configure_llm_endpoint_dataset(..., None) because None there means "preserve".
    """
    return patch_llm_endpoint_additional_config(
        jwt_token,
        resource_instance_id,
        dataset_id=None,  # JSON null => clear
    )


# ---------- Unified inventory + thin wrappers ----------

def list_resources(
    jwt_token: str,
    *,
    categories: List[str] | None = None,           # e.g., ["llm_endpoint"], ["model","model_assets"]
    organization_id: str | List[str] | None = None,
    project_id: str | List[str] | None = None,
    omit_not_ai: bool = True,
    valid_only: bool | None = None,                # applies to llm_endpoint category
    resource_instance_ids: List[str] | None = None,
    resource_display_names: List[str] | None = None,
) -> list[dict]:
    """
    Unified inventory call for all resource categories.
    - `categories` maps to 'resource_category' query param (list or scalar).
    - Scope filters handled by build_scope_filters (args preferred; config fallback).
    - For llm_endpoint, `valid_only=True` adds 'has_valid_pentest_connection_details'.
    - Optional direct filtering by resource_instance_id or resource_display_name.
    """
    params: Dict[str, Any] = {"omit_not_ai": omit_not_ai}
    if categories:
        params["resource_category"] = categories
    if valid_only is True:
        params["has_valid_pentest_connection_details"] = True
    if resource_instance_ids:
        params["resource_instance_id"] = resource_instance_ids if len(resource_instance_ids) > 1 else resource_instance_ids[0]
    if resource_display_names:
        params["resource_display_name"] = resource_display_names if len(resource_display_names) > 1 else resource_display_names[0]

    # Build scope filters and merge (no mutation in helper)
    params.update(build_scope_filters(organization_id=organization_id, project_id=project_id))

    endpoint = f"/v1/inventory/customer/{config.CUSTOMER_ID}/resources"
    resp = make_api_request(endpoint, token=jwt_token, method="GET", params=params)
    return resp.json().get("resources", [])


def list_llm_endpoints(
    jwt_token: str,
    organization_id: str | None = None,
    project_id: str | None = None,
    valid_only: bool = True,
) -> list[dict]:
    """returns llm_endpoint resources."""
    return list_resources(
        jwt_token,
        categories=["llm_endpoint"],
        organization_id=organization_id,
        project_id=project_id,
        omit_not_ai=True,
        valid_only=valid_only,
    )


def list_models_and_assets(
    jwt_token: str,
    organization_id: str | None = None,
    project_id: str | None = None,
    categories: List[str] | None = None,  # e.g. ["model","model_assets"]
    omit_not_ai: bool = True,
) -> list[dict]:
    """returns model + model_assets resources (or a custom subset)."""
    return list_resources(
        jwt_token,
        categories=categories or ["model", "model_assets"],
        organization_id=organization_id,
        project_id=project_id,
        omit_not_ai=omit_not_ai,
    )


def dedupe_resources(resources: list[dict]) -> list[dict]:
    """Deduplicate by resource_instance_id while keeping the first occurrence."""
    seen = set()
    out: list[dict] = []
    for r in resources:
        rid = r.get("resource_instance_id")
        if rid and rid not in seen:
            seen.add(rid)
            out.append(r)
    return out


def list_pentest_templates(jwt: str) -> List[Dict[str, Any]]:
    if not config.CUSTOMER_ID:
        raise ValueError("CUSTOMER_ID env var is required to list pentest templates")
    resp = make_api_request(
        f"/v2/llm-pentest/customer/{config.CUSTOMER_ID}/templates",
        token=jwt,
        method="GET",
        accept="application/json",
        content_type=None,
        timeout=30,
    )
    data = resp.json()
    return data.get("llm_pentest_scan_templates", [])


# ---- Models & Model Assets helpers ----

def is_pentestable_model_asset(res: dict) -> bool:
    """
    We scan 'model' and 'model_assets' but exclude Model Card Files.
    """
    rtd = (res.get("resource_type_display_name") or "").strip()
    return rtd != "Model Card File"


def model_scan_check_policies(
    jwt_token: str,
    *,
    resource_instance_id: str,
    project_id: str | None,
    policies_to_scan: List[str],
    description: str = "CI Model Scan",
) -> dict:
    """
    POST /v1/posture-management/customers/{CUSTOMER_ID}/model-scanning/check-policies
    Query params: resource_instance_id, project_id (optional)
    Body: { "policies_to_scan": [...], "description": "..." }
    Returns JSON payload from API.
    """
    endpoint = f"/v1/posture-management/customers/{config.CUSTOMER_ID}/model-scanning/check-policies"
    params: Dict[str, Any] = {"resource_instance_id": resource_instance_id}
    if project_id:
        params["project_id"] = project_id

    resp = make_api_request(
        endpoint,
        token=jwt_token,
        method="POST",
        data={"policies_to_scan": policies_to_scan, "description": description},
        params=params,
        accept="application/json",
        content_type="application/json",
        timeout=120,
    )
    return resp.json()


# ---------- v2 GraphQL: Model Scan Full ----------

def query_model_scan_execution_full(jwt_token: str, model_scan_execution_id: str) -> dict:
    """
    Fetch execution outcome, resource, per-policy results for a given model scan execution.
    """
    graphql_query = """
    query ModelScanExecutionResults($customerId: UUID!, $modelScanExecutionId: UUID!) {
      modelScanExecution(filter: {customerId: $customerId, modelScanExecutionId: $modelScanExecutionId}) {
        modelScanExecutionId
        status
        startedAt
        outcomeLevel
      }
      resourceInstanceForModelScanExecution(filter: { customerId: $customerId, modelScanExecutionId: $modelScanExecutionId }) {
        displayName
        resourceInstanceId
      }
      modelScanResultsPerPolicy(filter: { customerId: $customerId, modelScanExecutionId: $modelScanExecutionId }) {
        failedTestCases
        policyName
        passedTestCases
        severity
        failedTestCaseDetails {
          modelScanExecutionId
          modelVulnerability
          modelVulnerabilityDescription
          richDetails {
            attackFlowDiagramMermaidSpec
            backgroundInformation
            findingDescription
            impact
            remediation
            title
          }
        }
      }
    }
    """.strip()
    data = run_graphql(
        jwt_token,
        graphql_query,
        {"customerId": config.CUSTOMER_ID, "modelScanExecutionId": model_scan_execution_id},
        version="v2",
        timeout=60,
    )
    return data or {}


# ---------- v2 GraphQL: PentestScanSummaries ----------

_MODEL_SCAN_SUMMARIES_QUERY = """
query ModelScanSummaries($customerId: UUID!, $organizationId: UUID, $projectId: UUID) {
  modelScanSummaries(
    filter: {
      page: 1
      sortOrder: DESC
      customerId: $customerId
      organizationId: $organizationId
      projectId: $projectId
    }
  ) {
    pagination {
      currentPage
      perPage
      totalItems
    }
    items {
      startedAt
      executionStatus
      modelScanExecutionId
      modelScanExecutionStatus
      modelScanIsCompleted
      modelScanPolicies
      modelScanScope
      numOfIssues
      outcomeLevel
      resourceInstance {
        customerId
        displayName
        registeredAt
        resourceIdentifier
        resourceInstanceId
        resourceType
      }
    }
  }
}
""".strip()


# ---------- v1 GraphQL: Model Scan Details ----------

def query_model_scan_details(jwt_token: str, model_scan_execution_id: str) -> dict:
    """
    /v1/graphql: modelScanDetails - returns startAt, resource, issues, etc.
    """
    query = """
    query ModelScanDetails($customerId: UUID!, $scanId: UUID!) {
      modelScanDetails(filter: { customerId: $customerId, scanId: $scanId }) {
        customerId
        executionStatus
        isCompleted
        issues {
          createdAt
          issueId
          modelConfigurationPolicyName
          modelVulnerabilities
          modelVulnerabilitiesDescriptions
          severity
          status
        }
        numOfIssues
        outcomeLevel
        passed
        policies
        resource {
          displayName
          registeredAt
          resourceInstanceId
          resourceType
        }
        scanId
        scanType
        startAt
        target
        scope
      }
    }""".strip()
    data = run_graphql(
        jwt_token,
        query,
        {"customerId": config.CUSTOMER_ID, "scanId": model_scan_execution_id},
        version="v1",
        timeout=45,
    )
    return (data.get("modelScanDetails") or {})


# ---------- Generic polling wrapper + model-scan ID polling ----------

T = TypeVar("T")


def _poll_until(
    fetch_func: Callable[[], Optional[T]],
    timeout_secs: float,
    interval_secs: float,
) -> Optional[T]:
    """Generic polling helper: repeatedly calls fetch_func until it returns a truthy value or times out."""
    deadline = _t.monotonic() + max(0.0, timeout_secs)
    while _t.monotonic() < deadline:
        try:
            result = fetch_func()
            if result:
                return result
        except Exception:
            # Swallow and keep polling; callers should handle logging/retries if desired.
            pass
        _t.sleep(max(0.0, interval_secs))
    return None


def _try_fetch_model_scan_id_once(
    jwt_token: str,
    *,
    resource_instance_id: str,
    min_started_at_iso: Optional[str] = None,
    project_id: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """
    Fetch the most recent MODEL_SCAN summary rows (DESC, org-scoped if available)
    and return the first that matches the given resource_instance_id.
    If min_started_at_iso is provided, only accept summaries whose startedAt is
    >= that ISO timestamp.
    """
    # Build variables with org context
    # Note: We intentionally make project filtering optional because:
    # 1. resource_instance_id is globally unique
    # 2. Onboarded models may be in different projects than config.PROJECT_IDS
    # 3. Overly restrictive filtering causes false negatives
    variables = {
        "customerId": config.CUSTOMER_ID,
        "organizationId": getattr(config, "ORGANIZATION_ID", None),
        "projectId": project_id,
    }

    data = run_graphql(
        jwt_token,
        _MODEL_SCAN_SUMMARIES_QUERY,
        variables,
        version="v2",
        timeout=60,
    )

    # Extract items from the response
    summaries = data.get("modelScanSummaries") or {}
    items = summaries.get("items") or []

    # Log pagination info for debugging
    pagination = summaries.get("pagination") or {}
    total_items = pagination.get("totalItems", 0)
    if total_items > 0:
        print(f"[model-scan-bind] Found {total_items} total model scan executions in system")

    # Helper: robust ISO8601 parsing (handles trailing 'Z')
    def _to_dt(s: Optional[str]):
        if not s:
            return None
        s2 = s.replace("Z", "+00:00")
        try:
            return datetime.fromisoformat(s2)
        except Exception:
            return None

    min_dt = _to_dt(min_started_at_iso) if min_started_at_iso else None

    # Find matching execution
    for it in items:
        ri = (it.get("resourceInstance") or {})
        if ri.get("resourceInstanceId") != resource_instance_id:
            continue

        # Check timestamp if min_started_at_iso provided
        if min_dt:
            started = _to_dt(it.get("startedAt"))
            # If we can't parse startedAt, be conservative and skip
            if not started or started < min_dt:
                continue

        return it

    return None


def poll_model_scan_execution_id(
    jwt_token: str,
    *,
    resource_instance_id: str,
    poll_interval_secs: float = 6.0,
    timeout_secs: float = 180.0,
    min_started_at_iso: Optional[str] = None,
    project_id: Optional[str] = None,
) -> Optional[str]:
    """
    Poll GraphQL summaries until we can resolve a modelScanExecutionId for the given resource_instance_id.

    Args:
        jwt_token: JWT authentication token
        resource_instance_id: The resource UUID to find execution for
        poll_interval_secs: Seconds between poll attempts
        timeout_secs: Maximum time to poll before giving up
        min_started_at_iso: Optional ISO timestamp - only return executions started after this time

    Returns:
        modelScanExecutionId if found, None if timeout or not found
    """
    print(f"[model-scan-bind] Polling for execution ID (resource: {resource_instance_id[:8]}...)")
    if min_started_at_iso:
        print(f"[model-scan-bind] Only considering executions started >= {min_started_at_iso}")

    def _fetch() -> Optional[str]:
        row = _try_fetch_model_scan_id_once(
            jwt_token,
            resource_instance_id=resource_instance_id,
            min_started_at_iso=min_started_at_iso,
            project_id=project_id,
        )
        if row:
            msid = row.get("modelScanExecutionId")
            if msid:
                status = row.get("modelScanExecutionStatus") or "UNKNOWN"
                print(f"[model-scan-bind] Found execution {msid[:8]}... (status: {status})")
            return msid or None
        return None

    result = _poll_until(_fetch, timeout_secs=timeout_secs, interval_secs=poll_interval_secs)

    if not result:
        print(f"[model-scan-bind] Failed to resolve execution ID after {timeout_secs}s")

    return result
