import os
from typing import Dict, List, Optional
from dotenv import load_dotenv

from src.alltrue_scanner.utils import parse_csv_string

# Load .env file only if running locally
if os.getenv("CI") != "true":  # GitHub Actions sets CI=true
    load_dotenv()

# ---------------------------
# Core connection
# ---------------------------
API_URL  = os.getenv("API_URL", "https://api.prod.alltrue-be.com").rstrip("/")
API_KEY  = os.getenv("API_KEY", "")
CUSTOMER_ID = os.getenv("CUSTOMER_ID", "")

if not all([API_URL, API_KEY, CUSTOMER_ID]):
    raise ValueError("Missing one or more required endpoint environment variables.")

LOG_JWT_THREADS = True

# ---------------------------
# Execution toggles
# ---------------------------
ENABLE_LLM_PENTEST = os.getenv("ENABLE_LLM_PENTEST", "true").lower() == "true"
ENABLE_MODEL_SCANNING = os.getenv("ENABLE_MODEL_SCANNING", "false").lower() == "true"

# ---------------------------
# Inventory selection
# ---------------------------
INVENTORY_SCOPE = os.getenv("INVENTORY_SCOPE", "organization")  # organization|project|resource

# Organization - can be ID or name (will be resolved)
ORGANIZATION_ID = os.getenv("ORGANIZATION_ID") or None
ORGANIZATION_NAME = os.getenv("ORGANIZATION_NAME") or None

# Projects - can be IDs or names (will be resolved)
PROJECT_IDS: List[str] = parse_csv_string(os.getenv("PROJECT_IDS", ""))
PROJECT_NAMES: List[str] = parse_csv_string(os.getenv("PROJECT_NAMES", ""))

# Resources
TARGET_RESOURCE_IDS: List[str] = [s.lower() for s in parse_csv_string(os.getenv("TARGET_RESOURCE_IDS", ""))]
TARGET_RESOURCE_NAMES: List[str] = parse_csv_string(os.getenv("TARGET_RESOURCE_NAMES", ""))

# ---------------------------
# Model scanning (posture mgmt)
# ---------------------------
MODEL_SCAN_POLICIES: List[str] = parse_csv_string(os.getenv("MODEL_SCAN_POLICIES", "model-scan-code-execution-prohibited,model-scan-input-output-operations-prohibited,model-scan-network-access-prohibited,model-scan-malware-signatures-prohibited,model-custom-layers-prohibited"))
MODEL_SCAN_DESCRIPTION = os.getenv("MODEL_SCAN_DESCRIPTION", "CI Model Scan")

# ---------------------------
# HuggingFace Model Onboarding (optional)
# ---------------------------
# Enable onboarding of HuggingFace models before scanning
HUGGINGFACE_ONBOARDING_ENABLED = os.getenv("HUGGINGFACE_ONBOARDING_ENABLED", "false").lower() == "true"

# HuggingFace models to onboard
# Format options:
#   1. Simple: "org1/repo1,org2/repo2@revision"
#   2. JSON: '[{"organization_id":"org1","repo_name":"repo1","revision":"main","display_name":"Custom Name"}]'
HUGGINGFACE_MODELS_TO_ONBOARD = os.getenv("HUGGINGFACE_MODELS_TO_ONBOARD", "")

# Wait time after onboarding before scanning (seconds)
# Allows time for models to be indexed in inventory
HUGGINGFACE_ONBOARDING_WAIT_SECS = float(os.getenv("HUGGINGFACE_ONBOARDING_WAIT_SECS", "10"))

# Project ID to associate onboarded models with
# If not specified, uses the first project from PROJECT_IDS
HUGGINGFACE_ONBOARDING_PROJECT_ID = os.getenv("HUGGINGFACE_ONBOARDING_PROJECT_ID", "")

# Project name to associate onboarded models with (preferred over UUID)
# If both name and ID are provided, NAME takes precedence.
# If neither is specified, uses the first project from PROJECT_IDS/PROJECT_NAMES.
HUGGINGFACE_ONBOARDING_PROJECT_NAME = os.getenv("HUGGINGFACE_ONBOARDING_PROJECT_NAME", "").strip()

# Skip inventory selection and only scan onboarded HuggingFace models
# When true, no models from inventory will be selected - only onboarded models will be scanned
HUGGINGFACE_ONBOARDING_ONLY = os.getenv("HUGGINGFACE_ONBOARDING_ONLY", "false").lower() == "true"


HAS_VALID_PENTEST_CONNECTION_DETAILS = True

# ---------------------------
# Pentest run parameters
# ---------------------------
TARGET_TEMPLATE_NAME = os.getenv("TARGET_TEMPLATE_NAME", "Prompt Injection")
MAX_CONCURRENT_PENTESTS = int(os.getenv("MAX_CONCURRENT_PENTESTS", "5"))

# Pentest connection details - Model mapping by resource type
# Format: "ResourceType1:model1,ResourceType2:model2"
# Example: "OpenAIEndpoint:gpt-4,AnthropicEndpoint:claude-3-5-sonnet-latest"
PENTEST_MODEL_MAPPING_STR = os.getenv("PENTEST_MODEL_MAPPING", "")

def parse_model_mapping(mapping_str: str) -> Dict[str, str]:
    """
    Parse model mapping string into dict.
    Format: "ResourceType1:model1,ResourceType2:model2"
    Returns: {"ResourceType1": "model1", "ResourceType2": "model2"}
    """
    if not mapping_str:
        return {}
    
    mapping = {}
    for pair in mapping_str.split(","):
        pair = pair.strip()
        if ":" not in pair:
            continue
        resource_type, model = pair.split(":", 1)
        mapping[resource_type.strip()] = model.strip()
    
    return mapping

PENTEST_MODEL_MAPPING: Dict[str, str] = parse_model_mapping(PENTEST_MODEL_MAPPING_STR)

PENTEST_SYSTEM_PROMPT_ENABLED = os.getenv("PENTEST_SYSTEM_PROMPT_ENABLED", "false").lower() == "true"
# Optional: custom system prompt text
PENTEST_SYSTEM_PROMPT_TEXT: Optional[str] = (os.getenv("PENTEST_SYSTEM_PROMPT_TEXT", "").strip() or None)
# Optional: Clear system prompt from resource after pentest completes
PENTEST_CLEANUP_SYSTEM_PROMPT = os.getenv("PENTEST_CLEANUP_SYSTEM_PROMPT", "true").lower() == "true"

# Optional: resource system description (llm_endpoint_resource_system_description)
PENTEST_RESOURCE_SYSTEM_DESCRIPTION_ENABLED = os.getenv("PENTEST_RESOURCE_SYSTEM_DESCRIPTION_ENABLED", "false").lower() == "true"
PENTEST_RESOURCE_SYSTEM_DESCRIPTION_TEXT: Optional[str] = (os.getenv("PENTEST_RESOURCE_SYSTEM_DESCRIPTION_TEXT", "").strip() or None)
PENTEST_CLEANUP_RESOURCE_SYSTEM_DESCRIPTION = os.getenv("PENTEST_CLEANUP_RESOURCE_SYSTEM_DESCRIPTION", "false").lower() == "true"

# Dataset configuration for capture-replay pentesting
PENTEST_DATASET_ENABLED = os.getenv("PENTEST_DATASET_ENABLED", "false").lower() == "true"
# Dataset ID or name (will be resolved to ID at runtime)
PENTEST_DATASET_ID = os.getenv("PENTEST_DATASET_ID", "")
PENTEST_DATASET_NAME = os.getenv("PENTEST_DATASET_NAME", "")
# Optional: Clear dataset from resource after pentest completes
PENTEST_CLEANUP_DATASET = os.getenv("PENTEST_CLEANUP_DATASET", "true").lower() == "true"

PENTEST_APPLY_GUARDRAILS = os.getenv("PENTEST_APPLY_GUARDRAILS", "false").lower() == "true"

# Number of attempts per test case (1 = run once, 2+ = rerun to account for LLM variability)
PENTEST_NUM_ATTEMPTS = int(os.getenv("PENTEST_NUM_ATTEMPTS", "1"))

# Optional stagger between start requests (seconds)
START_STAGGER_SECS = float(os.getenv("START_STAGGER_SECS", "0"))

# Start retry behavior for start-pentest failures classified as retryable
MAX_START_RETRIES = int(os.getenv("MAX_START_RETRIES", "3"))
START_RETRY_DELAY = float(os.getenv("START_RETRY_DELAY", "30"))

# Polling behavior
# We poll GraphQL directly as the source of truth
GRAPHQL_POLL_INTERVAL_SECS = float(os.getenv("GRAPHQL_POLL_INTERVAL_SECS", "30"))  # Poll every 30 seconds
POLL_TIMEOUT_SECS = float(os.getenv("POLL_TIMEOUT_SECS", "5400"))  # 90 minutes
POLL_STATUS_LOG_EVERY = 10  # Log every 10 polls (5 minutes at 30s interval)
POLL_TIMEOUT_ACTION = os.getenv("POLL_TIMEOUT_ACTION", "fail")  # fail|continue|partial

# ---------------------------
# Outcome thresholding
# ---------------------------
# Lower index means more severe
SEVERITY_ORDER = ["Critical", "Poor", "Moderate", "Good", "Excellent"]
SEVERITY_INDEX: Dict[str, int] = {name.lower(): i for i, name in enumerate(SEVERITY_ORDER)}

def normalize_outcome(level: str | None) -> str:
    """Return a canonical outcome ('critical'|'poor'|'moderate'|'good'|'excellent') or '' if unknown."""
    if not level:
        return ""
    s = level.strip().lower()
    return s if s in {"critical", "poor", "moderate", "good", "excellent"} else ""

# Fail the job if worst KNOWN outcome is at/above this threshold (set empty to ignore outcomes)
FAIL_OUTCOME_AT_OR_ABOVE = os.getenv("FAIL_OUTCOME_AT_OR_ABOVE", "").strip()  # e.g., "moderate"

# --- GitHub integration / end-of-run actions ---
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN", "")
GITHUB_REPOSITORY = os.getenv("GITHUB_REPOSITORY", "")  # "owner/repo"

# What to do when outcomes breach the threshold:
#   - "fail"  : fail pipeline only
#   - "issue" : open GH issues only
#   - "both"  : fail AND open GH issues
#   - "none"  : do nothing
ON_THRESHOLD_ACTION = os.getenv("ON_THRESHOLD_ACTION", "fail").strip().lower()

# What to do on hard failures (start errors, exceptions, etc.):
#   - "ignore" (default), "issue", "fail", "both"
ON_HARD_FAILURES_ACTION = os.getenv("ON_HARD_FAILURES_ACTION", "ignore").strip().lower()

# Optional issue cosmetics
# ⬇️ default to **no custom labels**; users can set GITHUB_DEFAULT_LABELS in .env
GITHUB_DEFAULT_LABELS = parse_csv_string(os.getenv("GITHUB_DEFAULT_LABELS", ""))
GITHUB_ASSIGNEES = parse_csv_string(os.getenv("GITHUB_ASSIGNEES", ""))

# ---------------------------
# Category severity filtering for per-category GitHub issues
# ---------------------------
# Order from most to least severe:
CATEGORY_SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]
CATEGORY_SEVERITY_INDEX: Dict[str, int] = {name: i for i, name in enumerate(CATEGORY_SEVERITY_ORDER)}

def normalize_category_severity(s: str | None) -> str:
    """Return normalized category severity (CRITICAL|HIGH|MEDIUM|LOW|INFORMATIONAL) or '' if unknown."""
    if not s:
        return ""
    up = s.strip().upper()
    return up if up in CATEGORY_SEVERITY_INDEX else ""

# Minimum category/policy severity to create per-category/per-policy GitHub issues.
# Default "INFORMATIONAL" (creates for all severities).
# Set to "NONE" to disable per-category/per-policy issues entirely (job-level issues may still be created).
_CATEGORY_ISSUE_MIN_SEVERITY_RAW = os.getenv("CATEGORY_ISSUE_MIN_SEVERITY", "INFORMATIONAL").strip()
if _CATEGORY_ISSUE_MIN_SEVERITY_RAW.lower() in ("", "none", "disabled", "disable", "off", "false", "0"):
    CATEGORY_ISSUES_ENABLED = False
    CATEGORY_ISSUE_MIN_SEVERITY: str | None = None
else:
    CATEGORY_ISSUES_ENABLED = True
    CATEGORY_ISSUE_MIN_SEVERITY = normalize_category_severity(_CATEGORY_ISSUE_MIN_SEVERITY_RAW)

def print_config_banner() -> None:
    print("=" * 80)
    print("CONFIG")
    print("=" * 80)
    print(f"API_URL: {API_URL}")
    print(f"CUSTOMER_ID set: {'yes' if CUSTOMER_ID else 'no'}")
    print(f"ENABLE_LLM_PENTEST: {ENABLE_LLM_PENTEST}")
    if ENABLE_LLM_PENTEST:
        print(f"HAS_VALID_PENTEST_CONNECTION_DETAILS: {HAS_VALID_PENTEST_CONNECTION_DETAILS}")
        print(f"TARGET_TEMPLATE_NAME: {TARGET_TEMPLATE_NAME}")
        print(f"PENTEST_NUM_ATTEMPTS: {PENTEST_NUM_ATTEMPTS}")
        if PENTEST_MODEL_MAPPING:
            print(f"PENTEST_MODEL_MAPPING:")
            for resource_type, model in PENTEST_MODEL_MAPPING.items():
                print(f"  - {resource_type}: {model}")
        print(f"PENTEST_SYSTEM_PROMPT_ENABLED: {PENTEST_SYSTEM_PROMPT_ENABLED}")
        if PENTEST_SYSTEM_PROMPT_TEXT:
            print(f"PENTEST_SYSTEM_PROMPT_TEXT: {PENTEST_SYSTEM_PROMPT_TEXT[:100]}...")
        print(f"PENTEST_RESOURCE_SYSTEM_DESCRIPTION_ENABLED: {PENTEST_RESOURCE_SYSTEM_DESCRIPTION_ENABLED}")
        if PENTEST_RESOURCE_SYSTEM_DESCRIPTION_TEXT:
            print(f"PENTEST_RESOURCE_SYSTEM_DESCRIPTION_TEXT: {PENTEST_RESOURCE_SYSTEM_DESCRIPTION_TEXT[:100]}...")
        print(f"PENTEST_CLEANUP_RESOURCE_SYSTEM_DESCRIPTION: {PENTEST_CLEANUP_RESOURCE_SYSTEM_DESCRIPTION}")
        print(f"PENTEST_DATASET_ENABLED: {PENTEST_DATASET_ENABLED}")
        if PENTEST_DATASET_ENABLED:
            if PENTEST_DATASET_ID:
                print(f"PENTEST_DATASET_ID: {PENTEST_DATASET_ID}")
            if PENTEST_DATASET_NAME:
                print(f"PENTEST_DATASET_NAME: {PENTEST_DATASET_NAME}")
            print(f"PENTEST_CLEANUP_DATASET: {PENTEST_CLEANUP_DATASET}")
        print(f"PENTEST_APPLY_GUARDRAILS: {PENTEST_APPLY_GUARDRAILS}")
    print(f"ENABLE_MODEL_SCANNING: {ENABLE_MODEL_SCANNING}")
    if ENABLE_MODEL_SCANNING:
        print(f"MODEL_SCAN_POLICIES: {MODEL_SCAN_POLICIES or '(none)'}")
        print(f"MODEL_SCAN_DESCRIPTION: {MODEL_SCAN_DESCRIPTION}")
    if HUGGINGFACE_ONBOARDING_ENABLED:
        print(f"HUGGINGFACE_ONBOARDING_ENABLED: {HUGGINGFACE_ONBOARDING_ENABLED}")
        print(f"HUGGINGFACE_MODELS_TO_ONBOARD: {HUGGINGFACE_MODELS_TO_ONBOARD}")
        if HUGGINGFACE_ONBOARDING_PROJECT_NAME:
            print(f"HUGGINGFACE_ONBOARDING_PROJECT_NAME: {HUGGINGFACE_ONBOARDING_PROJECT_NAME}")
        if HUGGINGFACE_ONBOARDING_PROJECT_ID:
            print(f"HUGGINGFACE_ONBOARDING_PROJECT_ID: {HUGGINGFACE_ONBOARDING_PROJECT_ID}")
        print(f"HUGGINGFACE_ONBOARDING_WAIT_SECS: {HUGGINGFACE_ONBOARDING_WAIT_SECS}")
        print(f"HUGGINGFACE_ONBOARDING_ONLY: {HUGGINGFACE_ONBOARDING_ONLY}")
    print(f"INVENTORY_SCOPE: {INVENTORY_SCOPE}")
    if ORGANIZATION_ID:
        print(f"ORGANIZATION_ID: {ORGANIZATION_ID}")
    if ORGANIZATION_NAME:
        print(f"ORGANIZATION_NAME: {ORGANIZATION_NAME}")
    if PROJECT_IDS:
        print(f"PROJECT_IDS: {PROJECT_IDS}")
    if PROJECT_NAMES:
        print(f"PROJECT_NAMES: {PROJECT_NAMES}")
    if TARGET_RESOURCE_IDS or TARGET_RESOURCE_NAMES:
        print(f"TARGET_RESOURCE_IDS: {TARGET_RESOURCE_IDS}")
        print(f"TARGET_RESOURCE_NAMES: {TARGET_RESOURCE_NAMES}")
    print(f"MAX_CONCURRENT_PENTESTS: {MAX_CONCURRENT_PENTESTS}")
    if START_STAGGER_SECS:
        print(f"START_STAGGER_SECS: {START_STAGGER_SECS}")
    print(f"POLL_TIMEOUT_SECS: {POLL_TIMEOUT_SECS}")
    print(f"GRAPHQL_POLL_INTERVAL_SECS: {GRAPHQL_POLL_INTERVAL_SECS}")
    if FAIL_OUTCOME_AT_OR_ABOVE:
        print(f"FAIL_OUTCOME_AT_OR_ABOVE: {FAIL_OUTCOME_AT_OR_ABOVE}")
    else:
        print("FAIL_OUTCOME_AT_OR_ABOVE: (none)")
    print(f"ON_THRESHOLD_ACTION: {ON_THRESHOLD_ACTION}")
    print(f"ON_HARD_FAILURES_ACTION: {ON_HARD_FAILURES_ACTION}")
    # GitHub integration presence (no secrets printed)
    print(f"GITHUB_REPOSITORY: {GITHUB_REPOSITORY or '(not set)'}")
    print(f"GITHUB_TOKEN set: {'yes' if GITHUB_TOKEN else 'no'}")
    print(f"CATEGORY_ISSUES_ENABLED: {CATEGORY_ISSUES_ENABLED}")
    print(f"CATEGORY_ISSUE_MIN_SEVERITY: {CATEGORY_ISSUE_MIN_SEVERITY or '(none)'}")
    if GITHUB_DEFAULT_LABELS:
        print(f"GITHUB_DEFAULT_LABELS: {GITHUB_DEFAULT_LABELS}")
    if GITHUB_ASSIGNEES:
        print(f"GITHUB_ASSIGNEES: {GITHUB_ASSIGNEES}")
    print("=" * 80)