# Orchestrates model scanning (check-policies -> poll job-status) and now:
# - Binds a scan to the correct GraphQL execution using a lower-bound startedAt
# - Uses GraphQL outcomeLevel to decide PASS/FAIL
# - Builds violations from modelScanResultsPerPolicy
#
# Depends on: config.py, api.py

from __future__ import annotations
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional, Tuple

import src.alltrue_scanner.api as api
import src.alltrue_scanner.config as config
from src.alltrue_scanner.inventory import select_with_scope


# ---------------------------
# Inventory selection
# ---------------------------

def _resource_name(r: dict) -> str:
    return (
        r.get("resource_display_name")
        or r.get("resource_type_display_name")
        or r.get("resource_type")
        or "Unnamed"
    )


def select_models_and_assets(jwt: str) -> Tuple[List[str], Dict[str, str]]:
    """
    Mirrors LLM endpoint selection but for models / model_assets.
    Excludes "Model Card File" via api.is_pentestable_model_asset.
    Returns (selected_ids, id->name mapping).
    """
    return select_with_scope(
        jwt=jwt,
        entity_label="model/model_asset resources",
        list_fn=api.list_models_and_assets,          # kwargs: jwt_token, organization_id?, project_id?
        dedupe_fn=api.dedupe_resources,
        include_predicate=api.is_pentestable_model_asset,  # exclude non-pentestable assets
        name_getter=_resource_name,
    )


# ---------------------------
# Outcome/violation helpers (GraphQL)
# ---------------------------

def _fail_threshold() -> str:
    """Return configured threshold or empty string if not set (aligned with summary.py)."""
    env = (config.FAIL_OUTCOME_AT_OR_ABOVE or "").strip().lower()
    return env  # Return empty string if not set


def _fails_from_outcome(outcome_level: str | None) -> bool:
    """Check if outcome fails threshold. Returns False if no threshold set."""
    thr = _fail_threshold()
    if not thr:  # No threshold configured
        return False
    norm = config.normalize_outcome(outcome_level)
    if not norm:
        return False
    i_norm = config.SEVERITY_INDEX.get(norm)
    i_thr = config.SEVERITY_INDEX.get(thr)
    return (i_norm is not None and i_thr is not None and i_norm <= i_thr)


def _violations_from_gql_per_policy(per_policy: List[dict]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for row in per_policy or []:
        failed = int(row.get("failedTestCases") or 0)
        passed = int(row.get("passedTestCases") or 0)
        total = (
            failed + passed
            if (row.get("failedTestCases") is not None and row.get("passedTestCases") is not None)
            else int(row.get("totalTestCases") or (failed + passed))
        )
        if failed <= 0:
            continue

        policy = (row.get("policyName") or "").strip() or "UNKNOWN_POLICY"
        severity = (row.get("severity") or "").strip().upper() or ""
        detail_blocks: List[str] = []
        examples = row.get("failedTestCaseDetails") or []

        # Build up to 5 “detail blocks” from richDetails (model-scan flavor)
        for ex in examples[:5]:
            rich = ex.get("richDetails") or {}
            title = (rich.get("title") or "").strip()
            finding = (rich.get("findingDescription") or "").strip()
            impact = (rich.get("impact") or "").strip()
            remediation = (rich.get("remediation") or "").strip()
            background = (rich.get("backgroundInformation") or "").strip()
            vuln = ex.get("modelVulnerability")
            desc = ex.get("modelVulnerabilityDescription")
            parts = []
            if title:
                parts.append(f"### {title}")
            if finding:
                parts.append(finding)
            if vuln or desc:
                parts.append("\n**Vulnerability:** " + " -- ".join([p for p in [vuln, desc] if p]))
            if impact:
                parts.append("\n**Impact:**\n" + impact)
            if remediation:
                parts.append("\n**Remediation:**\n" + remediation)
            if background:
                parts.append("\n**Background:**\n" + background)
            detail_blocks.append("\n".join(parts).strip())

        examples_total = len(examples)
        examples_shown = min(5, examples_total)

        out.append(
            {
                "policy": policy,
                "status": "UNRESOLVED",
                "severity": severity,
                "details": "\n\n".join([b for b in detail_blocks if b]).strip(),
                "detail_blocks": detail_blocks,
                "examples_total": examples_total,
                "examples_shown": examples_shown,
                "failed": failed,
                "passed": passed,
                "total": total if total else (failed + passed),
            }
        )
    return out


# ---------------------------
# Single-resource scanner (GraphQL-only)
# ---------------------------

def run_model_scan_for_resource(
    jwt: str,
    resource_id: str,
    resource_name: str,
    project_hint: Optional[str],
) -> Dict[str, Any]:
    """
    Start a model check-policies scan, then resolve modelScanExecutionId via GraphQL.
    Poll GraphQL until the execution status is COMPLETED, then:
      - mark PASS/FAIL strictly from outcomeLevel (with threshold)
      - collect violations from modelScanResultsPerPolicy.failedTestCases
    """
    try:
        start_resp = api.model_scan_check_policies(
            jwt_token=jwt,
            resource_instance_id=resource_id,
            project_id=project_hint,
            policies_to_scan=config.MODEL_SCAN_POLICIES,
            description=config.MODEL_SCAN_DESCRIPTION,
        )
    except Exception as e:
        return {
            "resource_id": resource_id,
            "resource_name": resource_name,
            "status": "ERROR",
            "error": f"start_error: {e}",
        }

    job_id = start_resp.get("job_id")
    # We may get a tentative execution id; we will re-resolve via summaries
    model_scan_execution_id = (
        start_resp.get("model_scan_execution_id")
        or start_resp.get("modelScanExecutionId")
        or None
    )

    # Establish a conservative lower bound for binding to the correct execution.
    # Use UTC now minus a small skew to avoid clock drift issues.
    lower_bound_dt = time.gmtime(time.time() - 60)
    lower_bound_iso = time.strftime("%Y-%m-%dT%H:%M:%S+00:00", lower_bound_dt)

    # Resolve execution id via summaries (polling)
    # Note: We intentionally pass project_id=None to search org-wide because:
    # 1. Onboarded models may be in different projects than project_hint
    # 2. resource_instance_id is globally unique, so org-wide search is safe
    # 3. Project filtering can cause false negatives for cross-project scenarios
    msid = api.poll_model_scan_execution_id(
        jwt_token=jwt,
        resource_instance_id=resource_id,
        poll_interval_secs=max(2.0, float(config.GRAPHQL_POLL_INTERVAL_SECS)),
        timeout_secs=float(config.POLL_TIMEOUT_SECS),
        min_started_at_iso=lower_bound_iso,
        project_id=None,  # <- Search org-wide for reliable execution binding
    )
    if msid:
        model_scan_execution_id = msid
        print(f"[ModelScan]    {resource_name}: bound modelScanExecutionId via GraphQL -> {msid}")

    if not model_scan_execution_id:
        return {
            "resource_id": resource_id,
            "resource_name": resource_name,
            "status": "ERROR",
            "error": "unable_to_bind_model_scan_execution_id",
            "job_id": job_id,
        }

    # GraphQL polling for completion
    POLL_INTERVAL_SECS = config.GRAPHQL_POLL_INTERVAL_SECS
    POLL_TIMEOUT_SECS = config.POLL_TIMEOUT_SECS
    start_ts = time.time()

    def _gql_fetch():
        try:
            data = api.query_model_scan_execution_full(jwt, model_scan_execution_id)
        except Exception:
            return None, None, None
        exec_info = data.get("modelScanExecution") or {}
        status = (exec_info.get("status") or "").upper()
        return data, exec_info, status

    data, exec_info, status = None, None, None
    while True:
        elapsed = time.time() - start_ts
        if elapsed >= POLL_TIMEOUT_SECS:
            return {
                "resource_id": resource_id,
                "resource_name": resource_name,
                "status": "POLL_TIMEOUT",
                "error": f"Timed out after {int(POLL_TIMEOUT_SECS)}s polling GraphQL for execution {model_scan_execution_id}",
                "scan_execution_id": model_scan_execution_id,
                "job_id": job_id,
            }

        data, exec_info, status = _gql_fetch()
        if status == "COMPLETED" and data is not None:
            break
        time.sleep(POLL_INTERVAL_SECS)

    per_policy = data.get("modelScanResultsPerPolicy") or []
    outcome = (exec_info or {}).get("outcomeLevel")
    violations = _violations_from_gql_per_policy(per_policy)
    failed = _fails_from_outcome(outcome)

    return {
        "resource_id": resource_id,
        "resource_name": resource_name,
        "status": "FAILED" if failed else "PASSED",
        "outcome": outcome or "Unknown",
        "scan_execution_id": model_scan_execution_id,
        "job_status": "MODEL_SCAN_COMPLETED",
        "job_id": job_id,
        "violations": violations,
        "raw_return_value": {"graphql": data},
    }


# ---------------------------


# ---------------------------
# CSV generation
# ---------------------------

def write_model_scan_csv(
    resource_name: str,
    resource_id: str,
    scan_execution_id: str,
    result: Dict[str, Any],
) -> Optional[str]:
    """
    Write model scan results to CSV file.
    Creates one row per policy (both violations and passed policies).
    
    Returns the filename if successful, None otherwise.
    """
    import csv
    from datetime import datetime, timezone
    
    # Get violations (failed policies only)
    violations = result.get("violations", [])
    
    # Also get ALL policies from the GraphQL data if available
    all_policies = []
    graphql_data = result.get("raw_return_value", {}).get("graphql", {})
    per_policy_results = graphql_data.get("modelScanResultsPerPolicy", [])
    
    if per_policy_results:
        # Use the complete per-policy results from GraphQL (includes both failed and passed)
        for policy_result in per_policy_results:
            failed = int(policy_result.get("failedTestCases", 0))
            passed = int(policy_result.get("passedTestCases", 0))
            total = failed + passed
            
            # Find matching violation for details (if this policy failed)
            details = ""
            status = "PASSED" if failed == 0 else "UNRESOLVED"
            for v in violations:
                if v.get("policy") == policy_result.get("policyName"):
                    details = v.get("details", "")
                    status = v.get("status", status)
                    break
            
            all_policies.append({
                "policy": policy_result.get("policyName", ""),
                "status": status,
                "severity": policy_result.get("severity", ""),
                "failed": failed,
                "passed": passed,
                "total": total,
                "details": details,
            })
    elif violations:
        # Fallback: only have violations data
        all_policies = violations
    else:
        # No data at all - create a single summary row
        all_policies = [{
            "policy": "All policies",
            "status": result.get("status", "PASSED"),
            "severity": "",
            "failed": 0,
            "passed": 0,
            "total": 0,
            "details": "No detailed policy results available",
        }]
    
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    fname = f"model_scan_results_{api.sanitize_name(resource_name)}_{resource_id[:8]}_{scan_execution_id[:8] if scan_execution_id else 'unknown'}_{ts}.csv"
    
    try:
        with open(fname, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            
            # Write header
            writer.writerow([
                "Resource Name",
                "Resource ID",
                "Scan Execution ID",
                "Overall Status",
                "Overall Outcome",
                "Policy Name",
                "Policy Status",
                "Severity",
                "Failed Test Cases",
                "Passed Test Cases",
                "Total Test Cases",
                "Vulnerability Details",
            ])
            
            # Write one row per policy (both failed and passed)
            for policy in all_policies:
                writer.writerow([
                    resource_name,
                    resource_id,
                    scan_execution_id or "",
                    result.get("status", ""),
                    result.get("outcome", ""),
                    policy.get("policy", ""),
                    policy.get("status", ""),
                    policy.get("severity", ""),
                    policy.get("failed", 0),
                    policy.get("passed", 0),
                    policy.get("total", 0),
                    policy.get("details", ""),
                ])
        
        print(f"[ModelScan][+] CSV saved as {fname}")
        return fname
    except Exception as e:
        print(f"[ModelScan][-] Error writing CSV {fname}: {e}")
        return None


# Parallel executor
# ---------------------------

def run_model_scans(jwt: str, selected_ids: List[str], mapping: Dict[str, str]) -> List[Dict[str, Any]]:
    project_hint = config.PROJECT_IDS[0] if config.PROJECT_IDS else None
    if project_hint:
        print(f"[i] Using project hint for model scans: {project_hint}")

    print(f"\n{'='*80}")
    print(f"STARTING MODEL SCANS FOR {len(selected_ids)} RESOURCES")
    print(f"Max parallel: {config.MAX_CONCURRENT_PENTESTS}")
    print(f"{'='*80}")

    results: List[Dict[str, Any]] = []
    results_by_id: Dict[str, Dict[str, Any]] = {}

    with ThreadPoolExecutor(max_workers=config.MAX_CONCURRENT_PENTESTS, thread_name_prefix="ModelScan") as ex:
        futs = {
            ex.submit(run_model_scan_for_resource, jwt, rid, mapping[rid], project_hint): rid
            for rid in selected_ids
        }
        for fut in as_completed(futs):
            res = fut.result()

            rid = res.get("resource_id")
            if rid:
                results_by_id.setdefault(rid, res)
            else:
                results.append(res)
                continue

            rn = mapping.get(rid, rid or "<unknown>")
            outcome = results_by_id[rid].get("status")
            line = f"[ModelScan] {rn} -> {outcome}"
            if results_by_id[rid].get("violations"):
                pols = ", ".join(x.get("policy", "?") for x in results_by_id[rid]["violations"])
                if outcome == "PASSED":
                    line += f" (violations noted: {pols}; overall outcome below fail threshold)"
                else:
                    line += f" (violations: {pols})"
            if results_by_id[rid].get("error"):
                line += f" [error: {results_by_id[rid].get('error')}]"
            print(line)
            
            # Generate CSV for this scan result
            if rid and results_by_id[rid].get("scan_execution_id"):
                write_model_scan_csv(
                    resource_name=rn,
                    resource_id=rid,
                    scan_execution_id=results_by_id[rid].get("scan_execution_id"),
                    result=results_by_id[rid],
                )

    for rid in selected_ids:
        if rid in results_by_id:
            results.append(results_by_id[rid])

    return results