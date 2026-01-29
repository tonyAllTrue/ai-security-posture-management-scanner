import textwrap
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import requests

import src.alltrue_scanner.auth as auth
import src.alltrue_scanner.api as api
import src.alltrue_scanner.config as config

API_ROOT = "https://api.github.com"


def _gh_headers() -> Dict[str, str]:
    return {
        "Authorization": f"Bearer {config.GITHUB_TOKEN}",
        "Accept": "application/vnd.github+json",
        "User-Agent": "alltrue-ci-modelscan/1.0",
    }


def github_ready() -> bool:
    return bool(config.GITHUB_TOKEN and config.GITHUB_REPOSITORY)


def _post_issue(title: str, body: str, labels: List[str]) -> Tuple[bool, str]:
    url = f"{API_ROOT}/repos/{config.GITHUB_REPOSITORY}/issues"
    payload: Dict[str, Any] = {"title": title, "body": body, "labels": labels}
    if config.GITHUB_ASSIGNEES:
        payload["assignees"] = config.GITHUB_ASSIGNEES
    r = requests.post(url, headers=_gh_headers(), json=payload, timeout=30)
    if r.status_code == 201:
        num = r.json().get("number")
        return True, f"Created issue #{num}: {title}"
    return False, f"Failed ({r.status_code}): {r.text}"


def _search_issue_by_marker(marker: str) -> bool:
    """
    Dedup helper: returns True if any **open** issue already contains the marker in the body.
    """
    try:
        q = f'repo:{config.GITHUB_REPOSITORY} "{marker}" in:body is:issue is:open'
        url = f"{API_ROOT}/search/issues"
        r = requests.get(url, headers=_gh_headers(), params={"q": q, "per_page": 1}, timeout=20)
        if r.status_code != 200:
            print(f"[!]  GitHub search (open-only) failed ({r.status_code}): {r.text}")
            return False
        data = r.json() or {}
        return (data.get("total_count") or 0) > 0
    except Exception as e:
        print(f"[!]  GitHub search (open-only) error: {e}")
        return False


def _format_result_line(r: dict) -> str:
    rid = r.get("resource_id") or "?"
    name = r.get("resource_name") or "?"
    status = r.get("status") or "?"
    out = r.get("outcome") or "Unknown"
    jid = r.get("job_id") or "-"
    sid = r.get("scan_execution_id") or "-"
    return f"- **{name}** (id: `{rid}`) - status: `{status}`, outcome: **{out}**, job: `{jid}`, exec: `{sid}`"


def _make_title(prefix: str, severity: Optional[str], resource_name: str, *, tag: str = "[Pentest]") -> str:
    sev = severity.capitalize() if severity else "Unknown"
    return f"{tag} {prefix}: {sev} - {resource_name}"


def _category_severity_meets_min(sev: str) -> bool:
    # Allow callers to disable per-category/per-policy issues entirely.
    if not getattr(config, "CATEGORY_ISSUES_ENABLED", True):
        return False
    norm = config.normalize_category_severity(sev)
    if not norm:
        return False
    min_norm = getattr(config, "CATEGORY_ISSUE_MIN_SEVERITY", None)
    if not min_norm:
        return False
    return config.CATEGORY_SEVERITY_INDEX[norm] <= config.CATEGORY_SEVERITY_INDEX[min_norm]


def _source_label_for_prefix(prefix_tag: str) -> str:
    return "model-scan" if prefix_tag.strip("[]").strip().lower() == "model scan" else "pentest"


def _with_labels(*label_groups: List[str]) -> List[str]:
    s = {lbl for group in label_groups for lbl in group if lbl}
    return list(s)


# ===== Unified body helpers =====

def _kv_line(label: str, value: Optional[str]) -> str:
    return f"**{label}:** {value}\n" if (value and str(value).strip()) else ""

def _header_common(
    *,
    resource_name: Optional[str],
    resource_id: Optional[str],
    exec_label: Optional[str],
    exec_id: Optional[str],
    severity_upper: Optional[str],
    model_name: Optional[str],
    started_at_iso: Optional[str],
) -> str:
    """
    Render in this exact order:
    Resource Name and ID
    <Exec Label>
    Severity
    Model
    Started At
    """
    rid = f"{resource_name or 'Unknown'} ({resource_id})" if resource_id else (resource_name or "Unknown")
    lines = ""
    lines += _kv_line("Resource Name and ID", rid)
    if exec_label and exec_id:
        lines += _kv_line(exec_label, f"`{exec_id}`")
    lines += _kv_line("Severity", (severity_upper or "").upper() or None)
    lines += _kv_line("Model", f"`{model_name}`" if model_name else None)
    lines += _kv_line("Started At", started_at_iso)
    return lines + "\n"  # blank line after header block

def _results_line(failed: Optional[int], passed: Optional[int], total: Optional[int]) -> str:
    if failed is None or passed is None or total is None:
        return ""
    return f"**Results:** {failed} failed / {passed} passed / {total} total\n\n"

def _render_examples(examples: List[dict]) -> str:
    """
    Accepts items with keys externalPrompt|prompt, output, failedReason|reason.
    Produces the 'Failed Examples (N of M)' collapsible block.
    """
    if not examples:
        return "**Failed Examples:** _No example details provided_\n"

    shown = min(len(examples), 5)
    suffix = f" of {len(examples)}" if len(examples) > 5 else ""
    lines: List[str] = []
    for i, d in enumerate(examples[:5], start=1):
        prompt = (d.get("externalPrompt") or d.get("prompt") or "").strip()
        reason = (d.get("failedReason") or d.get("reason") or "").strip()
        output = (d.get("output") or "").strip()
        prompt_short = textwrap.shorten(prompt.replace("\n", " "), width=300, placeholder="...")
        output_short = textwrap.shorten(output.replace("\n", " "), width=300, placeholder="...")
        reason_short = textwrap.shorten(reason.replace("\n", " "), width=500, placeholder="...")
        lines.append(
            f"**Example {i}**\n"
            f"- Failed Reason: {reason_short}\n"
            f"- Prompt (trimmed): `{prompt_short}`\n"
            f"- Output (trimmed): `{output_short}`\n"
        )
    extra = f"\n\n_...and {len(examples) - 5} more failed test case(s)_" if len(examples) > 5 else ""
    return (
        "<details>\n"
        f"<summary><strong>Failed Examples</strong> ({shown}{suffix})</summary>\n\n"
        + "\n".join(lines)
        + extra
        + "\n</details>\n"
    )

# ---------------------------
# v1 GraphQL enrichment helpers
# ---------------------------

def _norm(s: Optional[str]) -> str:
    return " ".join((s or "").strip().split()).lower()

def _pick_best_issue_match(
    findings: List[dict],
    *,
    exec_id: Optional[str],
    res_name: str,
    cat_name: str,
) -> Optional[dict]:
    if not findings:
        return None

    cat_norm = _norm(cat_name)
    res_norm = _norm(res_name)

    if exec_id:
        exact = [f for f in findings if _norm(f.get("llmPentestScanExecutionId")) == _norm(exec_id)]
        if exact:
            def _ts(row: dict) -> datetime:
                v = row.get("issueCreatedDate") or ""
                try:
                    return datetime.fromisoformat(v.replace("Z", "+00:00"))
                except Exception:
                    return datetime.min.replace(tzinfo=timezone.utc)
            return sorted(exact, key=_ts, reverse=True)[0]

    candidates = [
        f for f in findings
        if _norm(f.get("policyName")) == cat_norm and _norm(f.get("resourceDisplayName")) == res_norm
    ]
    if candidates:
        def _ts(row: dict) -> datetime:
            v = row.get("issueCreatedDate") or ""
            try:
                return datetime.fromisoformat(v.replace("Z", "+00:00"))
            except Exception:
                return datetime.min.replace(tzinfo=timezone.utc)
        return sorted(candidates, key=_ts, reverse=True)[0]

    return None

def _enrich_with_platform_issue_block(
    jwt: str,
    *,
    exec_id: Optional[str],
    res_name: str,
    cat_name: str,
) -> tuple[str, Optional[List[str]]]:
    try:
        # Build filters dict for the query
        filters: Dict[str, Any] = {
            "resourceDisplayNames": [res_name],
            "pentestFindings": [cat_name],
        }
        
        # Add organization/project if available
        if hasattr(config, "ORGANIZATION_ID") and config.ORGANIZATION_ID:
            filters["organizationId"] = config.ORGANIZATION_ID
        if hasattr(config, "PROJECT_IDS") and config.PROJECT_IDS:
            filters["projectId"] = config.PROJECT_IDS[0]
        
        findings = api.query_spm_pentest_issues(jwt_token=jwt, filters=filters)
    except Exception as e:
        print(f"[enrich:gql] Skipping enrichment for {cat_name}: {e}")
        return "", None

    match = _pick_best_issue_match(findings, exec_id=exec_id, res_name=res_name, cat_name=cat_name)
    if not match:
        return "", None

    proj_list = match.get("projectNames") or []
    proj_line = f"- Project(s): {', '.join(proj_list)}\n" if proj_list else ""
    block = (
        "\n\n**Platform Issue (AllTrue)**\n"
        f"- Issue ID: `{match.get('issueId') or '?'}`\n"
        f"- Status: {match.get('status') or 'UNKNOWN'}\n"
        f"- Severity: {match.get('severity') or 'UNKNOWN'}\n"
        f"- First Discovered At: {match.get('issueCreatedDate') or '?'}\n"
        f"- Policy (category): {match.get('policyName') or cat_name}\n"
        f"- Resource: {match.get('resourceDisplayName') or res_name}\n"
        f"{proj_line}"
    )
    return block, ["platform-issue-linked"]

def _enrich_modelscan_with_v1_details(
    jwt: str,
    *,
    model_scan_execution_id: Optional[str],
    res_name: str,
) -> tuple[str, Optional[str], Optional[List[str]]]:
    """
    Use /v1/graphql modelScanDetails to fetch:
      • startAt (for the header)
      • first Platform Issue row to render a 'Platform Issue (AllTrue)' block
    Returns (platform_issue_md, started_at, extra_labels)
    """
    if not model_scan_execution_id:
        return "", None, None

    try:
        det = api.query_model_scan_details(jwt, model_scan_execution_id)
    except Exception as e:
        print(f"[enrich:v1 modelScanDetails] Skipping enrichment for {model_scan_execution_id}: {e}")
        return "", None, None

    started_at = det.get("startAt")
    issues = det.get("issues") or []
    if not issues:
        return "", started_at, None

    # choose first issue; they are already UNRESOLVED/CRITICAL etc.
    i0 = issues[0]
    pol = i0.get("modelConfigurationPolicyName") or "Unknown"
    vulns = i0.get("modelVulnerabilities") or []
    descs = i0.get("modelVulnerabilitiesDescriptions") or []
    sev = i0.get("severity") or "UNKNOWN"
    st  = i0.get("status") or "UNKNOWN"
    issue_id = i0.get("issueId") or "?"

    # Flatten vuln pairs nicely
    pairs = []
    for a, b in zip(vulns, (descs or [""] * len(vulns))):
        pairs.append(f"{a}" + (f" - {b}" if b else ""))

    block = (
        "\n\n**Platform Issue (AllTrue)**\n"
        f"- Issue ID: `{issue_id}`\n"
        f"- Status: {st}\n"
        f"- Severity: {sev}\n"
        f"- Policy (category): {pol}\n"
        f"- Resource: {res_name}\n"
        + (f"- Vulnerabilities: {', '.join(pairs)}\n" if pairs else "")
    )
    # Always add unresolved + platform-issue-linked
    return block, started_at, ["platform-issue-linked", "unresolved"]


# ===== Threshold breaches =====

def create_issues_for_threshold_breaches(breaches: List[dict], threshold: str, *, prefix_tag: str = "[Pentest]") -> int:
    if not breaches:
        return 0
    if not github_ready():
        print("[!]  GitHub issue creation skipped: GITHUB_TOKEN or GITHUB_REPOSITORY not set.")
        return 0

    created = 0
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    source_label = _source_label_for_prefix(prefix_tag)

    for r in breaches:
        outcome_norm = (r.get("outcome") or "unknown").lower()
        title = _make_title("Outcome threshold breach", outcome_norm, r.get("resource_name") or "?", tag=prefix_tag)

        header = _header_common(
            resource_name=r.get("resource_name"),
            resource_id=r.get("resource_id"),
            exec_label="Execution ID",
            exec_id=r.get("scan_execution_id"),
            severity_upper=(r.get("outcome") or "Unknown").upper(),
            model_name=None,
            started_at_iso=None,
        )
        body = (
            f"<!-- threshold_breach resource:{r.get('resource_id')} -->\n"
            + header
            + f"**Policy:** Threshold\n"
            + f"**Results:** Breached Threshold **{threshold.capitalize()}**\n\n"
            + _format_result_line(r)
        )

        labels = _with_labels(config.GITHUB_DEFAULT_LABELS, [outcome_norm, source_label, "threshold-breach"])
        ok, msg = _post_issue(title, body, labels)
        print(("[OK] " if ok else "[X] ") + msg)
        if ok:
            created += 1
    return created


# ===== Pentest hard failures =====

def create_issues_for_hard_failures(failures: List[dict]) -> int:
    if not failures:
        return 0
    if not github_ready():
        print("[!]  GitHub issue creation skipped: GITHUB_TOKEN or GITHUB_REPOSITORY not set.")
        return 0

    created = 0
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    for r in failures:
        outcome_norm = (r.get("outcome") or "unknown").lower()
        title = _make_title("Start/Run failure", outcome_norm, r.get("resource_name") or "?")

        header = _header_common(
            resource_name=r.get("resource_name"),
            resource_id=r.get("resource_id"),
            exec_label="Pentest Scan Execution ID",
            exec_id=r.get("scan_execution_id"),
            severity_upper=(r.get("outcome") or "Unknown").upper(),
            model_name=None,
            started_at_iso=None,
        )
        body = header + _format_result_line(r) + f"\n\n**Error Log**\n\n```\n{(r.get('error') or 'n/a')}\n```"

        labels = _with_labels(config.GITHUB_DEFAULT_LABELS, [outcome_norm, "hard-failure", "pentest"])
        ok, msg = _post_issue(title, body, labels)
        print(("[OK] " if ok else "[X] ") + msg)
        if ok:
            created += 1
    return created


# ===== Per-category issues (Pentest) =====

def create_failed_category_issues_for_results(results: List[dict]) -> int:
    """
    One issue per failed category with the normalized body layout.
    Labels: severity + pentest + pentest-category-failure + unresolved + platform-issue-linked (+ user defaults)
    """
    if not getattr(config, "CATEGORY_ISSUES_ENABLED", True):
        print("[github] Per-category/per-policy issues disabled (CATEGORY_ISSUE_MIN_SEVERITY=NONE)")
        return 0
    if not github_ready():
        print("[!]  GitHub issue creation skipped: GITHUB_TOKEN or GITHUB_REPOSITORY not set.")
        return 0
    if not results:
        return 0

    jwt = auth.get_jwt_token(config.API_KEY)
    created_total = 0

    for r in results:
        exec_id = r.get("scan_execution_id")
        if not exec_id:
            continue

        try:
            data = api.query_pentest_execution_full(jwt, exec_id)
        except Exception as e:
            print(f"[X] GraphQL fetch failed for exec {exec_id}: {e}")
            continue

        exec_info = data.get("llmPentestScanExecution") or {}
        resource = data.get("resourceInstanceForLlmPentestScanExecution") or {}
        failed_per = data.get("failedCategoriesResultsPerCategory") or []
        if not failed_per:
            continue

        res_name = resource.get("displayName") or r.get("resource_name") or "Unknown resource"
        res_id = resource.get("resourceInstanceId") or r.get("resource_id") or "?"
        model = exec_info.get("chosenLlmModel") or None
        started = exec_info.get("startedAt") or None
        outcome = exec_info.get("outcomeLevel") or r.get("outcome") or "UNKNOWN"

        for cat in failed_per:
            severity = (cat.get("severity") or "UNKNOWN").upper()
            if not _category_severity_meets_min(severity):
                continue
            cat_name = cat.get("categoryDisplayName") or "Unnamed Category"
            total = cat.get("totalTestCases")
            failed = cat.get("failedTestCases")
            passed = cat.get("passedTestCases")

            title = f"[Pentest][{severity}] {cat_name} - {res_name}"

            # Evidence (examples)
            details = cat.get("failedTestCaseDetails") or []
            evidence_md = _render_examples(details)

            # Enrichment block
            enrich_block, _ = _enrich_with_platform_issue_block(
                jwt, exec_id=exec_id, res_name=res_name, cat_name=cat_name
            )

            marker = f"<!-- llm_pentest resource:{res_id} category:{cat_name} -->"

            # Deduplication check (same as model scan)
            try:
                if _search_issue_by_marker(marker):
                    print(f"[SKIP]  Skipping duplicate for {res_name} / {cat_name} (open issue exists).")
                    continue
            except Exception as e:
                print(f"[!]  Dedupe check failed ({e}); attempting to create issue anyway.")

            header = _header_common(
                resource_name=res_name,
                resource_id=res_id,
                exec_label="Pentest Scan Execution ID",
                exec_id=exec_id,
                severity_upper=severity,
                model_name=model,
                started_at_iso=started,
            )

            body = (
                f"{marker}\n"
                + header
                + f"**Policy:** {cat_name}\n"
                + _results_line(failed, passed, total)
                + evidence_md
                + (enrich_block if enrich_block else "")
            )

            labels = _with_labels(
                config.GITHUB_DEFAULT_LABELS,
                [severity.lower(), "pentest", "pentest-category-failure", "unresolved", "platform-issue-linked"],
            )
            ok, msg = _post_issue(title, body, labels)
            print(("[OK] " if ok else "[X] ") + msg)
            if ok:
                created_total += 1
    return created_total


# ===== Model-scan policy violations (Model Scan) =====

def create_issues_for_model_scan_violations(results: List[dict]) -> int:
    if not getattr(config, "CATEGORY_ISSUES_ENABLED", True):
        print("[github] Per-category/per-policy issues disabled (CATEGORY_ISSUE_MIN_SEVERITY=NONE)")
        return 0
    if not github_ready():
        print("[!]  GitHub issue creation skipped: GITHUB_TOKEN or GITHUB_REPOSITORY not set.")
        return 0

    created = 0
    jwt = auth.get_jwt_token(config.API_KEY)

    for r in results:
        violations = r.get("violations") or []
        if not violations:
            continue

        res_name = r.get("resource_name") or "Unknown resource"
        res_id = r.get("resource_id") or "?"
        exec_id = r.get("scan_execution_id")  # set in model_scan.run_model_scan_for_resource

        # v1 enrichment: startedAt + platform issue block
        platform_block, started_at, extra_labels = _enrich_modelscan_with_v1_details(
            jwt, model_scan_execution_id=exec_id, res_name=res_name
        )

        for v in violations:
            policy = v.get("policy") or "unknown-policy"
            status = (v.get("status") or "UNKNOWN").upper()
            severity_up = (v.get("severity") or "UNKNOWN").upper()
            severity_label = (severity_up or "UNKNOWN").lower()
            details = (v.get("details") or "")

            failed = v.get("failed")
            passed = v.get("passed")
            total  = v.get("total")

            # Skip if below configured minimum severity
            if severity_up and not _category_severity_meets_min(severity_up):
                continue

            title = f"[Model Scan][{policy}] {status} - {res_name}"
            marker = f"<!-- model_scan resource:{res_id} policy:{policy} -->"

            try:
                if _search_issue_by_marker(marker):
                    print(f"[SKIP]  Skipping duplicate for {res_name} / {policy} (marker found).")
                    continue
            except Exception as e:
                print(f"[!]  Dedupe check failed ({e}); attempting to create issue anyway.")

            # Common-format header
            header_lines = [
                marker,
                f"**Resource Name and ID:** {res_name} (`{res_id}`)",
                f"**Model Scan Execution ID:** `{exec_id or '?'}`",
                f"**Severity:** **{severity_up}**",
            ]
            if started_at:
                header_lines.append(f"**Started At:** {started_at}")

            body = "\n".join(header_lines) + "\n\n" + \
                   f"**Policy:** `{policy}`\n" + \
                   (f"**Results:** {failed} failed / {passed} passed / {total} total\n\n"
                    if (failed is not None and passed is not None and total is not None) else "\n")

            # Prefer a "Failed Examples" collapsible block if present
            detail_blocks = v.get("detail_blocks") or []
            examples_total = int(v.get("examples_total") or 0)
            examples_shown = int(v.get("examples_shown") or len(detail_blocks))

            if detail_blocks and examples_total > 0:
                suffix = f" of {examples_total}" if examples_total > examples_shown else ""
                body += (
                    "<details>\n"
                    f"<summary><strong>Failed Examples</strong> ({examples_shown}{suffix})</summary>\n\n"
                    + "\n\n".join(detail_blocks)
                    + (
                        f"\n\n_...and {examples_total - examples_shown} more failed test case(s)_" 
                        if examples_total > examples_shown else ""
                    )
                    + "\n</details>\n"
                )
            elif details:
                # Collapsible Details (mirrors pentest UX)
                body += (
                    "<details>\n"
                    "<summary><strong>Details</strong></summary>\n\n"
                    f"{details}\n"
                    "</details>\n"
                )
            else:
                body += "_No additional details provided_\n"

            if platform_block:
                body += platform_block

            labels = _with_labels(
                config.GITHUB_DEFAULT_LABELS,
                [
                    severity_label or "unknown",
                    "model-scan",
                    "model-scan-policy-failure",
                    "unresolved",            
                    "platform-issue-linked", 
                    status.lower(),
                ],
                extra_labels or [],
            )

            ok, msg = _post_issue(title, body, labels)
            print(("[OK] " if ok else "[X] ") + msg)
            if ok:
                created += 1
    return created


# ===== Model-scan hard failures =====

def create_issues_for_model_scan_failures(failures: List[dict]) -> int:
    if not getattr(config, "CATEGORY_ISSUES_ENABLED", True):
        print("[github] Per-category/per-policy issues disabled (CATEGORY_ISSUE_MIN_SEVERITY=NONE)")
        return 0
    if not failures:
        return 0
    if not github_ready():
        print("[!]  GitHub issue creation skipped: GITHUB_TOKEN or GITHUB_REPOSITORY not set.")
        return 0

    created = 0
    now = datetime.now(timezone.utc).isoformat(timespec="seconds")
    for r in failures:
        outcome_norm = (r.get("outcome") or "unknown").lower()
        title = _make_title("Start/Run failure", outcome_norm, r.get("resource_name") or "?", tag="[Model Scan]")

        header = _header_common(
            resource_name=r.get("resource_name"),
            resource_id=r.get("resource_id"),
            exec_label="Model Scan Execution ID",
            exec_id=r.get("scan_execution_id"),
            severity_upper=(r.get("outcome") or "UNKNOWN").upper(),
            model_name=None,
            started_at_iso=None,
        )
        body = header + _format_result_line(r) + f"\n\n**Error Log**\n\n```\n{(r.get('error') or 'n/a')}\n```"

        labels = _with_labels(config.GITHUB_DEFAULT_LABELS, [outcome_norm, "hard-failure", "model-scan"])
        ok, msg = _post_issue(title, body, labels)
        print(("[OK] " if ok else "[X] ") + msg)
        if ok:
            created += 1
    return created