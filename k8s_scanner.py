#!/usr/bin/env python3
"""
ContainerGuard - Kubernetes Security Scanner
Author: aneskubat
Description: Analyzes Kubernetes YAML manifests for security misconfigurations.
"""

import re
import json
import sys
import os
from datetime import datetime


# ─────────────────────────────────────────────
#  CHECKS DEFINITION
# ─────────────────────────────────────────────

K8S_CHECKS = [
    {
        "id": "K8S001",
        "severity": "CRITICAL",
        "title": "Container runs as root (missing runAsNonRoot)",
        "description": (
            "Running a container as root in Kubernetes is a critical misconfiguration. "
            "If compromised, the attacker gains root access to the container, "
            "significantly increasing the risk of a container escape to the host system."
        ),
        "fix": "Add to securityContext:\n  runAsNonRoot: true\n  runAsUser: 1000",
        "pattern": None,
        "check_fn": "check_no_run_as_non_root",
    },
    {
        "id": "K8S002",
        "severity": "CRITICAL",
        "title": "Privileged container (privileged: true)",
        "description": (
            "A privileged container has access to all Linux capabilities and "
            "can directly access host devices. This is equivalent to running "
            "a process with root privileges directly on the host."
        ),
        "fix": "Remove 'privileged: true' from securityContext.",
        "pattern": re.compile(r"privileged\s*:\s*true", re.IGNORECASE),
        "check_fn": "pattern",
    },
    {
        "id": "K8S003",
        "severity": "HIGH",
        "title": "Missing resource limits",
        "description": (
            "Without CPU and memory limits, a single Pod can consume all node resources "
            "and bring down other services — known as a resource exhaustion attack. "
            "The Kubernetes scheduler also cannot optimally place Pods without this information."
        ),
        "fix": "Add to container spec:\n  resources:\n    limits:\n      cpu: '500m'\n      memory: '512Mi'\n    requests:\n      cpu: '250m'\n      memory: '256Mi'",
        "pattern": None,
        "check_fn": "check_no_resources",
    },
    {
        "id": "K8S004",
        "severity": "HIGH",
        "title": "Latest tag used for container image",
        "description": (
            "The 'latest' tag is not deterministic — each deployment may run a different "
            "image version. This makes auditing difficult, prevents reliable rollbacks, "
            "and can silently introduce vulnerabilities."
        ),
        "fix": "Use a specific tag, e.g. nginx:1.25.3 instead of nginx:latest",
        "pattern": re.compile(r"image\s*:\s*\S+:latest", re.IGNORECASE),
        "check_fn": "pattern",
    },
    {
        "id": "K8S005",
        "severity": "HIGH",
        "title": "allowPrivilegeEscalation not disabled",
        "description": (
            "Without 'allowPrivilegeEscalation: false', a process inside the container "
            "can gain more privileges than its parent process through setuid/setgid "
            "mechanisms, making privilege escalation attacks easier."
        ),
        "fix": "Add to securityContext:\n  allowPrivilegeEscalation: false",
        "pattern": None,
        "check_fn": "check_no_privilege_escalation",
    },
    {
        "id": "K8S006",
        "severity": "MEDIUM",
        "title": "Missing liveness and readiness probes",
        "description": (
            "Without health probes, Kubernetes cannot automatically detect and restart "
            "unhealthy containers. The application may be in a broken state while "
            "Kubernetes continues routing traffic to it."
        ),
        "fix": "Add livenessProbe and readinessProbe to the container spec.",
        "pattern": None,
        "check_fn": "check_no_probes",
    },
    {
        "id": "K8S007",
        "severity": "MEDIUM",
        "title": "Root filesystem is not read-only",
        "description": (
            "Without readOnlyRootFilesystem: true, an attacker who compromises the container "
            "can write to the filesystem — installing tools, modifying configurations, "
            "or persisting malware across restarts."
        ),
        "fix": "Add to securityContext:\n  readOnlyRootFilesystem: true",
        "pattern": None,
        "check_fn": "check_no_readonly_fs",
    },
    {
        "id": "K8S008",
        "severity": "MEDIUM",
        "title": "hostNetwork or hostPID enabled",
        "description": (
            "hostNetwork: true or hostPID: true removes network/process isolation "
            "between the container and the host. An attacker can see all network "
            "interfaces and processes running on the host system."
        ),
        "fix": "Remove 'hostNetwork: true' and 'hostPID: true' from the Pod spec.",
        "pattern": re.compile(r"(hostNetwork|hostPID)\s*:\s*true", re.IGNORECASE),
        "check_fn": "pattern",
    },
    {
        "id": "K8S009",
        "severity": "LOW",
        "title": "Missing labels on resources",
        "description": (
            "Labels are essential for managing Kubernetes resources — selection, "
            "monitoring, and network policies all rely on them. Without labels, "
            "it becomes harder to track and manage resources in the cluster."
        ),
        "fix": "Add metadata.labels, e.g:\n  labels:\n    app: myapp\n    version: '1.0'",
        "pattern": None,
        "check_fn": "check_no_labels",
    },
    {
        "id": "K8S010",
        "severity": "CRITICAL",
        "title": "Secrets in plaintext environment variables",
        "description": (
            "Defining secrets directly as env var values means they are visible to anyone "
            "with kubectl describe access. Kubernetes Secret objects provide better "
            "access control and can be encrypted at rest."
        ),
        "fix": "Use secretKeyRef instead of plain values:\n  env:\n    - name: DB_PASSWORD\n      valueFrom:\n        secretKeyRef:\n          name: myapp-secrets\n          key: db-password",
        "pattern": re.compile(
            r"^\s*value\s*:\s*['\"]?.{4,}['\"]?\s*$",
            re.IGNORECASE | re.MULTILINE,
        ),
        "check_fn": "pattern",
    },
]


# ─────────────────────────────────────────────
#  CHECK LOGIC
# ─────────────────────────────────────────────

def run_k8s_checks(content):
    findings = []

    for check in K8S_CHECKS:
        fn = check["check_fn"]

        if fn == "pattern":
            if check["pattern"] and check["pattern"].search(content):
                findings.append({**check, "line": None, "pattern": None})

        elif fn == "check_no_run_as_non_root":
            if not re.search(r"runAsNonRoot\s*:\s*true", content, re.IGNORECASE):
                findings.append({**check, "line": None, "pattern": None})

        elif fn == "check_no_resources":
            if not re.search(r"resources\s*:", content, re.IGNORECASE):
                findings.append({**check, "line": None, "pattern": None})

        elif fn == "check_no_privilege_escalation":
            if not re.search(r"allowPrivilegeEscalation\s*:\s*false", content, re.IGNORECASE):
                findings.append({**check, "line": None, "pattern": None})

        elif fn == "check_no_probes":
            has_liveness  = bool(re.search(r"livenessProbe\s*:", content, re.IGNORECASE))
            has_readiness = bool(re.search(r"readinessProbe\s*:", content, re.IGNORECASE))
            if not has_liveness or not has_readiness:
                findings.append({**check, "line": None, "pattern": None})

        elif fn == "check_no_readonly_fs":
            if not re.search(r"readOnlyRootFilesystem\s*:\s*true", content, re.IGNORECASE):
                findings.append({**check, "line": None, "pattern": None})

        elif fn == "check_no_labels":
            if not re.search(r"labels\s*:", content, re.IGNORECASE):
                findings.append({**check, "line": None, "pattern": None})

    return findings


# ─────────────────────────────────────────────
#  SECURITY SCORE
# ─────────────────────────────────────────────

SEVERITY_WEIGHT = {"CRITICAL": 40, "HIGH": 20, "MEDIUM": 10, "LOW": 5}
SEVERITY_COLOR  = {"CRITICAL": "#C0392B", "HIGH": "#E67E22", "MEDIUM": "#2980B9", "LOW": "#27AE60"}

def calculate_score(findings):
    penalty = sum(SEVERITY_WEIGHT.get(f["severity"], 0) for f in findings)
    return max(0, 100 - penalty)


# ─────────────────────────────────────────────
#  HTML REPORT
# ─────────────────────────────────────────────

def generate_html_report(findings, score, filename):
    counts = {s: sum(1 for f in findings if f["severity"] == s)
              for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]}

    if score >= 80:
        score_color, score_label = "#27AE60", "Good"
    elif score >= 50:
        score_color, score_label = "#E67E22", "Moderate"
    else:
        score_color, score_label = "#C0392B", "Critical"

    def finding_cards(findings):
        if not findings:
            return '<div class="no-issues">No issues found.</div>'
        html = ""
        for f in findings:
            color = SEVERITY_COLOR[f["severity"]]
            html += f"""
        <div class="finding">
          <div class="finding-header">
            <span class="sev-badge" style="background:{color}">{f['severity']}</span>
            <span class="finding-id">{f['id']}</span>
            <span class="finding-title">{f['title']}</span>
          </div>
          <div class="finding-desc">{f['description']}</div>
          <div class="finding-fix"><strong>Fix:</strong> {f['fix']}</div>
        </div>"""
        return html

    timestamp = datetime.now().strftime("%Y-%m-%d at %H:%M")

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>ContainerGuard K8s Report</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: 'Segoe UI', system-ui, sans-serif; background: #0F1117; color: #E0E6F0; }}
  .header {{ background: linear-gradient(135deg, #1A1D2E 0%, #0F1117 100%); border-bottom: 1px solid #2A2D3E; padding: 2rem; }}
  .header h1 {{ font-size: 1.6rem; font-weight: 700; color: #fff; }}
  .header h1 span {{ color: #4A9EFF; }}
  .header-meta {{ font-size: 0.8rem; color: #666; margin-top: 6px; }}
  .container {{ max-width: 900px; margin: 0 auto; padding: 2rem; }}
  .score-card {{ background: #1A1D2E; border: 1px solid #2A2D3E; border-radius: 12px; padding: 2rem; display: flex; align-items: center; gap: 2rem; margin-bottom: 1.5rem; }}
  .score-circle {{ width: 90px; height: 90px; border-radius: 50%; border: 4px solid {score_color}; display: flex; flex-direction: column; align-items: center; justify-content: center; flex-shrink: 0; }}
  .score-num {{ font-size: 1.8rem; font-weight: 700; color: {score_color}; line-height: 1; }}
  .score-max {{ font-size: 0.7rem; color: #666; }}
  .score-label {{ font-size: 1.1rem; font-weight: 600; color: {score_color}; margin-bottom: 4px; }}
  .score-desc {{ font-size: 0.85rem; color: #888; line-height: 1.5; }}
  .summary-grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 10px; margin-bottom: 1.5rem; }}
  .sev-card {{ background: #1A1D2E; border: 1px solid #2A2D3E; border-radius: 10px; padding: 1rem; text-align: center; }}
  .sev-card .count {{ font-size: 1.8rem; font-weight: 700; }}
  .sev-card .label {{ font-size: 0.75rem; color: #888; margin-top: 4px; }}
  .section-title {{ font-size: 1rem; font-weight: 600; color: #fff; margin: 1.5rem 0 0.75rem; padding-bottom: 8px; border-bottom: 1px solid #2A2D3E; }}
  .finding {{ background: #1A1D2E; border: 1px solid #2A2D3E; border-radius: 10px; padding: 1.2rem; margin-bottom: 10px; }}
  .finding-header {{ display: flex; align-items: center; gap: 10px; margin-bottom: 8px; flex-wrap: wrap; }}
  .sev-badge {{ font-size: 0.7rem; font-weight: 700; padding: 3px 8px; border-radius: 4px; color: #fff; }}
  .finding-id {{ font-size: 0.75rem; color: #666; font-family: monospace; }}
  .finding-title {{ font-size: 0.95rem; font-weight: 600; color: #E0E6F0; }}
  .finding-desc {{ font-size: 0.85rem; color: #AAB; line-height: 1.6; margin-bottom: 10px; }}
  .finding-fix {{ font-size: 0.83rem; background: #0D1F0D; border: 1px solid #1E4D1E; border-radius: 6px; padding: 10px 12px; color: #7EC87E; line-height: 1.6; font-family: monospace; white-space: pre-wrap; }}
  .no-issues {{ background: #0D1F0D; border: 1px solid #1E4D1E; border-radius: 10px; padding: 1rem 1.2rem; color: #7EC87E; }}
  .footer {{ text-align: center; color: #444; font-size: 0.8rem; padding: 2rem; border-top: 1px solid #1A1D2E; margin-top: 2rem; }}
</style>
</head>
<body>
<div class="header">
  <div class="container" style="padding-top:0;padding-bottom:0">
    <h1>Container<span>Guard</span> — Kubernetes Report</h1>
    <div class="header-meta">Scanned file: {filename} · Generated: {timestamp}</div>
  </div>
</div>
<div class="container">
  <div class="score-card">
    <div class="score-circle">
      <div class="score-num">{score}</div>
      <div class="score-max">/100</div>
    </div>
    <div>
      <div class="score-label">{score_label}</div>
      <div class="score-desc">
        Found {len(findings)} {'issues' if len(findings) != 1 else 'issue'} in total.
        {'Critical issues require immediate attention.' if counts['CRITICAL'] > 0 else 'No critical issues found.'}
      </div>
    </div>
  </div>
  <div class="summary-grid">
    <div class="sev-card"><div class="count" style="color:#C0392B">{counts['CRITICAL']}</div><div class="label">CRITICAL</div></div>
    <div class="sev-card"><div class="count" style="color:#E67E22">{counts['HIGH']}</div><div class="label">HIGH</div></div>
    <div class="sev-card"><div class="count" style="color:#2980B9">{counts['MEDIUM']}</div><div class="label">MEDIUM</div></div>
    <div class="sev-card"><div class="count" style="color:#27AE60">{counts['LOW']}</div><div class="label">LOW</div></div>
  </div>
  <div class="section-title">Kubernetes manifest — findings</div>
  {finding_cards(findings)}
</div>
<div class="footer">ContainerGuard · Kubernetes Security Scanner</div>
</body>
</html>"""


# ─────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────

def scan_file(path):
    if not os.path.exists(path):
        return None, f"File not found: {path}"
    with open(path, "r", encoding="utf-8") as f:
        return f.read(), None


def main():
    print("\n╔══════════════════════════════════════╗")
    print("║    ContainerGuard K8s Scanner v1.0   ║")
    print("║    Kubernetes Security Analysis      ║")
    print("╚══════════════════════════════════════╝\n")

    yaml_files = [
        f for f in os.listdir(".")
        if f.endswith((".yaml", ".yml"))
        and "docker-compose" not in f
        and "workflows" not in f
    ]

    if not yaml_files:
        print("  ⚠  No Kubernetes YAML files found.")
        sys.exit(0)

    all_findings = []

    for yaml_file in yaml_files:
        content, err = scan_file(yaml_file)
        if err:
            print(f"  ⚠  {err}")
            continue

        print(f"  ✓  Loaded: {yaml_file}")
        findings = run_k8s_checks(content)
        all_findings.extend(findings)

        score = calculate_score(findings)
        print(f"  Security Score: {score}/100 — {len(findings)} issues\n")

        for f in findings:
            icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🔵", "LOW": "🟢"}.get(f["severity"], "•")
            print(f"  {icon} [{f['severity']}] {f['id']} — {f['title']}")

        report_name = yaml_file.replace(".yaml", "").replace(".yml", "") + "_report.html"
        html = generate_html_report(findings, score, yaml_file)
        with open(report_name, "w", encoding="utf-8") as rf:
            rf.write(html)
        print(f"\n  ✅  Report saved: {report_name}\n")

    with open("k8s_report.json", "w", encoding="utf-8") as f:
        json.dump({
            "timestamp": datetime.now().isoformat(),
            "total_findings": len(all_findings),
            "findings": [{k: v for k, v in f.items() if k not in ("pattern", "check_fn")} for f in all_findings],
        }, f, indent=2, ensure_ascii=False)

    print("  ✅  JSON summary saved: k8s_report.json\n")

    critical_count = sum(1 for f in all_findings if f["severity"] == "CRITICAL")
    sys.exit(1 if critical_count > 0 else 0)


if __name__ == "__main__":
    main()