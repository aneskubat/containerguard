#!/usr/bin/env python3
"""
ContainerGuard - Docker & Kubernetes Security Scanner
Author: aneskubat
Description: Analyzes Dockerfile and docker-compose.yml files for security misconfigurations.
"""

import re
import json
import sys
import os
from datetime import datetime


# ─────────────────────────────────────────────
#  CHECKS DEFINITION
# ─────────────────────────────────────────────

DOCKERFILE_CHECKS = [
    {
        "id": "DF001",
        "severity": "CRITICAL",
        "title": "Container runs as root user",
        "description": (
            "Running a container as root is a serious security misconfiguration. "
            "If an attacker compromises the application, they automatically gain "
            "root access to the container, making container escape attacks much easier."
        ),
        "fix": "Add 'USER appuser' at the end of your Dockerfile (create the user first with RUN adduser).",
        "pattern": None,
        "check_fn": "check_no_user",
    },
    {
        "id": "DF002",
        "severity": "HIGH",
        "title": "Latest tag used for base image",
        "description": (
            "The 'latest' tag is not a fixed version — it changes over time. "
            "An image that is secure today may contain vulnerabilities tomorrow. "
            "It also makes builds impossible to reproduce consistently."
        ),
        "fix": "Use a specific tag, e.g. FROM python:3.11.9-slim instead of FROM python:latest",
        "pattern": re.compile(r"^FROM\s+\S+:latest", re.IGNORECASE | re.MULTILINE),
        "check_fn": "pattern",
    },
    {
        "id": "DF003",
        "severity": "CRITICAL",
        "title": "Hardcoded password or API key in ENV",
        "description": (
            "Secrets hardcoded in a Dockerfile become part of the Docker image layer. "
            "Anyone who pulls the image can read them using 'docker history' "
            "or by inspecting the image layers directly."
        ),
        "fix": "Use Docker Secrets or pass environment variables at runtime. Never hardcode secrets in a Dockerfile.",
        "pattern": re.compile(
            r"^ENV\s+\S*(PASSWORD|SECRET|KEY|TOKEN|API_KEY|PASSWD|PWD)\s*=?\s*\S+",
            re.IGNORECASE | re.MULTILINE,
        ),
        "check_fn": "pattern",
    },
    {
        "id": "DF004",
        "severity": "MEDIUM",
        "title": "ADD used instead of COPY",
        "description": (
            "The ADD instruction has hidden behaviour: it automatically extracts archives "
            "and can fetch files from URLs. This can lead to unexpected results "
            "and potential security issues. COPY is more explicit and safer."
        ),
        "fix": "Replace ADD with COPY for copying local files. Only use ADD if you specifically need archive extraction.",
        "pattern": re.compile(r"^ADD\s+", re.IGNORECASE | re.MULTILINE),
        "check_fn": "pattern",
    },
    {
        "id": "DF005",
        "severity": "MEDIUM",
        "title": "Missing HEALTHCHECK instruction",
        "description": (
            "Without a HEALTHCHECK instruction, Docker cannot determine whether "
            "the application inside the container is actually healthy. "
            "A container may show as 'running' while the application has crashed."
        ),
        "fix": "Add a HEALTHCHECK instruction, e.g: HEALTHCHECK --interval=30s CMD curl -f http://localhost:8080/health || exit 1",
        "pattern": None,
        "check_fn": "check_no_healthcheck",
    },
    {
        "id": "DF006",
        "severity": "LOW",
        "title": "apt-get without --no-install-recommends",
        "description": (
            "Installing packages without --no-install-recommends pulls in unnecessary "
            "packages that increase the attack surface. "
            "More packages means more potential vulnerabilities."
        ),
        "fix": "Use: RUN apt-get install -y --no-install-recommends <packages>",
        "pattern": re.compile(
            r"apt-get install(?!.*--no-install-recommends)", re.IGNORECASE
        ),
        "check_fn": "pattern",
    },
    {
        "id": "DF007",
        "severity": "HIGH",
        "title": "Privileged port exposed (below 1024)",
        "description": (
            "Ports below 1024 are privileged and require root permissions to bind. "
            "If the Dockerfile exposes such ports and the application runs as root, "
            "this creates a compounded security problem."
        ),
        "fix": "Use ports above 1024 (e.g. 8080 instead of 80). A reverse proxy (nginx/traefik) can map port 80 to 8080.",
        "pattern": re.compile(
            r"^EXPOSE\s+(9[0-9]{1}|[1-9][0-9]{0}|[1-9][0-9]{2}|10[0-1][0-9]|102[0-3])\b",
            re.MULTILINE,
        ),
        "check_fn": "pattern",
    },
]

COMPOSE_CHECKS = [
    {
        "id": "DC001",
        "severity": "CRITICAL",
        "title": "Privileged mode enabled",
        "description": (
            "privileged: true gives the container nearly the same access to the host "
            "as a root user. An attacker who compromises such a container can easily "
            "perform a container escape attack and take control of the host machine."
        ),
        "fix": "Remove 'privileged: true'. If specific capabilities are needed, use 'cap_add' for only those Linux capabilities required.",
        "pattern": re.compile(r"privileged\s*:\s*true", re.IGNORECASE),
        "check_fn": "pattern",
    },
    {
        "id": "DC002",
        "severity": "CRITICAL",
        "title": "Docker socket mounted into container",
        "description": (
            "Mounting /var/run/docker.sock gives the container full control over the Docker daemon. "
            "An attacker inside the container can create new privileged containers, "
            "mount the host filesystem, and effectively take over the entire host."
        ),
        "fix": "Never mount the Docker socket into production containers. If Docker-in-Docker is needed, use alternatives like Kaniko.",
        "pattern": re.compile(r"/var/run/docker\.sock", re.IGNORECASE),
        "check_fn": "pattern",
    },
    {
        "id": "DC003",
        "severity": "HIGH",
        "title": "Hardcoded password in environment variables",
        "description": (
            "Passwords directly in docker-compose.yml are visible to anyone with access "
            "to the repository or filesystem. This is a common cause of credential leakage."
        ),
        "fix": "Use a .env file (added to .gitignore) or an external secrets manager (Vault, AWS Secrets Manager).",
        "pattern": re.compile(
            r"^\s*(PASSWORD|SECRET|KEY|TOKEN|API_KEY|PASSWD)\s*[=:]\s*\S+",
            re.IGNORECASE | re.MULTILINE,
        ),
        "check_fn": "pattern",
    },
    {
        "id": "DC004",
        "severity": "MEDIUM",
        "title": "Missing resource limits (CPU/memory)",
        "description": (
            "Without resource limits, a single container can consume all host resources "
            "and bring down other services — known as a resource exhaustion or noisy neighbor problem."
        ),
        "fix": "Add limits under deploy.resources:\n  limits:\n    cpus: '0.5'\n    memory: 512M",
        "pattern": None,
        "check_fn": "check_no_limits",
    },
    {
        "id": "DC005",
        "severity": "LOW",
        "title": "Restart policy not defined",
        "description": (
            "Without a restart policy, containers will not automatically restart after a crash "
            "or system reboot. This is not a direct security issue but affects service availability."
        ),
        "fix": "Add 'restart: unless-stopped' or 'restart: always' for production services.",
        "pattern": None,
        "check_fn": "check_no_restart",
    },
]


# ─────────────────────────────────────────────
#  CHECK LOGIC
# ─────────────────────────────────────────────

def run_dockerfile_checks(content):
    findings = []
    lines = content.splitlines()

    for check in DOCKERFILE_CHECKS:
        fn = check["check_fn"]

        if fn == "pattern":
            if check["pattern"] and check["pattern"].search(content):
                lineno = None
                for i, line in enumerate(lines, 1):
                    if check["pattern"].search(line):
                        lineno = i
                        break
                findings.append({**check, "line": lineno, "pattern": None})

        elif fn == "check_no_user":
            if not re.search(r"^USER\s+\S+", content, re.IGNORECASE | re.MULTILINE):
                findings.append({**check, "line": None, "pattern": None})

        elif fn == "check_no_healthcheck":
            if not re.search(r"^HEALTHCHECK\s+", content, re.IGNORECASE | re.MULTILINE):
                findings.append({**check, "line": None, "pattern": None})

    return findings


def run_compose_checks(content):
    findings = []

    for check in COMPOSE_CHECKS:
        fn = check["check_fn"]

        if fn == "pattern":
            if check["pattern"] and check["pattern"].search(content):
                findings.append({**check, "line": None, "pattern": None})

        elif fn == "check_no_limits":
            if not re.search(r"limits\s*:", content, re.IGNORECASE):
                findings.append({**check, "line": None, "pattern": None})

        elif fn == "check_no_restart":
            if not re.search(r"restart\s*:", content, re.IGNORECASE):
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
#  HTML REPORT GENERATOR
# ─────────────────────────────────────────────

def generate_html_report(dockerfile_findings, compose_findings, score, target_files):
    all_findings = dockerfile_findings + compose_findings
    counts = {s: sum(1 for f in all_findings if f["severity"] == s)
              for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]}

    if score >= 80:
        score_color, score_label = "#27AE60", "Good"
    elif score >= 50:
        score_color, score_label = "#E67E22", "Moderate"
    else:
        score_color, score_label = "#C0392B", "Critical"

    def finding_cards(findings, source):
        if not findings:
            return f'<div class="no-issues">No issues found in {source}</div>'
        html = ""
        for f in findings:
            sev = f["severity"]
            color = SEVERITY_COLOR[sev]
            line_info = f" · Line {f['line']}" if f.get("line") else ""
            html += f"""
        <div class="finding">
          <div class="finding-header">
            <span class="sev-badge" style="background:{color}">{sev}</span>
            <span class="finding-id">{f['id']}</span>
            <span class="finding-title">{f['title']}</span>
          </div>
          <div class="finding-meta">{source}{line_info}</div>
          <div class="finding-desc">{f['description']}</div>
          <div class="finding-fix"><strong>Fix:</strong> {f['fix']}</div>
        </div>"""
        return html

    files_scanned = ", ".join(target_files) if target_files else "—"
    timestamp = datetime.now().strftime("%Y-%m-%d at %H:%M")

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ContainerGuard Report</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: 'Segoe UI', system-ui, sans-serif; background: #0F1117; color: #E0E6F0; min-height: 100vh; }}
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
  .finding:hover {{ border-color: #3A3D5E; }}
  .finding-header {{ display: flex; align-items: center; gap: 10px; margin-bottom: 8px; flex-wrap: wrap; }}
  .sev-badge {{ font-size: 0.7rem; font-weight: 700; padding: 3px 8px; border-radius: 4px; color: #fff; }}
  .finding-id {{ font-size: 0.75rem; color: #666; font-family: monospace; }}
  .finding-title {{ font-size: 0.95rem; font-weight: 600; color: #E0E6F0; }}
  .finding-meta {{ font-size: 0.75rem; color: #666; margin-bottom: 8px; font-family: monospace; }}
  .finding-desc {{ font-size: 0.85rem; color: #AAB; line-height: 1.6; margin-bottom: 10px; }}
  .finding-fix {{ font-size: 0.83rem; background: #0D1F0D; border: 1px solid #1E4D1E; border-radius: 6px; padding: 10px 12px; color: #7EC87E; line-height: 1.6; font-family: monospace; white-space: pre-wrap; }}
  .no-issues {{ background: #0D1F0D; border: 1px solid #1E4D1E; border-radius: 10px; padding: 1rem 1.2rem; color: #7EC87E; font-size: 0.9rem; }}
  .footer {{ text-align: center; color: #444; font-size: 0.8rem; padding: 2rem; border-top: 1px solid #1A1D2E; margin-top: 2rem; }}
</style>
</head>
<body>
<div class="header">
  <div class="container" style="padding-top:0;padding-bottom:0">
    <h1>Container<span>Guard</span> Security Report</h1>
    <div class="header-meta">Scanned files: {files_scanned} · Generated: {timestamp}</div>
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
        Found {len(all_findings)} {'issues' if len(all_findings) != 1 else 'issue'} in total.
        {'Critical issues require immediate attention.' if counts['CRITICAL'] > 0 else 'No critical issues found — focus on HIGH and MEDIUM.'}
      </div>
    </div>
  </div>
  <div class="summary-grid">
    <div class="sev-card"><div class="count" style="color:#C0392B">{counts['CRITICAL']}</div><div class="label">CRITICAL</div></div>
    <div class="sev-card"><div class="count" style="color:#E67E22">{counts['HIGH']}</div><div class="label">HIGH</div></div>
    <div class="sev-card"><div class="count" style="color:#2980B9">{counts['MEDIUM']}</div><div class="label">MEDIUM</div></div>
    <div class="sev-card"><div class="count" style="color:#27AE60">{counts['LOW']}</div><div class="label">LOW</div></div>
  </div>
  <div class="section-title">Dockerfile — findings</div>
  {finding_cards(dockerfile_findings, 'Dockerfile')}
  <div class="section-title">docker-compose.yml — findings</div>
  {finding_cards(compose_findings, 'docker-compose.yml')}
</div>
<div class="footer">ContainerGuard · Docker & Kubernetes Security Scanner</div>
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
    print("║      ContainerGuard v1.0             ║")
    print("║  Docker & K8s Security Scanner       ║")
    print("╚══════════════════════════════════════╝\n")

    dockerfile_path = "Dockerfile"
    compose_path    = "docker-compose.yml"
    scanned_files   = []

    dockerfile_content, err = scan_file(dockerfile_path)
    if err:
        print(f"  ⚠  {err}")
        dockerfile_findings = []
    else:
        print(f"  ✓  Loaded: {dockerfile_path}")
        scanned_files.append(dockerfile_path)
        dockerfile_findings = run_dockerfile_checks(dockerfile_content)

    compose_content, err = scan_file(compose_path)
    if err:
        print(f"  ⚠  {err}")
        compose_findings = []
    else:
        print(f"  ✓  Loaded: {compose_path}")
        scanned_files.append(compose_path)
        compose_findings = run_compose_checks(compose_content)

    all_findings = dockerfile_findings + compose_findings
    score = calculate_score(all_findings)

    print(f"\n  Issues found:   {len(all_findings)}")
    print(f"  Security Score: {score}/100\n")

    for f in all_findings:
        icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🔵", "LOW": "🟢"}.get(f["severity"], "•")
        line = f" (line {f['line']})" if f.get("line") else ""
        print(f"  {icon} [{f['severity']}] {f['id']} — {f['title']}{line}")

    report_path = "containerguard_report.html"
    html = generate_html_report(dockerfile_findings, compose_findings, score, scanned_files)
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"\n  ✅  HTML report saved: {report_path}")

    with open("containerguard_report.json", "w", encoding="utf-8") as f:
        json.dump({
            "score": score,
            "timestamp": datetime.now().isoformat(),
            "findings": [{k: v for k, v in f.items() if k not in ("pattern", "check_fn")} for f in all_findings],
        }, f, indent=2, ensure_ascii=False)
    print("  ✅  JSON report saved: containerguard_report.json\n")

    critical_count = sum(1 for f in all_findings if f["severity"] == "CRITICAL")
    sys.exit(1 if critical_count > 0 else 0)


if __name__ == "__main__":
    main()