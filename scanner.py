#!/usr/bin/env python3
"""
ContainerGuard - Docker & Kubernetes Security Scanner
Autor: aneskubat
Opis: Analizira Dockerfile i docker-compose.yml fajlove i pronalazi sigurnosne propuste.
"""

import re
import json
import sys
import os
from datetime import datetime


# ─────────────────────────────────────────────
#  DEFINICIJA PROVJERA
# ─────────────────────────────────────────────

DOCKERFILE_CHECKS = [
    {
        "id": "DF001",
        "severity": "CRITICAL",
        "title": "Kontejner se pokreće kao root korisnik",
        "description": (
            "Pokretanje kontejnera kao root je ozbiljan sigurnosni propust. "
            "Ako napadač kompromituje aplikaciju, automatski ima root pristup kontejneru, "
            "što olakšava container escape napade."
        ),
        "fix": "Dodaj 'USER appuser' na kraj Dockerfile-a (prethodno kreiraj korisnika s RUN adduser).",
        "pattern": None,
        "check_fn": "check_no_user",
    },
    {
        "id": "DF002",
        "severity": "HIGH",
        "title": "Koristi se 'latest' tag za base image",
        "description": (
            "Tag 'latest' nije fiksna verzija — mijenja se. "
            "Danas je sigurna slika, sutra može sadržavati ranjivosti. "
            "Nemoguće je reproducirati isti build."
        ),
        "fix": "Koristi specifičan tag, npr. FROM python:3.11.9-slim umjesto FROM python:latest",
        "pattern": re.compile(r"^FROM\s+\S+:latest", re.IGNORECASE | re.MULTILINE),
        "check_fn": "pattern",
    },
    {
        "id": "DF003",
        "severity": "CRITICAL",
        "title": "Hardcoded lozinka ili API ključ u ENV",
        "description": (
            "Tajni podaci hardcoded u Dockerfile postaju dio Docker image sloja. "
            "Svako ko skine image može ih pročitati komandom 'docker history'."
        ),
        "fix": "Koristi Docker Secrets ili environment varijable koje se proslijeđuju pri pokretanju.",
        "pattern": re.compile(
            r"^ENV\s+\S*(PASSWORD|SECRET|KEY|TOKEN|API_KEY|PASSWD|PWD)\s*=?\s*\S+",
            re.IGNORECASE | re.MULTILINE,
        ),
        "check_fn": "pattern",
    },
    {
        "id": "DF004",
        "severity": "MEDIUM",
        "title": "Koristi se ADD umjesto COPY",
        "description": (
            "ADD instrukcija ima skrivene mogućnosti: automatski raspakuje arhive i "
            "može preuzimati fajlove s URL-ova. COPY je eksplicitniji i sigurniji."
        ),
        "fix": "Zamijeni ADD s COPY za kopiranje lokalnih fajlova.",
        "pattern": re.compile(r"^ADD\s+", re.IGNORECASE | re.MULTILINE),
        "check_fn": "pattern",
    },
    {
        "id": "DF005",
        "severity": "MEDIUM",
        "title": "Nedostaje HEALTHCHECK instrukcija",
        "description": (
            "Bez HEALTHCHECK instrukcije, Docker ne zna je li aplikacija funkcionalna. "
            "Kontejner može biti 'running' ali aplikacija može biti crashala."
        ),
        "fix": "Dodaj HEALTHCHECK instrukciju, npr: HEALTHCHECK --interval=30s CMD curl -f http://localhost:8080/health || exit 1",
        "pattern": None,
        "check_fn": "check_no_healthcheck",
    },
    {
        "id": "DF006",
        "severity": "LOW",
        "title": "apt-get bez --no-install-recommends",
        "description": (
            "Instaliranje paketa bez --no-install-recommends dovodi do instalacije "
            "nepotrebnih paketa koji povećavaju površinu napada."
        ),
        "fix": "Koristi: RUN apt-get install -y --no-install-recommends <paketi>",
        "pattern": re.compile(r"apt-get install(?!.*--no-install-recommends)", re.IGNORECASE),
        "check_fn": "pattern",
    },
    {
        "id": "DF007",
        "severity": "HIGH",
        "title": "Privilegovani port izložen (ispod 1024)",
        "description": (
            "Portovi ispod 1024 zahtijevaju root prava za binding. "
            "Ako aplikacija radi kao root, to je dvostruki sigurnosni problem."
        ),
        "fix": "Koristi portove iznad 1024 (npr. 8080 umjesto 80).",
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
        "title": "Privileged mod je uključen",
        "description": (
            "privileged: true daje kontejneru gotovo isti pristup hostu kao root korisnik. "
            "Napadač može lako izvesti container escape napad."
        ),
        "fix": "Ukloni 'privileged: true'. Koristi 'cap_add' samo za specifične capabilities.",
        "pattern": re.compile(r"privileged\s*:\s*true", re.IGNORECASE),
        "check_fn": "pattern",
    },
    {
        "id": "DC002",
        "severity": "CRITICAL",
        "title": "Docker socket je montiran u kontejner",
        "description": (
            "Montiranje /var/run/docker.sock daje kontejneru punu kontrolu nad Docker daemonom. "
            "Napadač može kreirati privilegovane kontejnere i preuzeti cijeli host."
        ),
        "fix": "Nikad ne montiraj Docker socket u produkcijske kontejnere.",
        "pattern": re.compile(r"/var/run/docker\.sock", re.IGNORECASE),
        "check_fn": "pattern",
    },
    {
        "id": "DC003",
        "severity": "HIGH",
        "title": "Hardcoded lozinka u environment varijablama",
        "description": (
            "Lozinke direktno u docker-compose.yml vidljive su svakome s pristupom repozitoriju."
        ),
        "fix": "Koristi .env fajl (koji je u .gitignore) ili external secrets management.",
        "pattern": re.compile(
            r"(PASSWORD|SECRET|KEY|TOKEN|API_KEY|PASSWD)\s*:\s*\S+",
            re.IGNORECASE,
        ),
        "check_fn": "pattern",
    },
    {
        "id": "DC004",
        "severity": "MEDIUM",
        "title": "Nedostaju resource limits (CPU/memorija)",
        "description": (
            "Bez resource limits, jedan kontejner može potrošiti sve resurse hosta "
            "i srušiti ostale servise."
        ),
        "fix": "Dodaj limits:\n  deploy:\n    resources:\n      limits:\n        cpus: '0.5'\n        memory: 512M",
        "pattern": None,
        "check_fn": "check_no_limits",
    },
    {
        "id": "DC005",
        "severity": "LOW",
        "title": "Container restart policy nije definisan",
        "description": "Bez restart policy, kontejner se ne pokreće automatski nakon pada sistema.",
        "fix": "Dodaj 'restart: unless-stopped' za produkcijske servise.",
        "pattern": None,
        "check_fn": "check_no_restart",
    },
]


# ─────────────────────────────────────────────
#  LOGIKA PROVJERA
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
        score_color, score_label = "#27AE60", "Dobro"
    elif score >= 50:
        score_color, score_label = "#E67E22", "Umjereno"
    else:
        score_color, score_label = "#C0392B", "Kritično"

    def finding_cards(findings, source):
        if not findings:
            return f'<div class="no-issues">✓ Nisu pronađeni problemi u {source}</div>'
        html = ""
        for f in findings:
            sev = f["severity"]
            color = SEVERITY_COLOR[sev]
            line_info = f" · Linija {f['line']}" if f.get("line") else ""
            html += f"""
        <div class="finding">
          <div class="finding-header">
            <span class="sev-badge" style="background:{color}">{sev}</span>
            <span class="finding-id">{f['id']}</span>
            <span class="finding-title">{f['title']}</span>
          </div>
          <div class="finding-meta">{source}{line_info}</div>
          <div class="finding-desc">{f['description']}</div>
          <div class="finding-fix"><strong>Rješenje:</strong> {f['fix']}</div>
        </div>"""
        return html

    files_scanned = ", ".join(target_files) if target_files else "—"
    timestamp = datetime.now().strftime("%d.%m.%Y u %H:%M")

    return f"""<!DOCTYPE html>
<html lang="bs">
<head>
<meta charset="UTF-8">
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
    <div class="header-meta">Skenirani fajlovi: {files_scanned} · Generirano: {timestamp}</div>
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
        Pronađeno ukupno {len(all_findings)} problema.
        {'Kritični problemi zahtijevaju hitnu pažnju.' if counts['CRITICAL'] > 0 else 'Nema kritičnih problema.'}
      </div>
    </div>
  </div>
  <div class="summary-grid">
    <div class="sev-card"><div class="count" style="color:#C0392B">{counts['CRITICAL']}</div><div class="label">CRITICAL</div></div>
    <div class="sev-card"><div class="count" style="color:#E67E22">{counts['HIGH']}</div><div class="label">HIGH</div></div>
    <div class="sev-card"><div class="count" style="color:#2980B9">{counts['MEDIUM']}</div><div class="label">MEDIUM</div></div>
    <div class="sev-card"><div class="count" style="color:#27AE60">{counts['LOW']}</div><div class="label">LOW</div></div>
  </div>
  <div class="section-title">Dockerfile — nalazi</div>
  {finding_cards(dockerfile_findings, 'Dockerfile')}
  <div class="section-title">docker-compose.yml — nalazi</div>
  {finding_cards(compose_findings, 'docker-compose.yml')}
</div>
<div class="footer">ContainerGuard · Sigurnosni skener kontejnerskih aplikacija</div>
</body>
</html>"""


# ─────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────

def scan_file(path):
    if not os.path.exists(path):
        return None, f"Fajl nije pronađen: {path}"
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
        print(f"  ✓  Učitan: {dockerfile_path}")
        scanned_files.append(dockerfile_path)
        dockerfile_findings = run_dockerfile_checks(dockerfile_content)

    compose_content, err = scan_file(compose_path)
    if err:
        print(f"  ⚠  {err}")
        compose_findings = []
    else:
        print(f"  ✓  Učitan: {compose_path}")
        scanned_files.append(compose_path)
        compose_findings = run_compose_checks(compose_content)

    all_findings = dockerfile_findings + compose_findings
    score = calculate_score(all_findings)

    print(f"\n  Pronađeno problema: {len(all_findings)}")
    print(f"  Security Score:    {score}/100\n")

    for f in all_findings:
        icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🔵", "LOW": "🟢"}.get(f["severity"], "•")
        line = f" (linija {f['line']})" if f.get("line") else ""
        print(f"  {icon} [{f['severity']}] {f['id']} — {f['title']}{line}")

    report_path = "containerguard_report.html"
    html = generate_html_report(dockerfile_findings, compose_findings, score, scanned_files)
    with open(report_path, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"\n  ✅  HTML report sačuvan: {report_path}")

    with open("containerguard_report.json", "w", encoding="utf-8") as f:
        json.dump({
            "score": score,
            "timestamp": datetime.now().isoformat(),
            "findings": [{k: v for k, v in f.items() if k not in ("pattern", "check_fn")} for f in all_findings],
        }, f, indent=2, ensure_ascii=False)
    print("  ✅  JSON report sačuvan: containerguard_report.json\n")

    critical_count = sum(1 for f in all_findings if f["severity"] == "CRITICAL")
    sys.exit(1 if critical_count > 0 else 0)


if __name__ == "__main__":
    main()