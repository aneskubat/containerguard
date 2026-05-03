# ContainerGuard

A static analysis tool for Docker and Kubernetes security configurations.

Developed as a practical implementation alongside a seminar paper on the topic:
Security of Containerized Applications (Docker and Kubernetes).

---

## About

ContainerGuard reads Dockerfile, docker-compose.yml, and Kubernetes YAML manifest files,
identifies common security misconfigurations, and generates an HTML report with
explanations and remediation recommendations.

No external dependencies required — runs on Python standard library only.

---

## Checks

### Dockerfile

| ID | Severity | Description |
|----|----------|-------------|
| DF001 | CRITICAL | Container runs as root user |
| DF002 | HIGH | Latest tag used for base image |
| DF003 | CRITICAL | Hardcoded password or API key in ENV |
| DF004 | MEDIUM | ADD used instead of COPY |
| DF005 | MEDIUM | Missing HEALTHCHECK instruction |
| DF006 | LOW | apt-get without --no-install-recommends |
| DF007 | HIGH | Privileged port exposed (below 1024) |

### docker-compose.yml

| ID | Severity | Description |
|----|----------|-------------|
| DC001 | CRITICAL | Privileged mode enabled |
| DC002 | CRITICAL | Docker socket mounted into container |
| DC003 | HIGH | Hardcoded password in environment variables |
| DC004 | MEDIUM | Missing resource limits |
| DC005 | LOW | Restart policy not defined |

### Kubernetes manifests

| ID | Severity | Description |
|----|----------|-------------|
| K8S001 | CRITICAL | Container runs as root (missing runAsNonRoot) |
| K8S002 | CRITICAL | Privileged container (privileged: true) |
| K8S003 | HIGH | Missing resource limits |
| K8S004 | HIGH | Latest tag used for container image |
| K8S005 | HIGH | allowPrivilegeEscalation not disabled |
| K8S006 | MEDIUM | Missing liveness and readiness probes |
| K8S007 | MEDIUM | Root filesystem is not read-only |
| K8S008 | MEDIUM | hostNetwork or hostPID enabled |
| K8S009 | LOW | Missing labels on resources |
| K8S010 | CRITICAL | Secrets in plaintext environment variables |

---

## Usage

```bash
git clone https://github.com/aneskubat/containerguard.git
cd containerguard

# Scan Dockerfile and docker-compose.yml
python3 scanner.py

# Scan Kubernetes manifests
python3 k8s_scanner.py

# Open report in browser
xdg-open containerguard_report.html
```

## Output

- `containerguard_report.html` — detailed report with remediation recommendations
- `containerguard_report.json` — machine-readable output for CI/CD integrations
- Exit code 1 if CRITICAL issues are found (triggers GitHub Actions failure)

## Scoring

| Score | Status |
|-------|--------|
| 80-100 | Good |
| 50-79 | Moderate |
| 0-49 | Critical |

---

Author: aneskubat