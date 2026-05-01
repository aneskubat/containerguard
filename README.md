# ContainerGuard

Alat za statičku analizu sigurnosti Docker i Kubernetes konfiguracija.

Razvijen kao praktični dio seminarskog rada iz predmeta Informacijska sigurnost,
na temu: Sigurnost kontejnerskih aplikacija (Docker i Kubernetes).

---

## O projektu

ContainerGuard čita Dockerfile i docker-compose.yml fajlove, traži uobičajene
sigurnosne propuste i generiše HTML izvještaj s objašnjenjima i prijedlozima za popravak.

Alat ne zahtijeva nikakve externe biblioteke — radi s Python standardnom bibliotekom.

---

## Provjere

### Dockerfile

| ID | Ozbiljnost | Opis |
|----|-----------|------|
| DF001 | CRITICAL | Kontejner se pokreće kao root korisnik |
| DF002 | HIGH | Koristi se latest tag za base image |
| DF003 | CRITICAL | Hardcoded lozinka ili API ključ u ENV |
| DF004 | MEDIUM | Koristi se ADD umjesto COPY |
| DF005 | MEDIUM | Nedostaje HEALTHCHECK instrukcija |
| DF006 | LOW | apt-get bez --no-install-recommends |
| DF007 | HIGH | Privilegovani port izložen ispod 1024 |

### docker-compose.yml

| ID | Ozbiljnost | Opis |
|----|-----------|------|
| DC001 | CRITICAL | Privileged mod je uključen |
| DC002 | CRITICAL | Docker socket montiran u kontejner |
| DC003 | HIGH | Hardcoded lozinka u environment varijablama |
| DC004 | MEDIUM | Nedostaju resource limits |
| DC005 | LOW | Restart policy nije definisan |

---

## Pokretanje

```bash
git clone https://github.com/aneskubat/containerguard.git
cd containerguard
python3 scanner.py
xdg-open containerguard_report.html
```

## Output

- `containerguard_report.html` — detaljan izvještaj s preporukama
- `containerguard_report.json` — JSON output za CI/CD integracije
- Exit code 1 ako postoje CRITICAL problemi

## Scoring

| Score | Status |
|-------|--------|
| 80-100 | Dobro |
| 50-79 | Umjereno |
| 0-49 | Kritično |

---

Autor: aneskubat