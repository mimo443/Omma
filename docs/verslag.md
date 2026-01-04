# Ethical Hacking Project - Verslag

## Titelpagina

**Naam:** [Je naam]  
**Vak:** Ethical Hacking  
**Academiejaar:** 2025-2026  
**Datum:** 4 januari 2026  
**Instelling:** Bachelor Elektronica-ICT - Jaar 3

---

## 1. Doel & Scope

### Doelstelling

Het opzetten van een kwetsbare FastAPI applicatie met 3 security vulnerabilities, deze detecteren met Aikido security scanning, exploiteren, en vervolgens mitigeren.

### Scope

- **Hoofdaanval:** Server-Side Request Forgery (SSRF)
- **Extra kwetsbaarheden:** Path Traversal, Secrets Leakage
- **Tooling:** Aikido IDE plugin (gratis), Python FastAPI
- **Platform:** Lokale development omgeving

---

## 2. Tooling & Vereisten

### Project Beschrijving

- **Project:** FastAPI security lab: SSRF (hoofdaanval) + path traversal + secrets leakage (Aikido findings)

### Operating System

- **OS:** Windows (zie screenshot)

### Development Environment

- **IDE:** Cursor
- **Security Scanning:** Aikido Free IDE plugin (token-based) in Cursor
- **Runtime:** Python 3.x
- **Framework:** FastAPI + Uvicorn

### Dependencies

```txt
fastapi==0.115.6
uvicorn[standard]==0.34.0
httpx==0.27.2
```

Zie `requirements.txt` voor volledige lijst.

### Setup & Run

**Installatie:**

```bash
pip install -r requirements.txt
```

**Server starten:**

```bash
uvicorn app.main:app --reload --port 8080
```

**API Documentatie:**

- Server: `http://127.0.0.1:8080`
- Interactive GUI: `http://127.0.0.1:8080` (browser-based demo interface)
- Swagger docs: `http://127.0.0.1:8080/docs`

**Auto-Setup:**

Bij het starten van de applicatie worden automatisch aangemaakt:

- `reports/` directory (voor path traversal demo)
- `reports/report1.txt` (sample file met demo content)

Dit gebeurt via FastAPI startup event, zodat de demo out-of-the-box werkt.

**Interactive GUI Features:**

De root endpoint (`/`) serveert een volledige HTML interface met:

- 🔴 SSRF demo section (vulnerable + safe endpoint testing)
- 🔴 Path Traversal demo section (file download met traversal voorbeelden)
- 🔴 Secrets Leakage demo (config viewer)
- Real-time output display
- Pre-filled exploit voorbeelden
- Educational info boxes met vulnerability uitleg

---

## 3. Aikido Findings (3 Kwetsbaarheden)

### Overview

[Screenshot van Aikido dashboard met 3 detected vulnerabilities]

### Kwetsbaarheid 1: SSRF (Server-Side Request Forgery)

- **Severity:** HIGH/CRITICAL
- **Location:** `app/main.py` - `/fetch` endpoint (line ~38-57)
- **Beschrijving:** De `/fetch?url=...` endpoint accepteert elke URL als parameter en voert server-side een HTTP request uit via httpx zonder URL validatie. Een aanvaller kan hierdoor:
  - Interne endpoints benaderen (localhost, 127.0.0.1)
  - Port scanning uitvoeren op interne netwerken
  - Cloud metadata endpoints raadplegen (AWS, Azure)
  - Toegang krijgen tot services die niet publiek toegankelijk zijn
- **Aikido beschrijving:** [Copy van Aikido output - komt na scan]

**Demo exploit:**

```bash
curl "http://127.0.0.1:8000/fetch?url=http://127.0.0.1:8000/internal/secret"
```

### Kwetsbaarheid 2: Path Traversal

- **Severity:** MEDIUM/HIGH
- **Location:** `app/main.py` - `/download` endpoint (line ~67-85)
- **Beschrijving:** De `/download?file=...` endpoint gebruikt directe string concatenatie (`f"reports/{file}"`) zonder input sanitization. Een aanvaller kan met `../` path traversal sequences willekeurige bestanden op het systeem lezen die toegankelijk zijn voor de applicatie user.
- **Aikido beschrijving:** [Copy van Aikido output - komt na scan]

**Demo exploit:**

```bash
# Legitiem gebruik:
curl "http://127.0.0.1:8000/download?file=report1.txt"

# Path traversal attack:
curl "http://127.0.0.1:8000/download?file=../app/main.py"
curl "http://127.0.0.1:8000/download?file=../requirements.txt"
```

### Kwetsbaarheid 3: Secrets Leakage

- **Severity:** MEDIUM
- **Location:** `app/main.py` - Hardcoded `OMMA_API_KEY` (line ~11)
- **Beschrijving:** De applicatie bevat een hardcoded API key (`OMMA_API_KEY = "sk_test_DEMO_DONT_USE"`) in de source code. Dit is een security anti-pattern omdat:
  - De secret in version control (git) terecht komt
  - Iedereen met repository toegang de secret kan zien
  - De secret wordt ge-exposed via het `/config` endpoint
- **Aikido beschrijving:** [Copy van Aikido output - komt na scan]

**Demo:**

```bash
curl http://127.0.0.1:8000/config
# Output toont: "api_key": "sk_test_DEMO_DONT_USE"
```

---

## 4. Hoofdaanval: SSRF (Server-Side Request Forgery)

### 4.1 Kwetsbaarheid Analyse

**Wat is SSRF?**  
[Uitleg van SSRF vulnerability]

**Kwetsbare Code:**

```python
#Voorbeeld kwetsbare endpoint (komt in stap 2)
```

**Root Cause:**  
[Waarom is deze code kwetsbaar?]

### 4.2 Exploit Ontwikkeling

**Attack Vector:**  
[Hoe exploit je deze kwetsbaarheid?]

**Exploit Script:** `scripts/attack_ssrf.sh`

```bash
# Script inhoud (komt in stap 3)
```

**Proof of Concept:**  
[Screenshots/output van succesvolle exploit]

### 4.3 Impact Assessment

**Mogelijk Misbruik:**

- [ ] Toegang tot interne services (localhost, 127.0.0.1)
- [ ] Cloud metadata endpoints (AWS EC2, Azure IMDS)
- [ ] Port scanning interne netwerk
- [ ] Data exfiltratie

**CVSS Score:** [Score + uitleg]

### 4.4 Mitigatie

**Implementatie:**  
Security guard in `app/security/ssrf_guard.py`

**Mitigatie Strategie:**

- URL whitelist/blacklist
- IP address validation
- Disable redirects
- Network segmentation

**Fixed Code:**

```python
# Gemigeerde versie (komt in stap 4)
```

### 4.5 Retest

**Retest Script:** `scripts/retest_ssrf.sh`

**Resultaat:**  
[Screenshot van gefaalde exploit na mitigatie]

**Aikido Retest:**  
[Screenshot: vulnerability FIXED]

---

## 5. Extra Kwetsbaarheid: Path Traversal

### Beschrijving

[Korte uitleg path traversal]

### Exploit

**Script:** `scripts/attack_traversal.sh`  
[Exploit output/screenshot]

### Mitigatie

[Korte beschrijving van fix]

### Retest

[Bevestiging dat exploit niet meer werkt]

---

## 6. Extra Kwetsbaarheid: Secrets Leakage

### Beschrijving

[Korte uitleg secrets in code]

### Bevinding

[Waar stond de secret? Waarom is dit gevaarlijk?]

### Mitigatie

[Environment variables, .env files, secrets manager]

### Verificatie

[Aikido scan toont geen secrets meer]

---

## 7. Deliverables Checklist

### Code & Scripts

- [ ] `app/main.py` - Kwetsbare FastAPI app
- [ ] `app/security/ssrf_guard.py` - SSRF mitigatie
- [ ] `scripts/attack_ssrf.sh` - SSRF exploit
- [ ] `scripts/retest_ssrf.sh` - SSRF retest
- [ ] `scripts/attack_traversal.sh` - Path traversal exploit
- [ ] `requirements.txt` - Dependencies

### Documentatie

- [ ] `docs/verslag.md` - Dit verslag (compleet)
- [ ] `README.md` - Project beschrijving
- [ ] Aikido screenshots (voor/na mitigatie)
- [ ] Exploit proof-of-concepts

### Video

- [ ] `video/demo.mp4` - Demo video (max 15 min)
  - Aikido scan uitleg
  - SSRF exploit demonstratie
  - Mitigatie implementatie
  - Retest bevestiging
  - Bonus: 2 extra kwetsbaarheden

---

## 8. Conclusie

[Samenvatting van geleerde lessen, belangrijkste bevindingen, reflectie op security best practices]

---

## Bijlagen

### Bronnen

- [OWASP SSRF](https://owasp.org/www-community/attacks/Server_Side_Request_Forgery)
- [Aikido Documentation](https://www.aikido.dev/docs)
- [FastAPI Security](https://fastapi.tiangolo.com/tutorial/security/)

### Timestamps

- Project start: [Datum]
- Aikido eerste scan: [Datum]
- Exploits ontwikkeld: [Datum]
- Mitigaties geïmplementeerd: [Datum]
- Retest completed: [Datum]
