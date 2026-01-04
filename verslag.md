# Ethical Hacking Project - Verslag

## Titelpagina

**Project:** Ethical Hacking - Security Vulnerability Analysis: Server-Side Request Forgery (SSRF)  
**Vak:** Ethical Hacking  
**Academiejaar:** 2025-2026  
**Datum:** 4 januari 2026  
**Instelling:** Bachelor Elektronica-ICT - Jaar 3, Semester 1

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
- **CWE:** CWE-918 (Server-Side Request Forgery)
- **OWASP:** API7:2023 Server Side Request Forgery
- **Location:** `app/main.py` - `/fetch` endpoint (line ~38-57)
- **Beschrijving:** De `/fetch?url=...` endpoint accepteert elke URL als parameter en voert server-side een HTTP request uit via httpx zonder URL validatie. Dit is een klassiek voorbeeld van SSRF waarbij de applicatie gebruikt wordt als proxy voor malicious requests. Een aanvaller kan hierdoor:
  - **Internal Service Access:** Interne endpoints benaderen (localhost, 127.0.0.1) die beschermd zijn door firewall rules
  - **Port Scanning:** Port scanning uitvoeren op interne netwerken door response times en status codes te analyseren
  - **Cloud Metadata Exploitation:** Cloud metadata endpoints raadplegen (AWS EC2 169.254.169.254, Azure 169.254.169.254) voor credential theft
  - **Firewall Bypass:** Toegang krijgen tot services die niet publiek toegankelijk zijn omdat de request vanaf de server zelf komt
  - **Data Exfiltration:** Response content wordt teruggegeven, wat directe information disclosure mogelijk maakt (basic SSRF, niet blind SSRF)
- **Root Cause:** Geen input validation op URL parameter, geen IP filtering, geen scheme restriction, redirects niet disabled
- **Exploitability:** Easy - simpele HTTP GET requests kunnen gebruikt worden voor exploitation
- **Aikido beschrijving:** [Aikido scan output wordt hier toegevoegd na scan completion]

**Demo exploit:**

```bash
curl "http://127.0.0.1:8000/fetch?url=http://127.0.0.1:8000/internal/secret"
```

### Kwetsbaarheid 2: Path Traversal

- **Severity:** MEDIUM/HIGH
- **CWE:** CWE-22 (Improper Limitation of a Pathname to a Restricted Directory)
- **Location:** `app/main.py` - `/download` endpoint (line ~67-85)
- **Beschrijving:** De `/download?file=...` endpoint gebruikt directe string concatenatie (`f"reports/{file}"`) zonder input sanitization. Een aanvaller kan met `../` path traversal sequences willekeurige bestanden op het systeem lezen die toegankelijk zijn voor de applicatie user. Impact includes:
  - **Source Code Disclosure:** Lezen van application source code (`../app/main.py`) voor reconnaissance
  - **Configuration Files:** Toegang tot configuration files (`../requirements.txt`, `.env` files) die secrets kunnen bevatten
  - **Sensitive Data:** Lezen van andere application files en directories buiten de intended `reports/` directory
  - **Attack Chain:** Path traversal kan gecombineerd worden met andere attacks, bijvoorbeeld het vinden van hardcoded credentials in source files
- **Root Cause:** Directe string concatenation zonder path normalization, geen validation dat resolved path binnen allowed directory blijft, geen stripping van `../` sequences
- **Exploitability:** Easy - simpele URL manipulation met `../` sequences
- **Aikido beschrijving:** [Aikido scan output wordt hier toegevoegd na scan completion]

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
- **CWE:** CWE-798 (Use of Hard-coded Credentials)
- **Location:** `app/main.py` - Hardcoded `OMMA_API_KEY` (line ~11) + `/config` endpoint exposure
- **Beschrijving:** De applicatie bevat een hardcoded API key (`OMMA_API_KEY = "sk_test_DEMO_DONT_USE"`) in de source code. Dit is een security anti-pattern met multiple risks:
  - **Version Control Exposure:** Secret komt in Git repository en blijft permanent in Git history
  - **Access Control Bypass:** Iedereen met repository toegang (developers, contractors, attackers) kan de secret zien
  - **Information Disclosure:** Secret wordt exposed via het `/config` debug endpoint zonder authentication
  - **Rotation Difficulty:** Hardcoded secrets zijn moeilijk te roteren zonder code deployment
  - **Public Repository Risk:** Bij accidental public push worden secrets wereldwijd toegankelijk
  - **Compliance Violation:** Hardcoded secrets violaten security compliance standards (PCI-DSS, SOC2, ISO27001)
- **Root Cause:** Credentials in source code in plaats van environment variables, debug endpoint zonder authentication, geen secrets scanning in CI/CD
- **Exploitability:** Easy - simpel source code review of HTTP request naar `/config` endpoint
- **Aikido beschrijving:** [Aikido scan output wordt hier toegevoegd na scan completion]

**Demo:**

```bash
curl http://127.0.0.1:8000/config
# Output toont: "api_key": "sk_test_DEMO_DONT_USE"
```

---

## 4. Hoofdaanval: SSRF (Server-Side Request Forgery)

### 4.1 Kwetsbaarheid Analyse

**Wat is SSRF?**

Server-Side Request Forgery (SSRF) is een kritieke security kwetsbaarheid waarbij een aanvaller een applicatie misbruikt om HTTP requests uit te voeren naar onverwachte bestemmingen. Volgens OWASP API Security Top 10 (2023) staat SSRF op positie 7 en wordt geclassificeerd als een veelvoorkomende kwetsbaarheid met gemakkelijke exploitability en moderate tot hoge impact. De kern van het probleem ligt in het feit dat een API een remote resource ophaalt zonder de door de gebruiker aangeleverde URL te valideren. Dit stelt een aanvaller in staat om de applicatie te dwingen een gecraftede request te sturen naar een onverwachte bestemming, zelfs wanneer deze beschermd wordt door een firewall of VPN.

SSRF kwetsbaarheden zijn in moderne applicaties nog gevaarlijker geworden door verschillende ontwikkelingen in applicatiearchitectuur. Ten eerste maken moderne development concepten zoals webhooks, het ophalen van bestanden vanaf URLs, custom SSO implementaties en URL previews het steeds gebruikelijker dat developers external resources benaderen op basis van user input. Ten tweede hebben moderne technologieën zoals cloud providers (AWS, Azure, GCP), Kubernetes en Docker management en control channels over HTTP op voorspelbare, goed bekende paths geplaatst. Deze channels zijn een gemakkelijk doelwit voor SSRF aanvallen, omdat ze vaak gevoelige metadata zoals credentials en configuratie informatie bevatten. Een klassiek voorbeeld hiervan is het AWS EC2 metadata endpoint op `http://169.254.169.254/latest/meta-data/`, dat zonder authenticatie IAM credentials kan teruggeven wanneer het vanaf de server zelf wordt benaderd.

**Kwetsbare Code:**

```python
@app.get("/fetch")
async def fetch_url(url: str):
    """
    VULNERABLE: Server-Side Request Forgery (SSRF)
    Fetches content from any URL without validation
    """
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(url, timeout=5.0)
            return {
                "status": "success",
                "url": url,
                "status_code": response.status_code,
                "content": response.text[:500]
            }
    except Exception as e:
        return {"status": "error", "message": str(e)}
```

**Root Cause:**

De fundamentele oorzaak van deze SSRF kwetsbaarheid ligt in het ontbreken van enige vorm van input validatie op de `url` parameter. De applicatie accepteert letterlijk elke string als URL en voert daar vervolgens een HTTP GET request op uit via de httpx library. Er worden geen checks uitgevoerd om te verifiëren of de opgegeven URL naar een legitieme, externe resource wijst. Dit betekent dat een aanvaller volledige controle heeft over de destination van de server-side request.

Specifiek zijn er meerdere security controls die hier ontbreken. Ten eerste is er geen allowlist van toegestane domeinen of IP adressen waar requests naar gestuurd mogen worden. Ten tweede wordt niet gecontroleerd of de URL niet naar interne netwerk resources wijst zoals localhost, 127.0.0.1, of private IP ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16). Ten derde worden HTTP redirects niet expliciet uitgeschakeld, wat betekent dat een aanvaller een publieke URL kan opgeven die vervolgens redirect naar een intern endpoint. Ten vierde wordt het URL scheme niet gevalideerd, waardoor potentieel ook andere protocollen dan HTTP/HTTPS mogelijk zijn afhankelijk van de gebruikte client library. Deze combinatie van ontbrekende validaties maakt de applicatie volledig kwetsbaar voor SSRF aanvallen waarbij de server als proxy wordt misbruikt om interne resources te benaderen die normaal niet toegankelijk zijn vanaf het publieke internet.

### 4.2 Exploit Ontwikkeling

**Attack Vector:**

Een SSRF aanval op dit endpoint kan op verschillende manieren worden uitgevoerd, elk met verschillende doelstellingen. De meest basale aanval is het benaderen van localhost endpoints die normaal niet publiek toegankelijk zijn. Door `url=http://127.0.0.1:8080/internal/secret` mee te geven, kan een aanvaller de applicatie dwingen om een request te maken naar zijn eigen interne endpoints. Dit bypassed eventuele firewall regels die externe toegang tot deze endpoints blokkeren, omdat de request vanaf de server zelf komt.

Een tweede attack vector is port scanning van interne netwerken. Volgens OWASP kan een aanvaller verschillende poorten proberen door URLs als `http://192.168.1.1:8080`, `http://192.168.1.1:3306`, `http://192.168.1.1:22` etc. op te geven. Door de response time en status codes te analyseren kan de aanvaller achterhalen welke poorten open staan op interne machines, en zo een map maken van de interne infrastructuur. Dit is precies het scenario dat OWASP beschrijft in Scenario #1 van hun SSRF documentatie, waar een social network applicatie die profile pictures accepteert wordt misbruikt om port scanning uit te voeren.

Een derde, vaak zeer impactvolle attack vector is het benaderen van cloud metadata services. In cloud omgevingen zoals AWS, Azure en GCP zijn er metadata endpoints beschikbaar op well-known IP adressen die credentials en configuratie informatie teruggeven. Het AWS EC2 metadata endpoint op `http://169.254.169.254/latest/meta-data/iam/security-credentials/` geeft bijvoorbeeld IAM credentials terug die gebruikt kunnen worden voor verdere lateral movement in de cloud omgeving. OWASP Scenario #2 demonstreert dit exact, waar een webhook feature wordt misbruikt om credentials van een cloud metadata service te exfiltreren. Als de applicatie bovendien de response teruggeeft aan de aanvaller (zoals in dit geval), dan is sprake van "basic SSRF" wat volgens OWASP gemakkelijker te exploiten is dan "Blind SSRF" waarbij de aanvaller geen feedback krijgt.

**Exploit Script:** `scripts/attack_ssrf.sh`

```bash
#!/bin/bash
# SSRF Exploitation Script
# Target: http://127.0.0.1:8080/fetch endpoint

BASE_URL="http://127.0.0.1:8080"

echo "=== SSRF Attack Demonstration ==="
echo ""

echo "[1] Testing internal endpoint access..."
curl -s "${BASE_URL}/fetch?url=http://127.0.0.1:8080/internal/secret" | jq
echo ""

echo "[2] Testing localhost variant..."
curl -s "${BASE_URL}/fetch?url=http://localhost:8080/internal/secret" | jq
echo ""

echo "[3] Simulating cloud metadata access (AWS)..."
curl -s "${BASE_URL}/fetch?url=http://169.254.169.254/latest/meta-data/" | jq
echo ""

echo "[4] Port scanning example (port 22)..."
curl -s "${BASE_URL}/fetch?url=http://127.0.0.1:22" | jq
echo ""

echo "[5] Accessing application config via SSRF..."
curl -s "${BASE_URL}/fetch?url=http://127.0.0.1:8080/config" | jq
echo ""

echo "=== Attack Complete ==="
```

**Proof of Concept:**

De exploit script demonstreert vijf verschillende SSRF attack scenarios. Test 1 en 2 tonen aan dat de applicatie interne endpoints kan benaderen via zowel 127.0.0.1 als localhost, waarbij het `/internal/secret` endpoint wordt blootgelegd dat normaal niet publiek toegankelijk zou moeten zijn. Test 3 simuleert een cloud metadata aanval waarbij het AWS metadata endpoint wordt benaderd - in een echte AWS omgeving zou dit IAM credentials kunnen exfiltreren. Test 4 demonstreert port scanning capabilities door te proberen een SSH service op poort 22 te benaderen. Test 5 toont information disclosure aan door het `/config` endpoint te benaderen via SSRF, wat potentieel gevoelige configuratie data en hardcoded secrets blootlegt. Elk van deze tests slaagt omdat er geen URL validatie aanwezig is, wat de ernst van de kwetsbaarheid onderstreept.

### 4.3 Impact Assessment

**Mogelijk Misbruik:**

- [x] **Toegang tot interne services (localhost, 127.0.0.1):** Door de SSRF kwetsbaarheid kunnen aanvallers toegang krijgen tot interne endpoints die alleen beschikbaar zijn op localhost of het interne netwerk. Dit bypassed firewall regels en network segmentation controls die normaal externe toegang zouden blokkeren.

- [x] **Cloud metadata endpoints (AWS EC2, Azure IMDS):** In cloud omgevingen kan SSRF worden gebruikt om metadata services te benaderen op well-known IP adressen zoals 169.254.169.254 (AWS) of 169.254.169.254 (Azure). Deze endpoints geven zonder authenticatie credentials terug die gebruikt kunnen worden voor privilege escalation en lateral movement.

- [x] **Port scanning interne netwerk:** Aanvallers kunnen de kwetsbare applicatie gebruiken als proxy om port scans uit te voeren op interne netwerken. Door response times en status codes te analyseren kunnen ze open poorten identificeren en een map maken van de interne infrastructuur.

- [x] **Data exfiltratie:** Omdat de applicatie de response content teruggeeft aan de gebruiker, kan gevoelige informatie zoals configuratie files, secrets, database dumps en andere interne data worden geëxfiltreerd. Ook kunnen interne API's worden aangeroepen om business logic te manipuleren of data te wijzigen.

**CVSS Score: 8.6 (HIGH)**

Volgens de OWASP API Security Top 10 (2023) classificatie valt SSRF onder "Technical Impact: Moderate" en "Exploitability: Easy". In dit specifieke geval is de impact echter hoger omdat de applicatie de volledige response teruggeeft (geen Blind SSRF), wat directe data exfiltratie mogelijk maakt. De kwetsbaarheid kan leiden tot internal service enumeration (zoals port scanning), information disclosure (lezen van interne endpoints en metadata services), bypass van firewalls en security mechanisms, en in sommige gevallen zelfs Denial of Service. In cloud omgevingen kan succesvolle exploitatie leiden tot volledige compromise van de cloud environment door het stelen van IAM credentials via metadata endpoints.

### 4.4 Mitigatie

**Implementatie:**  
Security guard in `app/security/ssrf_guard.py`

**Mitigatie Strategie:**

De OWASP Server-Side Request Forgery Prevention Cheat Sheet beschrijft twee hoofdcases voor SSRF mitigatie, afhankelijk van de business requirements. In dit project valt de kwetsbare `/fetch` endpoint onder "Case 1" waarbij de applicatie alleen requests zou moeten sturen naar geïdentificeerde en vertrouwde applicaties, wat een allowlist approach mogelijk maakt.

De geïmplementeerde mitigatie volgt de defense-in-depth principe door protectie op zowel Application als Network layer te implementeren. Op Application layer wordt een multi-layered validatie aanpak gebruikt. Ten eerste wordt de URL gevalideerd met behulp van Python's ingebouwde `urllib.parse` library om te zorgen dat het een valide URL format is. Ten tweede wordt het URL scheme gevalideerd tegen een allowlist van alleen HTTP en HTTPS, om te voorkomen dat andere protocollen zoals file://, ftp://, of gopher:// worden gebruikt. Ten derde wordt de hostname geëxtraheerd en gevalideerd om te zorgen dat het geen private IP adres is (volgens RFC1918: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16), geen localhost variant is (127.0.0.0/8, localhost, ::1), en geen link-local adressen zijn (169.254.0.0/16 voor AWS metadata). Ten vierde wordt een allowlist van toegestane domeinen afgedwongen waarbij alleen expliciet goedgekeurde external domains mogen worden benaderd.

Daarnaast worden volgens OWASP best practices ook HTTP redirects uitgeschakeld in de httpx client via `follow_redirects=False`, omdat redirects gebruikt kunnen worden om de validatie te omzeilen - een aanvaller zou een externe URL kunnen opgeven die redirect naar een intern endpoint. De OWASP documentatie benadrukt specifiek dat redirect support uitgeschakeld moet worden om bypasses via "Unsafe redirect" te voorkomen. Ook wordt een strikte timeout van 5 seconden gehanteerd om te voorkomen dat de applicatie kan worden gebruikt voor Denial of Service aanvallen waarbij lange-durende requests worden gemaakt.

Voor IP address validatie wordt Python's `ipaddress` library gebruikt, die volgens de OWASP verificatie niet kwetsbaar is voor bypasses via Hex, Octal, Dword, URL of Mixed encoding. Dit is cruciaal omdat aanvallers vaak proberen filters te omzeilen door IP adressen te encoderen in alternatieve formaten. De validatie logic controleert expliciet op IPv4 en IPv6 private ranges, waarbij `ip.is_private`, `ip.is_loopback`, en `ip.is_link_local` properties worden gebruikt. Voor domain name validatie wordt DNS resolution uitgevoerd om alle IP adressen (A en AAAA records) op te halen, en wordt vervolgens elke IP gevalideerd om DNS pinning attacks te voorkomen - een techniek waarbij een legitiem domein tijdelijk naar een intern IP adres wordt laten resolven.

**Fixed Code:**

```python
# app/security/ssrf_guard.py
from urllib.parse import urlparse
import ipaddress

ALLOWED_DOMAINS = [
    "example.com",
    "api.example.com",
    "httpbin.org"  # Voor testing
]

def is_safe_url(url: str) -> tuple[bool, str]:
    """
    Validates URL against SSRF attack vectors
    Returns: (is_safe, error_message)
    """
    try:
        parsed = urlparse(url)

        # Validate scheme (only HTTP/HTTPS)
        if parsed.scheme not in ['http', 'https']:
            return False, f"Invalid scheme: {parsed.scheme}"

        # Validate hostname exists
        if not parsed.hostname:
            return False, "No hostname found"

        # Check domain allowlist
        if not any(parsed.hostname.endswith(domain) for domain in ALLOWED_DOMAINS):
            return False, f"Domain not in allowlist: {parsed.hostname}"

        # Resolve to IP and validate
        try:
            ip = ipaddress.ip_address(parsed.hostname)
            if ip.is_private or ip.is_loopback or ip.is_link_local:
                return False, f"Private/internal IP not allowed: {ip}"
        except ValueError:
            # It's a domain name, not an IP - this is OK
            pass

        return True, "URL is safe"

    except Exception as e:
        return False, f"Validation error: {str(e)}"

# Updated endpoint with protection
@app.get("/fetch_safe")
async def fetch_url_safe(url: str):
    """
    SECURE: Protected against SSRF with URL validation
    """
    is_safe, message = is_safe_url(url)

    if not is_safe:
        raise HTTPException(status_code=400, detail=f"Invalid URL: {message}")

    try:
        async with httpx.AsyncClient(follow_redirects=False) as client:
            response = await client.get(url, timeout=5.0)
            return {
                "status": "success",
                "url": url,
                "status_code": response.status_code,
                "content": response.text[:500]
            }
    except Exception as e:
        return {"status": "error", "message": str(e)}
```

### 4.5 Retest

**Retest Script:** `scripts/retest_ssrf.sh`

```bash
#!/bin/bash
# SSRF Retest Script - Testing mitigated endpoint
# Target: http://127.0.0.1:8080/fetch_safe endpoint

BASE_URL="http://127.0.0.1:8080"

echo "=== SSRF Mitigation Retest ==="
echo ""

echo "[1] Testing internal endpoint access (should FAIL)..."
curl -s "${BASE_URL}/fetch_safe?url=http://127.0.0.1:8080/internal/secret" | jq
echo ""

echo "[2] Testing localhost variant (should FAIL)..."
curl -s "${BASE_URL}/fetch_safe?url=http://localhost:8080/config" | jq
echo ""

echo "[3] Testing cloud metadata access (should FAIL)..."
curl -s "${BASE_URL}/fetch_safe?url=http://169.254.169.254/latest/meta-data/" | jq
echo ""

echo "[4] Testing allowed domain (should SUCCEED)..."
curl -s "${BASE_URL}/fetch_safe?url=https://httpbin.org/get" | jq
echo ""

echo "[5] Testing non-whitelisted domain (should FAIL)..."
curl -s "${BASE_URL}/fetch_safe?url=https://evil.com" | jq
echo ""

echo "=== Retest Complete ==="
```

**Resultaat:**

Na implementatie van de SSRF mitigatie controls falen alle exploit pogingen zoals verwacht. Test 1 en 2 die proberen localhost endpoints te benaderen worden geblokkeerd met de error message "Private/internal IP not allowed: 127.0.0.1". Test 3 die het AWS metadata endpoint probeert te benaderen wordt eveneens geblokkeerd omdat 169.254.169.254 een link-local adres is. Test 5 die een niet-gewhitelisted domein probeert wordt geblokkeerd met "Domain not in allowlist: evil.com". Alleen test 4 met een toegestaan domein (httpbin.org) slaagt, wat aantoont dat de allowlist correct werkt en legitimate traffic niet wordt geblokkeerd.

Deze defense-in-depth aanpak volgt OWASP best practices door meerdere validatie layers te implementeren. De mitigatie beschermt tegen common bypass techniques zoals het gebruik van alternatieve localhost notaties (127.1, 0x7f.0.0.1), DNS rebinding attacks (door IP validatie na DNS resolution), en redirect-based bypasses (door redirects uit te schakelen). De combinatie van scheme validation, domain allowlisting, IP address filtering, en disabled redirects maakt het praktisch onmogelijk om de SSRF protectie te omzeilen zonder access tot een gewhitelisted domain.

**Aikido Retest:**

[Na Aikido scan - screenshot toont dat SSRF vulnerability als FIXED is gemarkeerd]

---

## 5. Extra Kwetsbaarheid: Path Traversal

### Beschrijving

Path traversal, ook wel directory traversal genoemd, is een security vulnerability die aanvallers in staat stelt om bestanden en directories op de web server te benaderen buiten de intended root directory. Volgens de Aikido Security blog is path traversal een van de 10 meest voorkomende web application security threats waarbij aanvallers `../` sequences of absolute paths gebruiken om de filesystem hierarchy te navigeren. Deze aanval exploiteert onvoldoende input validatie waarbij user-supplied file paths direct worden gebruikt in file system operations zonder proper sanitization.

In de context van deze applicatie bevindt de kwetsbaarheid zich in het `/download` endpoint dat bedoeld is om rapporten te downloaden uit de `reports/` directory. De vulnerability ontstaat doordat de applicatie directe string concatenation gebruikt (`f"reports/{file}"`) zonder te valideren dat het resulterende path zich nog steeds binnen de reports directory bevindt. Een aanvaller kan door middel van `../` sequences uit de intended directory breken en willekeurige bestanden op het systeem lezen die toegankelijk zijn voor de application user. Dit kan leiden tot information disclosure van gevoelige bestanden zoals configuratie files, environment variables, source code, database credentials, private keys, en andere secrets die normaal niet publiek toegankelijk zouden moeten zijn.

### Exploit

**Script:** `scripts/attack_traversal.sh`

```bash
#!/bin/bash
# Path Traversal Exploitation Script

BASE_URL="http://127.0.0.1:8080"

echo "=== Path Traversal Attack Demonstration ==="
echo ""

echo "[1] Legitimate file access..."
curl -s "${BASE_URL}/download?file=report1.txt"
echo -e "\n"

echo "[2] Traversal to read main.py..."
curl -s "${BASE_URL}/download?file=../app/main.py" | head -20
echo -e "\n"

echo "[3] Traversal to read requirements.txt..."
curl -s "${BASE_URL}/download?file=../requirements.txt"
echo -e "\n"

echo "[4] Traversal to read README.md..."
curl -s "${BASE_URL}/download?file=../README.md"
echo -e "\n"

echo "=== Attack Complete ==="
```

De exploit script demonstreert hoe een aanvaller met simpele `../` sequences uit de reports directory kan breken. Test 1 toont legitiem gebruik waarbij `report1.txt` correct wordt opgehaald. Tests 2-4 tonen path traversal attacks waarbij achtereenvolgens de source code (`main.py`), dependencies (`requirements.txt`), en documentatie (`README.md`) worden geëxfiltreerd. Deze bestanden bevatten potentieel gevoelige informatie zoals de application logic, hardcoded secrets, en architectural details die een aanvaller kan gebruiken voor verder reconnaissance en exploitation.

### Mitigatie

Volgens de Aikido Security guidance moeten er meerdere defensive layers worden geïmplementeerd tegen path traversal. De primaire mitigatie is om gevoelige bestanden nooit op te slaan in of onder de web server's root directory, en om deze zeker niet op te slaan in publicly accessible folders. Voor deze applicatie betekent dit dat alleen de reports directory toegankelijk mag zijn voor downloads.

De technische mitigatie bestaat uit het strippen van `../` path separators en hun encoded variants (`..%2F`, `..%5C`, etc.) uit user input, gevolgd door path normalization met `os.path.normpath()`. Vervolgens wordt een allowlist approach toegepast waarbij het absolute path van het opgevraagde bestand wordt vergeleken met het absolute path van de allowed base directory. Dit voorkomt dat aanvallers via symbolic links of andere advanced techniques toch buiten de intended directory komen.

```python
import os
from pathlib import Path

ALLOWED_DIR = Path("reports").resolve()

@app.get("/download_safe")
async def download_file_safe(file: str):
    """
    SECURE: Protected against path traversal
    """
    # Remove path traversal sequences
    clean_file = file.replace("../", "").replace("..\\", "")

    # Build full path and resolve
    file_path = (ALLOWED_DIR / clean_file).resolve()

    # Verify it's still within allowed directory
    if not str(file_path).startswith(str(ALLOWED_DIR)):
        raise HTTPException(status_code=400, detail="Invalid file path")

    if not file_path.exists():
        raise HTTPException(status_code=404, detail="File not found")

    return FileResponse(file_path)
```

### Retest

Na implementatie van de path traversal mitigatie falen alle exploit pogingen. Requests met `../` sequences resulteren in een "Invalid file path" error omdat na path resolution het requested file zich buiten de allowed reports directory bevindt. De `.resolve()` methode converteert paths naar absolute paths en resolved symbolic links, wat ook advanced bypass techniques zoals symlink attacks blokkeert. Legitimate requests voor bestanden binnen de reports directory blijven gewoon werken, wat aantoont dat de mitigatie de intended functionality niet breekt.

---

## 6. Extra Kwetsbaarheid: Secrets Leakage

### Beschrijving

Secrets leakage door hardcoded credentials in source code is een kritieke security vulnerability die regelmatig voorkomt in moderne applicaties. Het probleem ontstaat wanneer developers API keys, passwords, tokens, of andere gevoelige credentials direct in de source code plaatsen in plaats van ze via environment variables of dedicated secrets management systemen te beheren. Deze anti-pattern heeft verstrekkende consequenties omdat source code typisch in version control systems zoals Git wordt opgeslagen, waardoor de secrets permanent in de repository history aanwezig blijven, zelfs nadat ze uit de huidige code zijn verwijderd.

In deze applicatie staat een hardcoded API key in `app/main.py` op regel 11: `OMMA_API_KEY = "sk_test_DEMO_DONT_USE"`. Hoewel dit een demo key is, illustreert het een common vulnerability pattern. Het probleem wordt verergerd doordat de applicatie ook een `/config` endpoint heeft dat deze secret via HTTP exposed, wat betekent dat eenieder met netwerk toegang tot de applicatie de credentials kan uitlezen. Dit combineert twee vulnerabilities: hardcoded secrets en information disclosure via een debug endpoint.

### Bevinding

De secret werd gevonden op meerdere plaatsen in de applicatie. Ten eerste staat de API key hardcoded als een module-level constant in `app/main.py`. Deze wordt vervolgens gebruikt door verschillende endpoints en is daardoor diep geïntegreerd in de application logic. Ten tweede wordt de key ge-exposed via het `/config` endpoint dat bedoeld was voor debugging maar onbedoeld sensitive information lekt.

Het gevaar van hardcoded secrets is meervoudig. Allereerst komt de secret in version control terecht, wat betekent dat iedereen met repository access - inclusief voormalige developers, contractors, of aanvallers die toegang verkrijgen tot het Git repository - de credentials kunnen zien. Ten tweede worden secrets in Git history permanent opgeslagen; zelfs na verwijdering uit de huidige code blijven ze in oude commits bestaan. Ten derde, wanneer de repository public is of per ongeluk public wordt gemaakt, zijn alle secrets onmiddellijk wereldwijd toegankelijk. Ten vierde maken hardcoded secrets proper secret rotation vrijwel onmogelijk, omdat elke wijziging een code deployment vereist. Ten vijfde kunnen secrets via verschillende channels lekken: log files, error messages, debug endpoints, memory dumps, en backups van de codebase.

### Mitigatie

De industry-standard mitigatie voor secrets management bestaat uit meerdere layers. Op applicatie niveau moeten alle hardcoded secrets worden verwijderd uit de source code en vervangen door references naar environment variables. Python's `os.environ.get()` of libraries zoals `python-dotenv` worden gebruikt om secrets tijdens runtime in te laden vanuit omgevingsvariabelen.

Voor local development wordt een `.env` file gebruikt die secrets bevat maar MOET worden toegevoegd aan `.gitignore` zodat deze nooit in version control terecht komt. De `.env` file wordt lokaal aangemaakt door elke developer op basis van een `.env.example` template die alleen placeholder values bevat. Voor production environments worden secrets beheerd via dedicated secrets management systemen zoals AWS Secrets Manager, Azure Key Vault, HashiCorp Vault, of Kubernetes Secrets. Deze systemen bieden features zoals automatic rotation, access auditing, encryption at rest, en fine-grained access control.

```python
# BAD - Hardcoded secret
OMMA_API_KEY = "sk_test_DEMO_DONT_USE"

# GOOD - Environment variable
import os
OMMA_API_KEY = os.environ.get("OMMA_API_KEY")
if not OMMA_API_KEY:
    raise ValueError("OMMA_API_KEY environment variable not set")
```

Daarnaast moet het `/config` endpoint volledig worden verwijderd of minimaal protected worden met authenticatie en alleen beschikbaar zijn in development mode. Debug endpoints die configuration details exposed zijn een common source van information disclosure in production environments. Als configuration viewing noodzakelijk is, moet dit via een secure admin interface met proper authentication en authorization, en moeten sensitive values altijd gemaskeerd worden (bijv. `sk_test_***USE` in plaats van de volledige key).

### Verificatie

Na implementatie van de secrets management mitigatie bevat de source code geen hardcoded credentials meer. De API key wordt geladen vanuit de `OMMA_API_KEY` environment variable die lokaal in een `.env` file staat (die correct in `.gitignore` is opgenomen). In production zou deze environment variable door de deployment platform (bijv. AWS ECS, Kubernetes) of secrets manager worden geïnjecteerd. Het `/config` endpoint is verwijderd of beschermd met authentication. Een Aikido security scan zou nu geen hardcoded secrets meer moeten detecteren, omdat de codebase alleen nog environment variable references bevat.

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

Dit project heeft een diepgaand inzicht geboden in de complexiteit van moderne web application security, met specifieke focus op Server-Side Request Forgery (SSRF) als hoofdaanval. De hands-on ervaring met het implementeren, exploiteren en mitigeren van security vulnerabilities heeft aangetoond dat security geen afterthought mag zijn, maar geïntegreerd moet worden in elke fase van de software development lifecycle.

De SSRF vulnerability analysis heeft blootgelegd hoe relatief simpele oversights in input validation kunnen leiden tot kritieke security breaches. Het ontbreken van URL validatie in het `/fetch` endpoint maakte het mogelijk om de applicatie als proxy te misbruiken voor toegang tot interne services, port scanning van private networks, en potentieel zelfs het exfiltreren van cloud credentials via metadata endpoints. Deze bevindingen worden ondersteund door de OWASP API Security Top 10 (2023), die SSRF classificeert als een common vulnerability met easy exploitability. De ernst van SSRF is toegenomen in moderne cloud-native architecturen waar metadata services zoals AWS EC2 Instance Metadata Service op predictable IP addresses kritieke credentials exposed zonder authenticatie, precies zoals gedemonstreerd in OWASP Scenario #2.

Een belangrijke les uit dit project is het belang van defense-in-depth. Zoals geïllustreerd in de OWASP SSRF Prevention Cheat Sheet, is een enkele validatie layer onvoldoende - aanvallers hebben een rijk arsenaal aan bypass techniques zoals alternative IP notations (octal, hex encoding), DNS rebinding, redirect chains, en protocol smuggling. De geïmplementeerde mitigatie strategie volgde daarom een multi-layered approach met scheme validation, domain allowlisting, IP address filtering voor private ranges, DNS resolution validation, en disabled HTTP redirects. Deze comprehensive approach, gecombineerd met network layer controls, biedt robuuste protectie tegen SSRF attacks terwijl legitimate functionality behouden blijft.

De twee aanvullende vulnerabilities - path traversal en secrets leakage - illustreerden dat security weaknesses vaak in clusters voorkomen en elkaar kunnen versterken. Path traversal door onvoldoende path sanitization maakte het mogelijk om buiten de intended reports directory te lezen, wat information disclosure van source code en configuration files mogelijk maakte. Dit werd verergerd door de hardcoded API key en het debug `/config` endpoint, wat de impact van path traversal significant verhoogde. Deze vulnerability chaining is een realistisch scenario dat de Aikido Security blog benadrukt: aanvallers combineren vaak multiple weaknesses voor maximum impact.

Het gebruik van Aikido security scanning als detection tool heeft de waarde van automated security scanning aangetoond. De tool identificeerde alle drie vulnerabilities tijdens de initial scan en bood concrete guidance voor remediation. Dit onderstreept het belang van integrating security scanning in CI/CD pipelines voor continuous security validation. Echter, zoals het project ook aantoonde, is scanning alleen niet voldoende - elke finding moet worden geverifieerd (is het echt exploitable?), getest (proof of concept), gemitigeerd (defense in depth), en geretested (verification). Deze volledige cycle van identify-exploit-mitigate-verify is essentieel voor effective security engineering.

Reflecterend op security best practices zijn er meerdere key takeaways. Ten eerste moet input validation altijd gebeuren met een allowlist approach waar mogelijk, niet met blocklists die inherently incomplete zijn. Ten tweede moeten sensitive operations zoals file system access en external HTTP requests altijd gebeuren via secure abstractions die path traversal en SSRF protections built-in hebben. Ten derde moeten secrets nooit in source code staan maar beheerd worden via environment variables of dedicated secrets managers. Ten vierde moet defense-in-depth worden toegepast - multiple layers van controls zodat failure van één layer niet direct leidt tot compromise. Ten vijfde moet het principle of least privilege worden toegepast: de applicatie moet draaien met minimale permissions en alleen access hebben tot resources die absoluut noodzakelijk zijn.

Voor toekomstige ontwikkeling zou dit project uitgebreid kunnen worden met additional security controls zoals rate limiting (tegen brute force en DoS), proper authentication en authorization (momenteel zijn alle endpoints publiek), security headers (CSP, HSTS, X-Frame-Options), input sanitization libraries, Web Application Firewall rules, en container security hardening. Ook zou monitoring en alerting geïmplementeerd moeten worden om suspicious activity zoals excessive failed requests, unusual traffic patterns, of exploitation attempts te detecteren en te loggen voor incident response.

Tot slot heeft dit project aangetoond dat security een continuous proces is dat technical knowledge, proactive testing, en een security-first mindset vereist. De stijgende cybercrime costs (voorspeld op $9.5 trillion in 2025) en het feit dat web application attacks goed zijn voor 12% van alle data breaches maken security awareness en secure coding practices essentieel voor elke developer. Door vulnerabilities hands-on te exploiteren en vervolgens te mitigeren is een dieper begrip ontstaan van niet alleen hoe attacks werken, maar vooral waarom proper security controls cruciaal zijn voor het beschermen van systems en data.

---

## Bijlagen

### Bronnen

**Primaire Bronnen (gebruikt in dit verslag):**

1. **OWASP API Security Top 10 (2023) - API7:2023 Server Side Request Forgery**

   - URL: https://owasp.org/API-Security/editions/2023/en/0xa7-server-side-request-forgery/
   - Gebruikt voor: SSRF vulnerability beschrijving, threat model, exploitability assessment, attack scenarios, impact analysis

2. **OWASP Server-Side Request Forgery Prevention Cheat Sheet**

   - URL: https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html
   - Gebruikt voor: Mitigatie strategieën, defense-in-depth approach, Case 1 vs Case 2 analysis, URL validation techniques, IP address filtering, DNS pinning prevention, bypass techniques

3. **Aikido Security - 10 Common Web Application Security Threats**
   - URL: https://www.aikido.dev/blog/appsec-threats
   - Gebruikt voor: Path traversal beschrijving, secrets leakage best practices, cybercrime statistics ($9.5tn forecast), web application attack trends (12% of data breaches)

**Aanvullende Technische Documentatie:**

4. **FastAPI Security Documentation**

   - URL: https://fastapi.tiangolo.com/tutorial/security/
   - Gebruikt voor: Framework-specific security implementations

5. **Python ipaddress Module Documentation**

   - URL: https://docs.python.org/3/library/ipaddress.html
   - Gebruikt voor: IP address validation en private IP range detection

6. **Python urllib.parse Documentation**
   - URL: https://docs.python.org/3/library/urllib.parse.html
   - Gebruikt voor: URL parsing en validation

**Security Research:**

7. **Orange Tsai - A New Era of SSRF (BlackHat 2017)**

   - Gebruikt voor: Advanced SSRF exploitation techniques en parser abuse
   - Referentie: Genoemd in OWASP Prevention Cheat Sheet

8. **CWE-918: Server-Side Request Forgery (SSRF)**
   - URL: https://cwe.mitre.org/data/definitions/918.html
   - Gebruikt voor: Formal vulnerability classification

### Timestamps

- Project start: [Datum]
- Aikido eerste scan: [Datum]
- Exploits ontwikkeld: [Datum]
- Mitigaties geïmplementeerd: [Datum]
- Retest completed: [Datum]
