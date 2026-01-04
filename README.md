# Ethical Hacking Project - Kwetsbaarheden & Mitigatie

## Beschrijving

Dit project demonstreert 3 security kwetsbaarheden (SSRF, Path Traversal, Secrets Leakage) in een FastAPI applicatie, met focus op SSRF als hoofdaanval. Aikido security scanning wordt gebruikt voor vulnerability detection.

## Project Structuur

```
app/                    # FastAPI applicatie
app/security/           # Security guards & mitigaties
scripts/                # Exploit & retest scripts
docs/                   # Verslag & documentatie
video/                  # Demo video (later)
```

## How to Run

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Start FastAPI Server

```bash
uvicorn app.main:app --reload --port 8080
```

Server runs at: `http://127.0.0.1:8080`  
API docs: `http://127.0.0.1:8080/docs`

### 3. Open Interactive GUI

**Open in browser:**

```
http://127.0.0.1:8080
```

The GUI provides an interactive demo interface with:

- 🔴 **SSRF Demo** - Test vulnerable and safe URL fetching
- 🔴 **Path Traversal Demo** - Test file downloads with directory traversal
- 🔴 **Secrets Leakage Demo** - View exposed configuration

**Demo files are auto-generated at startup:**

- `reports/` directory (created automatically)
- `reports/report1.txt` (sample file for path traversal demo)

### 4. Test Endpoints (CLI)

**Health Check:**

```bash
curl http://127.0.0.1:8080/
```

**SSRF (Vulnerable):**

```bash
curl "http://127.0.0.1:8080/fetch?url=http://127.0.0.1:8080/internal/secret"
```

**Path Traversal (Vulnerable):**

```bash
curl "http://127.0.0.1:8080/download?file=report1.txt"
curl "http://127.0.0.1:8080/download?file=../app/main.py"
```

**Secrets Exposure:**

```bash
curl http://127.0.0.1:8080/config
```

## Demo Steps (for Video Recording)

### Step 1: Show the GUI

1. Start server: `uvicorn app.main:app --reload --port 8080`
2. Open browser: `http://127.0.0.1:8080`
3. Show the three vulnerability sections

### Step 2: Demonstrate SSRF Attack

1. In SSRF section, use default URL: `http://127.0.0.1:8080/internal/secret`
2. Click "Ophalen (Kwetsbaar)" button
3. Show that internal endpoint is accessible via SSRF
4. Explain: attacker can access internal services from external position

### Step 3: Demonstrate Path Traversal

1. In Path Traversal section, first try legitimate: `report1.txt`
2. Then try attack: `../app/main.py`
3. Show that source code is exposed
4. Try: `../requirements.txt` and `../docs/verslag.md`

### Step 4: Show Secrets Leakage

1. Click "View Exposed Config"
2. Show hardcoded API key
3. Mention it's also in git history (Aikido should detect this)

## API Endpoints

| Method | Endpoint              | Description                             | Status                         |
| ------ | --------------------- | --------------------------------------- | ------------------------------ |
| GET    | `/`                   | Interactive GUI Demo                    | ✅ GUI                         |
| GET    | `/internal/secret`    | Internal endpoint (should be protected) | ⚠️ Internal                    |
| GET    | `/fetch?url=...`      | Server-side URL fetch                   | 🔴 VULNERABLE (SSRF)           |
| GET    | `/fetch_safe?url=...` | Safe URL fetch (coming soon)            | 🚧 Not implemented             |
| GET    | `/download?file=...`  | Download report file                    | 🔴 VULNERABLE (Path Traversal) |
| GET    | `/config`             | App configuration                       | 🔴 VULNERABLE (Secrets leak)   |

## Security Note

⚠️ **WARNING**: This application contains intentional security vulnerabilities for educational purposes.

**Known Vulnerabilities:**

1. **SSRF (Server-Side Request Forgery)** - `/fetch` endpoint accepts any URL
2. **Path Traversal** - `/download` endpoint allows directory traversal
3. **Secrets Leakage** - Hardcoded API key in source code

**DO NOT deploy this to production or public servers!**

## Deliverables

- [ ] Kwetsbare FastAPI app met 3 vulnerabilities
- [ ] Aikido scan results (screenshots)
- [ ] SSRF exploit script + retest script
- [ ] Path traversal exploit script
- [ ] Security mitigations geïmplementeerd
- [ ] Complete verslag (docs/verslag.md)
- [ ] Demo video (max 15min)
