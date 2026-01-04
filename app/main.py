from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse, PlainTextResponse, HTMLResponse
import httpx
import os

app = FastAPI(title="OMMA Security Lab", version="1.0.0")

# DEMO ONLY – remove later
# VULNERABLE: Hardcoded secret in source code (Aikido should detect this)
OMMA_API_KEY = "sk_test_DEMO_DONT_USE"


# ============================================================================
# STARTUP: Auto-create demo files
# ============================================================================


@app.on_event("startup")
async def startup_event():
    """
    Startup hook: Create reports/ directory and demo file if they don't exist.

    WHY: Ensures the path traversal demo works out-of-the-box.
    """
    # Create reports directory
    if not os.path.exists("reports"):
        os.makedirs("reports")
        print("✅ Created reports/ directory")

    # Create demo report file
    report_file = "reports/report1.txt"
    if not os.path.exists(report_file):
        with open(report_file, "w") as f:
            f.write(
                """OMMA Security Lab - Sample Report

Report ID: RPT-001
Date: 2026-01-04
Status: DEMO

This is a sample report file for testing the file download functionality.
In a real application, this would contain sensitive business data.

Demo content - nothing confidential here.
"""
            )
        print("✅ Created reports/report1.txt")


# ============================================================================
# GUI: Interactive Demo Interface
# ============================================================================


@app.get("/", response_class=HTMLResponse)
async def root():
    """
    Root endpoint: Serves HTML GUI for interactive vulnerability testing.

    FEATURES:
    - SSRF demo: Test vulnerable and safe URL fetching
    - Path Traversal demo: Test file download with/without traversal
    - Real-time output display
    """
    html_content = """
<!DOCTYPE html>
<html lang="nl">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OMMA Security Lab</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            font-family: Arial, sans-serif;
            background: #f5f5f5;
            color: #333;
            line-height: 1.6;
        }
        .container {
            max-width: 1000px;
            margin: 0 auto;
            padding: 20px;
        }
        header {
            background: #2c3e50;
            color: white;
            padding: 20px;
            margin-bottom: 30px;
        }
        header h1 {
            font-size: 24px;
            margin-bottom: 5px;
        }
        header p {
            font-size: 14px;
            opacity: 0.9;
        }
        .waarschuwing {
            background: #c0392b;
            color: white;
            padding: 12px;
            margin-bottom: 30px;
            border-left: 4px solid #922b21;
        }
        .sectie {
            background: white;
            padding: 25px;
            margin-bottom: 25px;
            border: 1px solid #ddd;
        }
        .sectie h2 {
            font-size: 18px;
            margin-bottom: 15px;
            padding-bottom: 8px;
            border-bottom: 2px solid #2c3e50;
        }
        .info {
            background: #ecf0f1;
            padding: 12px;
            margin-bottom: 20px;
            border-left: 3px solid #2c3e50;
            font-size: 14px;
        }
        .invoer-groep {
            margin-bottom: 15px;
        }
        label {
            display: block;
            margin-bottom: 5px;
            font-weight: 600;
            font-size: 14px;
        }
        input[type="text"] {
            width: 100%;
            padding: 10px;
            border: 1px solid #bdc3c7;
            font-family: 'Courier New', monospace;
            font-size: 13px;
        }
        input[type="text"]:focus {
            outline: none;
            border-color: #2c3e50;
        }
        .knoppen {
            margin-bottom: 15px;
        }
        button {
            padding: 10px 20px;
            border: none;
            cursor: pointer;
            font-size: 14px;
            margin-right: 10px;
            margin-bottom: 10px;
        }
        .knop-kwetsbaar {
            background: #c0392b;
            color: white;
        }
        .knop-kwetsbaar:hover {
            background: #a93226;
        }
        .knop-veilig {
            background: #7f8c8d;
            color: white;
        }
        .knop-veilig:hover {
            background: #95a5a6;
        }
        .uitvoer {
            background: #2c3e50;
            color: #ecf0f1;
            padding: 15px;
            font-family: 'Courier New', monospace;
            font-size: 12px;
            white-space: pre-wrap;
            word-wrap: break-word;
            max-height: 350px;
            overflow-y: auto;
            border: 1px solid #34495e;
        }
        .voorbeelden {
            background: #ecf0f1;
            padding: 10px;
            margin-top: 10px;
            font-family: 'Courier New', monospace;
            font-size: 12px;
        }
        .voorbeelden strong {
            display: block;
            margin-bottom: 5px;
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>OMMA Security Lab</h1>
            <p>Ethical Hacking - Kwetsbaarheden Demonstratie</p>
        </header>

        <div class="waarschuwing">
            <strong>Waarschuwing:</strong> Deze applicatie bevat opzettelijke beveiligingslekken uitsluitend voor educatieve doeleinden.
        </div>

        <div class="sectie">
            <h2>A. SSRF - Server-Side Request Forgery</h2>
            
            <div class="info">
                <strong>Kwetsbaarheid:</strong> Server voert HTTP requests uit naar gebruiker-opgegeven URLs zonder validatie.<br>
                <strong>Impact:</strong> Toegang tot interne endpoints, port scanning, cloud metadata leakage.<br>
                <strong>Oplossing:</strong> URL whitelist, IP validatie, redirects uitschakelen.
            </div>

            <div class="invoer-groep">
                <label>URL om op te halen (server-side):</label>
                <input type="text" id="ssrf-url" 
                       value="http://127.0.0.1:8080/internal/secret"
                       placeholder="http://example.com">
            </div>

            <div class="knoppen">
                <button class="knop-kwetsbaar" onclick="haal_kwetsbaar()">
                    Ophalen (Kwetsbaar)
                </button>
                <button class="knop-veilig" onclick="haal_veilig()">
                    Ophalen (Beveiligd - Niet Geimplementeerd)
                </button>
            </div>

            <div class="voorbeelden">
                <strong>Testvoorbeelden:</strong>
                http://127.0.0.1:8080/internal/secret<br>
                http://127.0.0.1:8080/config<br>
                http://example.com
            </div>

            <div id="ssrf-uitvoer" class="uitvoer">Uitvoer verschijnt hier...</div>
        </div>

        <div class="sectie">
            <h2>B. Path Traversal - Directory Traversal</h2>
            
            <div class="info">
                <strong>Kwetsbaarheid:</strong> Bestandsdownload zonder input sanitization - string concatenatie met ../<br>
                <strong>Impact:</strong> Lezen van willekeurige bestanden (broncode, configuraties).<br>
                <strong>Oplossing:</strong> Path sanitization, whitelist, chroot jail.
            </div>

            <div class="invoer-groep">
                <label>Bestandsnaam om te downloaden:</label>
                <input type="text" id="bestandsnaam" 
                       value="report1.txt"
                       placeholder="report1.txt">
            </div>

            <div class="knoppen">
                <button class="knop-kwetsbaar" onclick="download_bestand()">
                    Download (Kwetsbaar)
                </button>
            </div>

            <div class="voorbeelden">
                <strong>Testvoorbeelden:</strong>
                report1.txt<br>
                ../app/main.py<br>
                ../requirements.txt<br>
                ../docs/verslag.md
            </div>

            <div id="bestand-uitvoer" class="uitvoer">Uitvoer verschijnt hier...</div>
        </div>

        <div class="sectie">
            <h2>C. Secrets Leakage - Hardcoded Credentials</h2>
            
            <div class="info">
                <strong>Kwetsbaarheid:</strong> Hardcoded API key in broncode - zichtbaar voor iedereen met repository toegang.<br>
                <strong>Impact:</strong> Credentials in git geschiedenis, blootgesteld via endpoints.<br>
                <strong>Oplossing:</strong> Environment variables, .env bestanden, secrets manager.
            </div>

            <div class="knoppen">
                <button class="knop-kwetsbaar" onclick="bekijk_configuratie()">
                    Bekijk Configuratie
                </button>
            </div>

            <div id="secrets-uitvoer" class="uitvoer">Uitvoer verschijnt hier...</div>
        </div>
    </div>

    <script>
        // SSRF - Kwetsbaar ophalen
        async function haal_kwetsbaar() {
            const url = document.getElementById('ssrf-url').value;
            const uitvoer = document.getElementById('ssrf-uitvoer');
            
            uitvoer.textContent = 'Bezig met ophalen (kwetsbaar endpoint)...\\n';
            
            try {
                const response = await fetch(`/fetch?url=${encodeURIComponent(url)}`);
                const data = await response.json();
                
                uitvoer.textContent = `SSRF Aanval Succesvol\\n\\n` +
                    `Opgehaalde URL: ${data.fetched_url}\\n` +
                    `Status Code: ${data.status}\\n\\n` +
                    `Response Preview:\\n${data.body_preview}\\n\\n` +
                    `KWETSBAARHEID: Server heeft intern endpoint opgehaald zonder validatie`;
            } catch (error) {
                uitvoer.textContent = `Fout: ${error.message}`;
            }
        }

        // SSRF - Veilig ophalen (niet geimplementeerd)
        async function haal_veilig() {
            const url = document.getElementById('ssrf-url').value;
            const uitvoer = document.getElementById('ssrf-uitvoer');
            
            uitvoer.textContent = 'Bezig met ophalen (veilig endpoint)...\\n';
            
            try {
                const response = await fetch(`/fetch_safe?url=${encodeURIComponent(url)}`);
                const data = await response.json();
                
                uitvoer.textContent = `${data.message}\\n\\n` +
                    `Dit endpoint zal URLs valideren en blokkeren:\\n` +
                    `- Interne IPs (127.0.0.1, 10.x.x.x, 192.168.x.x)\\n` +
                    `- Localhost varianten\\n` +
                    `- Cloud metadata endpoints\\n` +
                    `- Non-HTTP protocols`;
            } catch (error) {
                uitvoer.textContent = `Fout: ${error.message}`;
            }
        }

        // Path Traversal - Download bestand
        async function download_bestand() {
            const bestandsnaam = document.getElementById('bestandsnaam').value;
            const uitvoer = document.getElementById('bestand-uitvoer');
            
            uitvoer.textContent = 'Bezig met downloaden...\\n';
            
            try {
                const response = await fetch(`/download?file=${encodeURIComponent(bestandsnaam)}`);
                
                if (response.ok) {
                    const inhoud = await response.text();
                    
                    if (bestandsnaam.includes('..')) {
                        uitvoer.textContent = `PATH TRAVERSAL SUCCESVOL\\n\\n` +
                            `Bestand: ${bestandsnaam}\\n` +
                            `Status: ${response.status}\\n\\n` +
                            `Inhoud:\\n${'='.repeat(60)}\\n${inhoud}\\n${'='.repeat(60)}\\n\\n` +
                            `KWETSBAARHEID: Buiten reports/ directory gelezen`;
                    } else {
                        uitvoer.textContent = `Bestand Gedownload (Legitiem)\\n\\n` +
                            `Bestand: ${bestandsnaam}\\n\\n` +
                            `Inhoud:\\n${'='.repeat(60)}\\n${inhoud}\\n${'='.repeat(60)}`;
                    }
                } else {
                    const fout = await response.json();
                    uitvoer.textContent = `Fout ${response.status}: ${fout.detail}`;
                }
            } catch (error) {
                uitvoer.textContent = `Fout: ${error.message}`;
            }
        }

        // Secrets - Bekijk configuratie
        async function bekijk_configuratie() {
            const uitvoer = document.getElementById('secrets-uitvoer');
            
            uitvoer.textContent = 'Bezig met ophalen configuratie...\\n';
            
            try {
                const response = await fetch('/config');
                const data = await response.json();
                
                uitvoer.textContent = `SECRETS BLOOTGESTELD\\n\\n` +
                    `API Key: ${data.api_key}\\n` +
                    `Environment: ${data.environment}\\n` +
                    `Debug Mode: ${data.debug}\\n\\n` +
                    `KWETSBAARHEID: Hardcoded secret in broncode (regel 11)\\n` +
                    `Deze secret staat ook in git geschiedenis en is zichtbaar via /config endpoint\\n\\n` +
                    `OPLOSSING: Gebruik environment variables of secrets manager`;
            } catch (error) {
                uitvoer.textContent = `Fout: ${error.message}`;
            }
        }
    </script>
</body>
</html>
    """
    return HTMLResponse(content=html_content)


# ============================================================================
# A) SSRF VULNERABILITY (hoofdaanval)
# ============================================================================


@app.get("/internal/secret")
async def internal_secret():
    """
    INTERNAL ENDPOINT: Simulates a backend service that should NOT be publicly accessible.

    WHY VULNERABLE:
    - In production, this would be on internal network (not exposed to internet)
    - But via SSRF in /fetch endpoint, external attacker can access it

    EXAMPLE ATTACK:
    - Attacker calls: /fetch?url=http://127.0.0.1:8000/internal/secret
    - Server fetches it server-side and returns the secret

    REAL-WORLD IMPACT:
    - Access to internal APIs, databases, admin panels
    - Cloud metadata endpoints (AWS EC2: http://169.254.169.254/latest/meta-data/)
    - Port scanning internal network
    """
    return {"message": "INTERNAL ONLY", "secret": "omma-internal-flag-123"}


@app.get("/fetch")
async def fetch_url(url: str):
    """
    🔴 VULNERABLE: Server-Side Request Forgery (SSRF)

    WHAT IT DOES:
    - Accepts any URL as query parameter
    - Fetches that URL server-side using httpx
    - Returns the response to the client

    WHY VULNERABLE:
    - NO URL validation or sanitization
    - NO IP address blocking (localhost, private IPs)
    - Follows redirects (follow_redirects=True)
    - Can access internal endpoints that client cannot reach

    HOW TO EXPLOIT:
    - /fetch?url=http://127.0.0.1:8000/internal/secret → access internal endpoints
    - /fetch?url=http://169.254.169.254/latest/meta-data/ → cloud metadata (AWS)
    - /fetch?url=http://localhost:6379/ → probe internal services (Redis)

    HOW TO FIX:
    - Implement URL whitelist (only allow specific domains)
    - Block private IP ranges (127.0.0.1, 10.x, 192.168.x, 169.254.x)
    - Disable redirects or validate redirect targets
    - Use network segmentation (app shouldn't reach internal services)

    EXAMPLE INPUT:
    - url=http://127.0.0.1:8000/internal/secret

    EXAMPLE OUTPUT:
    - {"fetched_url": "http://127.0.0.1:8000/internal/secret",
       "status": 200,
       "body_preview": "{\"message\":\"INTERNAL ONLY\",\"secret\":\"omma-internal-flag-123\"}"}
    """
    try:
        # VULNERABLE: No validation on the URL parameter
        async with httpx.AsyncClient(follow_redirects=True, timeout=5.0) as client:
            response = await client.get(url)

            # Return fetched data to attacker
            body_preview = response.text[:500] if response.text else ""

            return JSONResponse(
                {
                    "fetched_url": str(response.url),
                    "status": response.status_code,
                    "body_preview": body_preview,
                }
            )

    except httpx.TimeoutException:
        raise HTTPException(status_code=408, detail="Request timeout")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Fetch error: {str(e)}")


@app.get("/fetch_safe")
async def fetch_url_safe(url: str):
    """
    🟢 SAFE VERSION: Mitigated SSRF (placeholder for step 3)

    WHAT IT WILL DO:
    - Validate URL format and protocol (only http/https)
    - Block private IP ranges (127.0.0.1, 10.x, 192.168.x, 169.254.x, ::1)
    - Block localhost and localhost variants
    - Implement domain whitelist
    - Disable redirects or validate redirect targets
    - Add timeout and rate limiting

    IMPLEMENTATION: Coming in step 3 (using app/security/ssrf_guard.py)
    """
    return JSONResponse(
        status_code=501,
        content={"message": "Not Implemented - safe version coming in step 3"},
    )


# ============================================================================
# B) PATH TRAVERSAL VULNERABILITY
# ============================================================================


@app.get("/download")
async def download_file(file: str):
    """
    🔴 VULNERABLE: Path Traversal (Directory Traversal)

    WHAT IT DOES:
    - Downloads files from reports/ directory
    - Accepts filename as query parameter
    - Returns file contents as plain text

    WHY VULNERABLE:
    - Uses string concatenation: f"reports/{file}"
    - NO input sanitization (doesn't strip ../ or validate path)
    - NO path validation (doesn't check if final path is still in reports/)
    - Attacker can use ../ to traverse to parent directories

    HOW TO EXPLOIT:
    - /download?file=report1.txt → legitimate (returns reports/report1.txt)
    - /download?file=../app/main.py → reads source code
    - /download?file=../requirements.txt → reads dependencies
    - /download?file=../../../../../../etc/passwd → read system files (Linux)

    HOW TO FIX:
    - Sanitize input: remove ../, ./, absolute paths
    - Validate resolved path stays within reports/
    - Use pathlib.resolve() and check if path starts with reports/
    - Use filename whitelist (only allow specific filenames)
    - Use UUIDs instead of user-provided filenames

    EXAMPLE INPUT:
    - file=../app/main.py

    EXAMPLE OUTPUT:
    - (Returns the source code of this file)
    """
    # VULNERABLE: Direct string concatenation without sanitization
    file_path = f"reports/{file}"

    try:
        if os.path.exists(file_path):
            with open(file_path, "r") as f:
                content = f.read()
            return PlainTextResponse(content)
        else:
            raise HTTPException(status_code=404, detail="File not found")

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error reading file: {str(e)}")


# ============================================================================
# C) SECRETS LEAKAGE (for Aikido detection)
# ============================================================================


@app.get("/config")
async def get_config():
    """
    🔴 VULNERABLE: Secrets Leakage

    WHAT IT DOES:
    - Returns application configuration including hardcoded API key

    WHY VULNERABLE:
    - Hardcoded secret in source code (line 11: OMMA_API_KEY)
    - Secret ends up in git repository and history
    - Secret is exposed via HTTP endpoint
    - Anyone with repo access can see the secret

    HOW TO EXPLOIT:
    - Simply call /config endpoint
    - Or read the source code (via path traversal or repo access)

    HOW TO FIX:
    - Use environment variables: os.getenv("OMMA_API_KEY")
    - Use .env files (with python-dotenv) - but don't commit them!
    - Use secrets managers: Azure Key Vault, AWS Secrets Manager, HashiCorp Vault
    - Never commit secrets to git
    - Rotate exposed secrets immediately

    REAL-WORLD IMPACT:
    - API keys leaked → unauthorized API usage, billing charges
    - Database credentials leaked → data breach
    - Cloud provider keys leaked → full infrastructure compromise

    EXAMPLE OUTPUT:
    - {"api_key": "sk_test_DEMO_DONT_USE", "environment": "demo", "debug": true}
    """
    return {
        "api_key": OMMA_API_KEY,  # VULNERABLE: exposing secret
        "environment": "demo",
        "debug": True,
    }


# ============================================================================
# Direct run support (python main.py)
# ============================================================================

if __name__ == "__main__":
    import uvicorn

    print("Starting OMMA Security Lab...")
    print("Server: http://127.0.0.1:8080")
    print("API Docs: http://127.0.0.1:8080/docs")
    print("WAARSCHUWING: Kwetsbare endpoints actief")
    print()

    # Note: reload disabled when running as script (use uvicorn CLI for reload)
    uvicorn.run(app, host="127.0.0.1", port=8080)
