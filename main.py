"""
OMMA Voting App - Honden vs Katten
Ethical Hacking Project - Kwetsbare Applicatie voor Demonstratie Doeleinden

BEVAT OPZETTELIJKE SECURITY KWETSBAARHEDEN:
1. SQL Injection in /votes/search endpoint
2. Path Traversal in /reports/download endpoint

WAARSCHUWING: Alleen voor educatieve doeleinden - NOOIT in productie gebruiken!
"""

# Importeer benodigde Python libraries
from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse, PlainTextResponse
import aiosqlite
import os
from datetime import datetime

# Maak een nieuwe FastAPI applicatie aan
# FastAPI is een modern Python web framework voor het bouwen van APIs
app = FastAPI(title="OMMA Voting App", version="1.0.0")

# Configuratie variabelen
# DB_PATH: De naam van het database bestand waar alle data wordt opgeslagen
# REPORTS_DIR: De directory waar rapport bestanden worden opgeslagen
DB_PATH = "voting.db"
REPORTS_DIR = "reports"


@app.on_event("startup")
async def startup_event():
    """
    Deze functie wordt EENMALIG uitgevoerd wanneer de applicatie start.

    Wat doet deze functie?
    1. Maakt een 'reports' map aan (als deze nog niet bestaat)
    2. Maakt een demo rapport bestand aan
    3. Maakt de database aan met twee tabellen: 'votes' en 'users'
    4. Vult de database met demo data (4 gebruikers en 4 stemmen)

    Waarom is dit nodig?
    Zodat de applicatie direct werkt zonder dat de gebruiker handmatig
    bestanden of databases moet aanmaken.
    """

    # STAP 1: Maak de reports directory aan
    if not os.path.exists(REPORTS_DIR):
        os.makedirs(REPORTS_DIR)
        print("[OK] Reports directory aangemaakt")

    # STAP 2: Maak een demo rapport bestand aan
    report_file = f"{REPORTS_DIR}/voting_report_2026.txt"
    if not os.path.exists(report_file):
        with open(report_file, "w") as f:
            f.write(
                """OMMA Voting App - Jaarrapport 2026

Totaal Stemmen: 1.234
- Honden: 678 (54.9%)
- Katten: 556 (45.1%)

Meest Actieve Gebruikers:
1. john_doe - 45 stemmen
2. jane_smith - 38 stemmen
3. bob_wilson - 31 stemmen

Status: APPROVED
Datum: 2026-01-04
"""
            )
        print("[OK] Demo rapport aangemaakt")

    # STAP 3: Maak database aan en vul met demo data
    async with aiosqlite.connect(DB_PATH) as db:
        # Maak de 'votes' tabel aan
        # Deze tabel slaat alle stemmen op met: id, username, choice (hond/kat), en timestamp
        await db.execute(
            """
            CREATE TABLE IF NOT EXISTS votes (
                id INTEGER PRIMARY KEY,
                username TEXT NOT NULL,
                choice TEXT NOT NULL,
                timestamp TEXT NOT NULL
            )
        """
        )

        # Maak de 'users' tabel aan
        # Deze tabel slaat gebruikersinformatie op: id, username, email, en role
        await db.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT NOT NULL,
                email TEXT NOT NULL,
                role TEXT NOT NULL
            )
        """
        )

        # Check of er al data in de database staat
        cursor = await db.execute("SELECT COUNT(*) FROM users")
        count = await cursor.fetchone()

        # Als de database leeg is, vul dan met demo data
        if count[0] == 0:
            # Voeg 4 demo gebruikers toe
            demo_users = [
                (1, "admin", "admin@omma.local", "administrator"),
                (2, "john_doe", "john@omma.local", "user"),
                (3, "jane_smith", "jane@omma.local", "user"),
                (4, "bob_wilson", "bob@omma.local", "moderator"),
            ]
            await db.executemany(
                "INSERT INTO users (id, username, email, role) VALUES (?, ?, ?, ?)",
                demo_users,
            )

            # Voeg 4 demo stemmen toe
            demo_votes = [
                (1, "john_doe", "hond", "2026-01-04 10:00:00"),
                (2, "jane_smith", "kat", "2026-01-04 10:05:00"),
                (3, "admin", "hond", "2026-01-04 10:10:00"),
                (4, "bob_wilson", "kat", "2026-01-04 10:15:00"),
            ]
            await db.executemany(
                "INSERT INTO votes (id, username, choice, timestamp) VALUES (?, ?, ?, ?)",
                demo_votes,
            )

            # Sla alle wijzigingen op in de database
            await db.commit()
            print("[OK] Database aangemaakt met demo data")


# ==============================================================================
# NORMALE ENDPOINTS (Legitieme Functionaliteit)
# ==============================================================================


@app.get("/")
async def root():
    """
    Dit is de hoofdpagina van de API.

    Wat doet deze functie?
    Geeft informatie terug over de applicatie en welke endpoints beschikbaar zijn.

    Hoe gebruik je dit?
    Open in je browser: http://127.0.0.1:8080/

    Wat krijg je terug?
    Een JSON object met de naam van de app, versie nummer, en een lijst
    van alle beschikbare API endpoints met uitleg.
    """
    return {
        "app": "OMMA Voting App - Honden vs Katten",
        "version": "1.0.0",
        "endpoints": {
            "vote": "POST /vote?username={naam}&choice={hond|kat}",
            "results": "GET /results",
            "search_user": "GET /votes/search?username={naam} [VULNERABLE - SQL Injection]",
            "download_report": "GET /reports/download?file={naam} [VULNERABLE - Path Traversal]",
        },
        "warning": "Bevat opzettelijke vulnerabilities voor educatieve doeleinden",
    }


@app.post("/vote")
async def cast_vote(username: str, choice: str):
    """
    Deze functie registreert een nieuwe stem in de database.

    Wat doet deze functie?
    1. Controleert of de 'choice' parameter 'hond' of 'kat' is
    2. Maakt een timestamp (tijdstip) aan
    3. Slaat de stem op in de database
    4. Geeft een bevestiging terug aan de gebruiker

    Parameters:
    - username: De naam van de gebruiker die stemt (bijvoorbeeld: "john_doe")
    - choice: De keuze van de gebruiker (moet "hond" of "kat" zijn)

    Hoe gebruik je dit?
    curl -X POST "http://127.0.0.1:8080/vote?username=test&choice=hond"

    Wat krijg je terug?
    Een bevestiging met de username, vote, en timestamp.
    """
    # Controleer of de choice parameter geldig is (moet hond of kat zijn)
    if choice.lower() not in ["hond", "kat"]:
        raise HTTPException(status_code=400, detail="Choice must be 'hond' or 'kat'")

    # Maak een timestamp aan (bijv: "2026-01-04 15:30:00")
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Open een verbinding met de database en sla de stem op
    async with aiosqlite.connect(DB_PATH) as db:
        # Gebruik een VEILIGE parameterized query met ? placeholders
        # Dit voorkomt SQL injection attacks
        await db.execute(
            "INSERT INTO votes (username, choice, timestamp) VALUES (?, ?, ?)",
            (username, choice.lower(), timestamp),
        )
        await db.commit()

    # Geef een succesbericht terug aan de gebruiker
    return {
        "status": "success",
        "username": username,
        "vote": choice.lower(),
        "timestamp": timestamp,
    }


@app.get("/results")
async def get_results():
    """
    Deze functie toont de huidige standen van de voting.

    Wat doet deze functie?
    1. Telt hoeveel stemmen er zijn voor 'hond'
    2. Telt hoeveel stemmen er zijn voor 'kat'
    3. Berekent het totaal aantal stemmen
    4. Berekent de percentages
    5. Geeft alle resultaten terug

    Hoe gebruik je dit?
    curl "http://127.0.0.1:8080/results"

    Wat krijg je terug?
    Een overzicht met:
    - Totaal aantal stemmen
    - Aantal stemmen voor honden
    - Aantal stemmen voor katten
    - Percentages voor beide keuzes
    """
    async with aiosqlite.connect(DB_PATH) as db:
        # Tel het aantal stemmen voor 'hond'
        cursor = await db.execute("SELECT COUNT(*) FROM votes WHERE choice = 'hond'")
        honden = (await cursor.fetchone())[0]

        # Tel het aantal stemmen voor 'kat'
        cursor = await db.execute("SELECT COUNT(*) FROM votes WHERE choice = 'kat'")
        katten = (await cursor.fetchone())[0]

        # Bereken het totaal
        total = honden + katten

        # Geef de resultaten terug met percentages
        return {
            "total_votes": total,
            "honden": honden,
            "katten": katten,
            "percentages": {
                "honden": round(honden / total * 100, 1) if total > 0 else 0,
                "katten": round(katten / total * 100, 1) if total > 0 else 0,
            },
        }


# ==============================================================================
# KWETSBAARHEID 1: SQL INJECTION
# ==============================================================================


@app.get("/votes/search")
async def search_user_votes(username: str):
    """
    KWETSBARE FUNCTIE - SQL INJECTION VULNERABILITY

    Wat doet deze functie?
    Zoekt alle stemmen van een specifieke gebruiker in de database.

    WAAROM IS DIT KWETSBAAR?
    Deze functie gebruikt STRING CONCATENATION om een SQL query te bouwen.
    De 'username' parameter wordt DIRECT in de query geplaatst zonder
    enige vorm van validatie of escaping.

    Voorbeeld van kwetsbare code:
    query = f"SELECT * FROM votes WHERE username = '{username}'"

    Als een gebruiker 'john_doe' invult, wordt de query:
    SELECT * FROM votes WHERE username = 'john_doe'    (NORMAAL)

    Maar als een aanvaller "admin' OR '1'='1" invult, wordt de query:
    SELECT * FROM votes WHERE username = 'admin' OR '1'='1'    (ATTACK!)

    De OR '1'='1' conditie is altijd waar, dus krijgt de aanvaller
    ALLE stemmen uit de database, niet alleen die van 'admin'.

    HOE KAN JE DIT EXPLOITEREN?

    Normale query:
    curl "http://127.0.0.1:8080/votes/search?username=john_doe"

    SQL Injection attack (haalt ALLE stemmen op):
    curl "http://127.0.0.1:8080/votes/search?username=admin'+OR+'1'='1"

    Advanced attack (haalt gebruikersdata op uit andere tabel):
    curl "http://127.0.0.1:8080/votes/search?username='+UNION+SELECT+id,username,email,role+FROM+users--"

    IMPACT:
    - Aanvaller kan alle votes uit de database halen
    - Aanvaller kan user data (emails, roles) uit andere tabellen halen
    - Aanvaller kan authentication omzeilen
    - In sommige gevallen: database modificeren of verwijderen
    """
    try:
        # KWETSBARE CODE: String concatenation in SQL query!
        # De username parameter wordt direct in de query string geplaatst
        # zonder enige vorm van validatie, escaping, of parameterization
        query = f"SELECT * FROM votes WHERE username = '{username}'"

        # Open database verbinding en voer de kwetsbare query uit
        async with aiosqlite.connect(DB_PATH) as db:
            cursor = await db.execute(query)
            rows = await cursor.fetchall()

            # Converteer database rows naar een lijst van dictionaries
            results = []
            for row in rows:
                results.append(
                    {
                        "id": row[0],
                        "username": row[1],
                        "choice": row[2],
                        "timestamp": row[3],
                    }
                )

            # Geef de resultaten terug
            # LET OP: We tonen ook de uitgevoerde query voor demo doeleinden
            # In productie zou dit NOOIT moeten gebeuren (information disclosure)
            return {
                "query_executed": query,
                "found": len(results),
                "votes": results,
            }

    except Exception as e:
        # Als er een fout optreedt, geef dan de fout en de query terug
        # Dit helpt bij debugging, maar in productie zou dit een security risk zijn
        return {"error": str(e), "query": query}


# ==============================================================================
# KWETSBAARHEID 2: PATH TRAVERSAL
# ==============================================================================


@app.get("/reports/download")
async def download_report(file: str):
    """
    KWETSBARE FUNCTIE - PATH TRAVERSAL VULNERABILITY

    Wat doet deze functie?
    Download een rapport bestand uit de 'reports' directory.

    WAAROM IS DIT KWETSBAAR?
    Deze functie gebruikt STRING CONCATENATION om een file path te bouwen.
    De 'file' parameter wordt DIRECT toegevoegd aan de base directory
    zonder enige vorm van validatie of sanitization.

    Voorbeeld van kwetsbare code:
    file_path = f"reports/{file}"

    Als een gebruiker 'voting_report_2026.txt' invult, wordt het path:
    reports/voting_report_2026.txt    (NORMAAL)

    Maar als een aanvaller "../main.py" invult, wordt het path:
    reports/../main.py    (wat resolved naar: main.py)    (ATTACK!)

    De '../' sequence betekent "ga één directory omhoog". Dit stelt
    een aanvaller in staat om uit de 'reports' directory te breken
    en willekeurige bestanden op het systeem te lezen.

    HOE KAN JE DIT EXPLOITEREN?

    Normale query:
    curl "http://127.0.0.1:8080/reports/download?file=voting_report_2026.txt"

    Path Traversal attack (leest source code):
    curl "http://127.0.0.1:8080/reports/download?file=../main.py"

    Lees dependencies file:
    curl "http://127.0.0.1:8080/reports/download?file=../requirements.txt"

    Lees database bestand:
    curl "http://127.0.0.1:8080/reports/download?file=../voting.db"

    Lees system files (Linux):
    curl "http://127.0.0.1:8080/reports/download?file=../../../../../../etc/passwd"

    IMPACT:
    - Aanvaller kan source code van de applicatie lezen
    - Aanvaller kan configuration files lezen (met credentials)
    - Aanvaller kan database bestanden downloaden
    - Aanvaller kan system files lezen
    - Information disclosure kan leiden tot andere attacks
    """
    try:
        # KWETSBARE CODE: Direct string concatenation voor file path!
        # De file parameter wordt direct toegevoegd aan REPORTS_DIR
        # zonder enige validatie of sanitization van '../' sequences
        file_path = f"{REPORTS_DIR}/{file}"

        # Check of het bestand bestaat
        if os.path.exists(file_path):
            # Open het bestand en lees de inhoud
            # encoding="utf-8" voor text files
            # errors="ignore" om binary files niet te laten crashen
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()

            # Geef de file inhoud terug als plain text
            return PlainTextResponse(content)
        else:
            # Als het bestand niet bestaat, geef een 404 error
            raise HTTPException(status_code=404, detail="File not found")

    except Exception as e:
        # Bij een fout, geef een 500 error met de error message
        # LET OP: In productie zou de error message geen details moeten geven
        raise HTTPException(status_code=500, detail=f"Error: {str(e)}")


# ==============================================================================
# START DE APPLICATIE
# ==============================================================================

if __name__ == "__main__":
    """
    Dit blok wordt uitgevoerd wanneer je 'python main.py' runt.

    Wat gebeurt er?
    1. De uvicorn library wordt geïmporteerd
    2. Informatie wordt geprint naar de console
    3. De FastAPI app wordt gestart op http://127.0.0.1:8080

    Hoe start je de applicatie?
    Voer in de terminal uit: python main.py

    Hoe stop je de applicatie?
    Druk op CTRL+C in de terminal
    """
    import uvicorn

    print("Starting OMMA Voting App (Honden vs Katten)...")
    print("Server: http://127.0.0.1:8080")
    print("API Docs: http://127.0.0.1:8080/docs")
    print("WARNING: Vulnerable endpoints active for demonstration!")

    # Start de uvicorn server
    # host="127.0.0.1" betekent: alleen toegankelijk vanaf deze computer
    # port=8080 betekent: de app draait op poort 8080
    uvicorn.run(app, host="127.0.0.1", port=8080)
