"""
OMMA Voting App - Honden vs Katten
Ethical Hacking Project - Kwetsbare Applicatie voor Demonstratie Doeleinden

KWETSBAARHEDEN:
1. SQL Injection in /votes/search endpoint
2. Path Traversal in /reports/download endpoint

WAARSCHUWING: Bevat opzettelijke security vulnerabilities - ALLEEN voor educatie!
"""

from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse, PlainTextResponse
import aiosqlite
import os
from datetime import datetime

app = FastAPI(title="OMMA Voting App", version="1.0.0")

DB_PATH = "voting.db"
REPORTS_DIR = "reports"


@app.on_event("startup")
async def startup_event():
    """Initialize database and reports directory"""

    # Create reports directory
    if not os.path.exists(REPORTS_DIR):
        os.makedirs(REPORTS_DIR)
        print("[OK] Created reports/ directory")

    # Create demo report
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
        print("[OK] Created voting report")

    # Create database
    async with aiosqlite.connect(DB_PATH) as db:
        # Votes table
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

        # Users table (voor SQL injection demo)
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

        # Check if data exists
        cursor = await db.execute("SELECT COUNT(*) FROM users")
        count = await cursor.fetchone()

        if count[0] == 0:
            # Insert demo users
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

            # Insert some demo votes
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

            await db.commit()
            print("[OK] Created database with demo data")


# ==============================================================================
# NORMALE ENDPOINTS (Legitieme Functionaliteit)
# ==============================================================================


@app.get("/")
async def root():
    """Root endpoint - API info"""
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
    """Cast a vote for hond or kat"""
    if choice.lower() not in ["hond", "kat"]:
        raise HTTPException(status_code=400, detail="Choice must be 'hond' or 'kat'")

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute(
            "INSERT INTO votes (username, choice, timestamp) VALUES (?, ?, ?)",
            (username, choice.lower(), timestamp),
        )
        await db.commit()

    return {
        "status": "success",
        "username": username,
        "vote": choice.lower(),
        "timestamp": timestamp,
    }


@app.get("/results")
async def get_results():
    """Get voting results"""
    async with aiosqlite.connect(DB_PATH) as db:
        # Count honden
        cursor = await db.execute("SELECT COUNT(*) FROM votes WHERE choice = 'hond'")
        honden = (await cursor.fetchone())[0]

        # Count katten
        cursor = await db.execute("SELECT COUNT(*) FROM votes WHERE choice = 'kat'")
        katten = (await cursor.fetchone())[0]

        total = honden + katten

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
    🔴 VULNERABLE: SQL Injection

    Search votes by username - VULNERABLE to SQL injection

    VULNERABILITY:
    - String concatenation in SQL query: f"SELECT * FROM ... WHERE username = '{username}'"
    - NO parameterized queries
    - NO input sanitization

    EXPLOIT:
    - Normal: /votes/search?username=john_doe
    - Attack: /votes/search?username=admin' OR '1'='1
    - Attack: /votes/search?username=' UNION SELECT id,username,email,role FROM users--

    IMPACT:
    - Extract all votes from database
    - Extract user data (emails, roles)
    - Bypass authentication logic
    """
    try:
        # VULNERABLE: String concatenation!
        query = f"SELECT * FROM votes WHERE username = '{username}'"

        async with aiosqlite.connect(DB_PATH) as db:
            cursor = await db.execute(query)
            rows = await cursor.fetchall()

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

            return {
                "query_executed": query,  # Exposing for demo
                "found": len(results),
                "votes": results,
            }

    except Exception as e:
        return {"error": str(e), "query": query}


# ==============================================================================
# KWETSBAARHEID 2: PATH TRAVERSAL
# ==============================================================================


@app.get("/reports/download")
async def download_report(file: str):
    """
    🔴 VULNERABLE: Path Traversal

    Download report file - VULNERABLE to directory traversal

    VULNERABILITY:
    - Direct string concatenation: f"reports/{file}"
    - NO path sanitization (../ not stripped)
    - NO validation that path stays within reports/

    EXPLOIT:
    - Normal: /reports/download?file=voting_report_2026.txt
    - Attack: /reports/download?file=../app/main.py
    - Attack: /reports/download?file=../voting.db
    - Attack: /reports/download?file=../../../../../../etc/passwd (Linux)

    IMPACT:
    - Read source code
    - Read database file
    - Read configuration files
    - Read system files
    """
    try:
        # VULNERABLE: Direct string concatenation!
        file_path = f"{REPORTS_DIR}/{file}"

        if os.path.exists(file_path):
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            return PlainTextResponse(content)
        else:
            raise HTTPException(status_code=404, detail="File not found")

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error: {str(e)}")


# ==============================================================================
# RUN
# ==============================================================================

if __name__ == "__main__":
    import uvicorn

    print("Starting OMMA Voting App (Honden vs Katten)...")
    print("Server: http://127.0.0.1:8080")
    print("API Docs: http://127.0.0.1:8080/docs")
    print("WARNING: Vulnerable endpoints active for demonstration!")
    uvicorn.run(app, host="127.0.0.1", port=8080)
