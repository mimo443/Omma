# OMMA Voting App - Ethical Hacking Project

**Honden vs Katten Stem Applicatie** met opzettelijke security vulnerabilities voor educatieve doeleinden.

## 🎯 Kwetsbaarheden

1. **SQL Injection** - `/votes/search` endpoint
2. **Path Traversal** - `/reports/download` endpoint

## 🚀 Setup

```bash
# Install dependencies
pip install -r requirements.txt

# Start server
python main.py
```

Server draait op: **http://127.0.0.1:8080**

## 💥 Exploitatie

```bash
# SQL Injection exploit
bash exploit_sql.sh

# Path Traversal exploit
bash exploit_path.sh
```

## 📝 Documentatie

Zie **verslag.md** voor complete analyse, exploitatie en mitigatie.

## ⚠️ Waarschuwing

Bevat OPZETTELIJKE security vulnerabilities. Alleen voor educatieve doeleinden!
