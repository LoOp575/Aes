# Cryptographic Network Forensics Engine

Stage 1: authorized, bounded TLS inventory scanner.

## Scope
- Manual hostname/IP and TCP port input.
- Explicit hostname/IP/CIDR allowlist and port allowlist.
- DNS resolution and one certificate-verified TLS handshake.
- Capture negotiated TLS version, cipher, ALPN, certificate metadata, and duration.
- Persist results in local SQLite.
- Clearly mark nonce reuse as **unverified** unless endpoint telemetry proves the key/nonce pair.

## Safety boundaries
This stage does not perform port-range scans, application requests, credential/cookie collection, packet injection, fuzzing, padding-oracle probes, timing exploitation, or GHASH key recovery. Only scan targets you own or are explicitly authorized to assess.

## Requirements
- Python 3.11+
- Network access from the machine running the scanner
- Explicit authorization for every configured target and port

## Local setup
Run these commands from the repository root:
```bash
python -m venv .venv
# Linux/macOS
source .venv/bin/activate
# Windows PowerShell: .venv\\Scripts\\Activate.ps1
pip install -r cryptographic-network-forensics/requirements.txt
cp cryptographic-network-forensics/.env.example .env
```

Edit `.env` with exact authorized targets. Load it before launching:

Linux/macOS:
```bash
set -a
. ./.env
set +a
uvicorn cnfe.main:app --app-dir cryptographic-network-forensics --host 127.0.0.1 --port 8000
```

Windows PowerShell:
```powershell
Get-Content .env | ForEach-Object {
  if ($_ -match '^([^#=]+)=(.*)$') {
    [Environment]::SetEnvironmentVariable($matches[1], $matches[2], 'Process')
  }
}
uvicorn cnfe.main:app --app-dir cryptographic-network-forensics --host 127.0.0.1 --port 8000
```

## Tests
Linux/macOS:
```bash
PYTHONPATH=cryptographic-network-forensics pytest -q
```

Windows PowerShell:
```powershell
$env:PYTHONPATH = "cryptographic-network-forensics"
pytest -q
```

## API
- `GET /health`
- `POST /api/scan` JSON: `{"target":"AUTHORIZED_HOST","port":443}`
- `GET /api/scans?limit=50`
- Interactive docs: `http://127.0.0.1:8000/docs`

Example:
```bash
curl -X POST http://127.0.0.1:8000/api/scan \\
  -H "Content-Type: application/json" \\
  -d '{"target":"YOUR_AUTHORIZED_DOMAIN","port":443}'
```

## Database
The running prototype stores scan summaries in SQLite table `scans`. A normalized PostgreSQL design is supplied in `database/schema.postgres.sql` for the next deployment stage. Never store raw AES keys, private keys, cookies, or session tokens.

## Deployment architecture
Vercel should host the future dashboard/control plane. Network discovery, packet capture, private-network access, and cryptographic endpoint telemetry belong in an authorized local/server agent. SQLite is for local development only; production should use managed PostgreSQL and authenticated agent ingestion. This repository does not claim that Vercel deployment has been completed.
