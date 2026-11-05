# Resolve issue workflow

This is the integrated BGP Troubleshooter project folder that is open from the Docker Desktop workspace.

## Safety behavior

- Diagnosis continues to use the existing read-only flow.
- The model never supplies commands. Remediation commands come from the typed allow-list in `api/remediation.py`.
- The allow-list supports a verified passive-neighbor fault, a verified administrative neighbor shutdown, and an Established peer whose live state reports `Policy`.
- For `route_filtered`, the operator must enter the exact IPv4 prefixes to receive and a new prefix-list name. The workflow will not invent route values, replace an existing inbound policy, or disable `bgp ebgp-requires-policy`.
- Route-policy success is reported only when live BGP table queries show every entered prefix learned from the selected peer. Otherwise, the result remains unverified and recorded rollback is offered.
- Plans are bound to a diagnosis run, enabled inventory entries, and validated values. They expire after five minutes.
- The API rechecks current config before applying, saves the relevant config and audit record, stops after an error, and verifies the live BGP state afterward.
- Rollback uses the recorded inverse command and requires an explicit click in the UI.

## Run on Windows

Open two PowerShell terminals. Keep Docker Desktop and the real FRR containers running.

Backend terminal:

```powershell
cd "C:\Users\SAUMYA AGARWAL\Downloads\networkops-bgp-troubleshooter-docker-desktop\networkops-bgp-troubleshooter"
& ".\.venv\Scripts\python.exe" -m uvicorn api.main:app --host 127.0.0.1 --port 8000 --reload
```

Frontend terminal:

```powershell
cd "C:\Users\SAUMYA AGARWAL\Downloads\networkops-bgp-troubleshooter-docker-desktop\networkops-bgp-troubleshooter\client"
npm run dev -- --host 127.0.0.1 --port 5173
```

Open `http://127.0.0.1:5173`.

## Tests

Run from the project root:

```powershell
..\networkops-bgp-troubleshooter\.venv\Scripts\python.exe -m unittest tests.test_remediation tests.test_remediation_api -v
```

The tests use isolated fixtures and fake device clients; they do not change the Docker routers.

## Archive contents

The `.env` file contains local SSH credentials and should stay on this machine. Keep it out of shared archives.
