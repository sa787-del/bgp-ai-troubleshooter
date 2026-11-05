# NetworkOps client

React/Vite frontend for the FastAPI BGP troubleshooter. It loads router inventory from `GET /devices` and uses each router's published SSH host/port for real tool calls.

```powershell
npm ci
npm run dev
```

The default API base is `http://localhost:8000`. Set `VITE_API_BASE` in `.env` only when the API runs elsewhere.
