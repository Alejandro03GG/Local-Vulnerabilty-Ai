# Troubleshooting & Diagnostic Guide

This guide details common issues, symptoms, root causes, and verified solutions for **Local Vulnerability AI**.

---

## 1. Backend Connectivity & Port Conflicts

### Symptom: `ERROR: [Errno 48] Address already in use`
- **Cause**: Another service (or an existing instance of `uvicorn`) is bound to port `8000`.
- **Solution**:
  - Identify and terminate the conflicting process:
    ```bash
    # On macOS / Linux:
    lsof -i :8000
    kill -9 <PID>

    # Or specify an alternate port:
    uvicorn vuln_ai.api.main:app --port 8080
    ```
  - If running the backend on a custom port, update `frontend/.env`:
    ```bash
    VITE_API_BASE_URL=http://localhost:8080
    ```

---

## 2. Database & Alembic Migrations

### Symptom: `alembic.util.exc.CommandError: Can't locate revision identified by 'head'`
- **Cause**: Out-of-sync migration revision or corrupted local database file.
- **Solution**:
  - Run database migrations from the `backend/` directory where `alembic.ini` is located:
    ```bash
    cd backend
    source .venv/bin/activate
    alembic upgrade head
    ```
  - For a clean local database reset in development:
    ```bash
    # Default SQLite location:
    rm -f ~/.local/share/vuln-ai/vuln_ai.db*
    alembic upgrade head
    ```

---

## 3. Frontend & API Communication

### Symptom: `Network error occurred connecting to API` in Frontend
- **Cause**:
  1. The backend FastAPI server is not running.
  2. Frontend is querying a mismatched host/port.
  3. CORS blocking requests from an unauthorized origin.
- **Solution**:
  1. Verify backend health probe:
     ```bash
     curl -i http://localhost:8000/health
     # Expected: HTTP/1.1 200 OK {"status":"ok",...}
     ```
  2. Check `frontend/.env`:
     ```bash
     VITE_API_BASE_URL=http://localhost:8000
     ```
  3. Verify CORS configuration in `backend/.env`:
     ```bash
     VULN_AI_API__CORS_ORIGINS=["http://localhost:3000","http://localhost:5173"]
     ```

---

## 4. Local AI & Ollama Diagnostics

### Symptom: Scan completes, but Match Detail shows "AI analysis unavailable"
- **Cause**: The local Ollama daemon is not running on port `11434`, or the required model (`llama3.2`) has not been pulled.
- **Note**: This is expected behavior when Ollama is offline. The core deterministic scanner, version matcher, and risk engine continue to operate without interruption.
- **Solution**:
  1. Start the Ollama server:
     ```bash
     ollama serve
     ```
  2. Verify that the configured model is installed:
     ```bash
     ollama list
     # If missing:
     ollama pull llama3.2
     ```
  3. Test connectivity to the Ollama endpoint:
     ```bash
     curl http://localhost:11434/api/tags
     ```
  4. Trigger a reanalysis from the Match Detail screen in the web console or via API:
     ```bash
     curl -X POST http://localhost:8000/api/v1/matches/<MATCH_ID>/reanalyze
     ```

---

## 5. Vulnerability Catalog & Source Synchronization

### Symptom: Scan returns 0 matches for known vulnerable dependencies
- **Cause**: The local vulnerability catalog has not been populated with advisories from external feeds.
- **Solution**:
  - Open the **Sources** page in the web console (`http://localhost:5173/sources`) and click **Sync Now** for OSV, NVD, or CISA KEV.
  - Or trigger synchronization via the REST API:
    ```bash
    # Sync CISA KEV catalog
    curl -X POST http://localhost:8000/api/v1/sources/sync \
      -H "Content-Type: application/json" \
      -d '{"source_name": "CISA KEV"}'
    ```
  - Verify that records exist in the catalog:
    ```bash
    curl http://localhost:8000/api/v1/vulnerabilities?page_size=5
    ```

### Symptom: `Source synchronization failed: NVD request timed out`
- **Cause**: The public NVD API rate-limits unauthenticated requests (especially during bulk syncs).
- **Solution**:
  - Obtain an official free API key from NIST NVD and add it to `backend/.env`:
    ```bash
    VULN_AI_NVD__API_KEY=your_nvd_api_key_here
    ```
  - Re-run synchronization. OSV and CISA KEV do not require API keys and sync independently.
