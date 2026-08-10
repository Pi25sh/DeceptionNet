# DeceptionNet MVP

DeceptionNet is an AI-orchestrated honeypot and attacker behavior profiling platform. This MVP tracks an attacker's interaction with a Cowrie SSH honeypot, maps actions to MITRE ATT&CK techniques using rule-based mapping, generates AI-powered plain-language summaries using Claude, and presents everything on a modern dashboard with one-click PDF reporting.

## Architecture

* **Honeypot (`honeypot/`)**: A Cowrie SSH honeypot (port 2222) and a Python script that tails the JSON logs and forwards them to the Core API. (Member 2 extends this with Dionaea.)
* **Core API (`core-api/`)**: A FastAPI service backed by **PostgreSQL** that ingests events asynchronously, tracks sessions (with IP + time-window correlation), maps actions to MITRE techniques, and generates PDF reports. Techniques are stored in `session_techniques` with a `source` column (`rule` or `semantic`).
* **AI Service (`ai-service/`)**: A FastAPI service that communicates with the Anthropic Claude API to generate a narrative summary of the attacker's intent, plus (Member 3) a semantic MITRE endpoint.
* **Dashboard (`dashboard/`)**: A Vite/React frontend that displays a premium, dark-themed UI. It renders from the `/ws/live-events` WebSocket — a full session snapshot on connect, then live pushes as events are ingested and AI summaries complete (with reconnect + backoff).

## Notable behavior

* **Async ingestion**: `POST /events` validates and returns immediately; persistence runs in a FastAPI `BackgroundTask` (in a worker thread), so bursts of honeypot traffic can't block the ingestion endpoint. New events are also pushed over the `/ws/live-events` WebSocket.
* **Session correlation**: Events are matched to a session by exact session-id first. If the id is unknown (Dionaea events carry their own ids), the event is correlated to the most recent session from the same `src_ip` within a configurable window (`SESSION_CORRELATION_WINDOW_MINUTES`, default 5).
* **MITRE mapping**: `core-api/mitre.py` maps Cowrie commands and Dionaea protocols to 20 distinct MITRE ATT&CK techniques via a rule table, with a pure-function scoring formula (`combine_severity` / `severity_from_events`) covered by unit tests in `core-api/tests/`.

## Prerequisites

* Docker and Docker Compose installed
* Python 3.x installed (for the attack simulator)
* An Anthropic Claude API key

## Setup & Running

1. **Configure API Key**
   Create a `.env` file in the root directory (if it doesn't exist) and add your Claude API key:
   ```env
   ANTHROPIC_API_KEY=your_claude_api_key_here
   ```
   *(Note: If you don't have a key, the AI Service will return a mock response instead of failing).*

2. **Start the Platform**
   Run all services via Docker Compose. This starts PostgreSQL too (the Core API waits on its healthcheck before serving):
   ```bash
   docker-compose up --build -d
   ```

3. **Access the Dashboard**
   Open your browser and navigate to [http://localhost:3000](http://localhost:3000). Initially, you'll see a "No active sessions found" state.

### Service ports

| Service    | Port        | Notes                                              |
|------------|-------------|----------------------------------------------------|
| Dashboard  | 3000        | Vite/React frontend                                |
| Core API   | 8000        | `POST /events`, `GET /sessions`, `/ws/live-events` |
| AI Service | 8001        | `/summarize`, `/api/v1/ai/semantic-mitre` (M3)     |
| Honeypot   | 2222        | Cowrie SSH                                         |
| PostgreSQL | **5433**    | Host port is 5433 (5432 is taken on this machine); container-internal stays 5432 |

### Environment overrides

* `SEMANTIC_MITRE_URL` — points the Core API at Member 3's semantic MITRE service (default `http://ai-service:8001/api/v1/ai/semantic-mitre`). If it's down or returns non-200, reports fall back to rule-based techniques only.
* `SESSION_CORRELATION_WINDOW_MINUTES` — how far back to look when correlating an unknown session id by `src_ip` (default 5).

4. **Simulate an Attack**
   Run the simulation script to generate a fake attack session against the honeypot:
   ```bash
   pip install paramiko
   python simulate_attack.py
   ```
   *Watch the dashboard auto-update with the new session, technique tags, and score.*

5. **Generate a Report**
   Click on the session in the dashboard to view details, then click "Generate Report". A PDF containing the timeline, MITRE techniques, and AI summary will be downloaded.

## Running the tests

Core API unit tests cover the MITRE rule table, the scoring formula, session
correlation, and technique upserting. They run against an in-memory SQLite DB,
so they don't need Docker:

```bash
cd core-api
pip install -r requirements-dev.txt
pytest
```

*If you're on a very new Python (e.g. 3.14), `psycopg2-binary` may fail to
build; it's only needed to reach Postgres, and the tests never use it — install
the rest of `requirements-dev.txt` minus that one package and `pytest` works
(the test conftest already points the app at SQLite).*

## Stopping
```bash
docker-compose down
```
