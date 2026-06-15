# AI SOC MVP

An AI-powered Security Operations Center (SOC) MVP designed to ingest logs, detect sophisticated attacks using device fingerprinting and behavioral baselines, triage alerts using LLMs, and autonomously execute tiered responses (e.g., rate limiting, blocking, account locking) in real-time.

## Key Features

- **Real-Time Log Ingestion & Rate Limiting**: Accepts telemetry (logins, OTP requests, page views) and enforces strict API rate limits to mitigate volumetric attacks.
- **Robust Device Fingerprinting**: Generates unique fingerprints using User-Agent, Device ID, and HTTP Header ordering (similar to JA3) to track evasive attackers rotating IP addresses.
- **Immediate Threat Detection & Blocking**: Identifies attack patterns like Credential Stuffing, Bot Scraping, OTP Pumping, and Account Takeovers. Immediately blocks active threats directly at the ingestion layer using `HTTP 403 Forbidden` to prevent the attack from progressing.
- **Incident Correlation**: Intelligently groups related alerts (based on IP, device fingerprint, or targeted user) into unified Incidents to reduce alert fatigue.
- **LLM-Powered Triage (Background Tasks)**: Uses AI to generate human-readable alert summaries, detailed attacker behavior reports, and custom deterrence emails directed at the attacker's ISP—all processed asynchronously so as not to hang the ingestion endpoint.
- **Tiered Autonomous Response Engine**: Reacts to threats based on severity and confidence:
  - Tier 1: Monitor
  - Tier 2: Rate Limit
  - Tier 3: CAPTCHA Challenge
  - Tier 4: Temporary IP Block
  - Tier 5: Permanent IP Block & Account Locking (requires Analyst approval)
- **Human-in-the-Loop Approval Queue**: High-impact defensive actions are queued for manual review by a human analyst.
- **WebSockets & Live Dashboard**: Streams live logs, alerts, and approval requests to the frontend in real-time.
- **Natural Language DB Querying**: Includes an AI chat interface that converts natural language questions into SQL to query the SOC database.

## Architecture & Tech Stack

- **Backend**: Python, FastAPI, SQLite
- **Frontend**: Vanilla JavaScript, HTML, CSS
- **AI Integration**: Custom LLM integrations for summarization, report generation, and NL-to-SQL.
- **Simulation Suite**: Includes `simulate_attacks.py`, a robust tool for running YAML-configured attack scenarios (burst, evasive, distributed botnets, mixed traffic) against the platform.

## Setup & Running

1. **Install dependencies:**
   ```bash
   cd backend
   pip install -r requirements.txt
   ```
2. **Configure environment:**
   Ensure you have a `.env` file in the `backend/` directory with necessary API keys (e.g., `OPENAI_API_KEY`, SMTP credentials for deterrence emails).
3. **Run the API:**
   ```bash
   cd backend
   python main.py
   ```
4. **Run the Frontend:**
   Serve the `frontend/` directory (e.g., `python -m http.server 3000`).
5. **Run the Attack Simulator:**
   ```bash
   python simulate_attacks.py --scenario all
   ```
