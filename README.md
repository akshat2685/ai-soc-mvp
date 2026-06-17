# AI SOC MVP

An AI-powered Security Operations Center (SOC) MVP designed to ingest logs, detect sophisticated attacks using device fingerprinting and behavioral baselines, triage alerts using LLMs, and autonomously execute tiered responses (e.g., rate limiting, blocking, account locking) in real-time.

## Key Features

- **Real-Time Log Ingestion & Rate Limiting**: Accepts telemetry (logins, OTP requests, page views) and enforces strict API rate limits via Redis to mitigate volumetric attacks.
- **Robust Device Fingerprinting**: Generates unique fingerprints using User-Agent, Device ID, and HTTP Header ordering to track evasive attackers rotating IP addresses.
- **Immediate Threat Detection & Blocking**: Identifies attack patterns like Credential Stuffing, Bot Scraping, OTP Pumping, and Account Takeovers. Immediately blocks active threats at the ingestion layer (`HTTP 403 Forbidden`).
- **Incident Correlation & Investigation Engine**: Intelligently groups related alerts into unified Incidents to reduce alert fatigue. Uses Gemini 2.0 Flash to synthesize forensic investigations spanning threat intel, user history, asset criticality, and Mitre ATT&CK mapping.
- **LLM-Powered Triage & Remediation (Background Tasks)**: Uses AI to generate human-readable alert summaries, technical/executive incident reports, remediation steps referencing playbooks (via Qdrant RAG), and custom deterrence emails directed at the attacker's ISP.
- **Tiered Autonomous Response Engine**: Reacts to threats based on severity and confidence:
  - Tier 1: Monitor
  - Tier 2: Rate Limit
  - Tier 3: CAPTCHA Challenge
  - Tier 4: Temporary IP Block
  - Tier 5: Permanent IP Block & Account Locking (requires Analyst approval)
- **Plug-and-Play API Key Integration**: Easily secure your website's backend by validating incoming requests directly with the SOC's Redis-backed WAF rules.
- **Human-in-the-Loop Approval Queue**: High-impact defensive actions are queued for manual review by a human analyst.
- **WebSockets & Live Dashboard**: Streams live logs, alerts, and approval requests to a React-based frontend in real-time.
- **Natural Language DB Querying**: Includes an AI chat interface that converts natural language questions into SQL to query the Postgres SOC database.

## Architecture & Tech Stack

This project is built using a modern microservice-oriented data infrastructure:

- **Backend**: Python, FastAPI
- **Frontend**: React, Vite, TailwindCSS
- **Primary Database**: PostgreSQL (Stores alerts, investigations, assets, logs, threat intel)
- **In-Memory Cache & Rate Limiting**: Redis (Fast rate limiting and WAF blocking)
- **Message Broker**: Kafka + Zookeeper (Asynchronous high-volume log parsing)
- **Vector Database**: Qdrant (RAG engine for retrieving remediation playbooks)
- **Analytics & Big Data**: ClickHouse (High-throughput metric storage)
- **Distributed Tracing**: Jaeger (OpenTelemetry tracing across the stack)
- **AI Integration**: Gemini 2.0 Flash integration for triage, SQL generation, and investigations.

## Setup & Running

This project uses Docker Compose to orchestrate all services.

1. **Configure environment:**
   Create a `.env` file in the root directory (or use environment variables) with:
   ```env
   GEMINI_API_KEY=your_gemini_api_key_here
   ```

2. **Run the entire stack with Docker Compose:**
   ```bash
   docker compose up --build -d
   ```
   This command provisions Postgres, Redis, Kafka, Zookeeper, ClickHouse, Qdrant, Jaeger, the FastAPI backend (port 8000), and the React frontend (port 5173).

3. **Access the Dashboard:**
   Open your browser and navigate to: `http://localhost:5173`

4. **Run the Attack Simulator:**
   To test the SOC capabilities, you can run the attack simulator natively or inside the backend container:
   ```bash
   docker compose exec soc-backend python simulate_attacks.py --scenario all
   ```
   This sends bursts of mixed legitimate and malicious traffic (Credential Stuffing, Account Takeovers, Bots, etc.) to trigger alerts and LLM investigations.

5. **Access Traces (Jaeger):**
   Navigate to: `http://localhost:16686`
