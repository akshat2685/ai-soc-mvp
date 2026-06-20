# EDYSOR-X (V2 Evolution)

An enterprise-grade, AI-powered Cyber Immune System. EDYSOR-X evolves beyond standard SOCs by ingesting telemetry, autonomously investigating threats via LLMs, and executing real-time, tiered defensive playbooks. The V2 Evolution transforms the platform into a self-healing, quantum-secure, and self-learning ecosystem.

## Key V2 Evolution Features

### 🧠 Continuous Online Learning & AI Red Teaming
- **Feedback Ingestion:** The AI engine adjusts trust weights on Sigma rules dynamically based on analyst feedback (Overrides vs. Approvals).
- **Confidence Decay:** Applies exponential decay to stale rules that haven't fired in >30 days to prevent alert fatigue.
- **Canary A/B Routing:** Deploys new experimental detection models in shadow mode to a configurable percentage of traffic (e.g., 10%) to benchmark against production models without risking infrastructure.
- **Autonomous Red Agent:** An LLM-powered Red Team generates polymorphic, Base64-obfuscated attack payloads and injects them into the ingestion pipeline to continuously test the Blue Team.

### 🛡️ Autonomous Response Engine & Deception
- **Tier 0 Auto-Block:** Drops connections at the firewall for Critical threats with >95% AI confidence.
- **Tier 1 Auto-Investigate:** Triggers forensic playbooks (memory snapshots) for threats between 80-95% confidence.
- **Deception Network:** Integrates `cowrie` (SSH) and `dionaea` (multi-protocol) honeypots into the Docker cluster to capture and analyze raw malware payloads.
- **Multi-Sig Kill Switch:** Open Policy Agent (OPA) strictly enforces that any manual destructive actions (e.g., network isolation) require at least *two* admin approvals.

### 🌐 Threat Fusion & Data Lake
- **Multi-Source Threat Fusion:** Replaces single-source intelligence with a weighted fusion engine pulling from VirusTotal, MISP, AlienVault OTX, and Abuse.ch.
- **Sigma Auto-Generator:** Threat Intel IOCs are automatically parsed and dumped into deployable `YAML` Sigma rules.
- **Cloud Data Lake:** Aggregates labeled incidents and synthetic attacks into JSONL and pushes them to Google Cloud Storage (GCS) for continuous offline model fine-tuning.

### 🔐 Long-Term Enterprise Architecture (Hardware Plugins)
- **Quantum-Resistant Cryptography:** Implements true C-bindings for Kyber512 (Key Encapsulation) and Dilithium2 (Digital Signatures) using the `liboqs-python` library to secure communications against future quantum threats.
- **Enterprise Plugin Registry:** A "Bring-Your-Own-Hardware" architecture allowing enterprise buyers to securely drop in their API keys for:
  - Confidential Compute (AMD SEV-SNP memory enclaves)
  - Neuromorphic Compute (Intel Loihi / Lava SNN clusters)
  - Swarm Robotics (ROS orchestration for physical server isolation)
- **Edge IoT Agents:** Lightweight Python agents deployed via K3s that filter syslogs in <100ms locally, forwarding only critical anomalies to the central cluster.

## Architecture & Tech Stack

- **Backend**: Python, FastAPI, Scikit-Learn
- **Frontend**: React, Vite, TailwindCSS (Includes WebXR AR Threat Maps & Native Speech Recognition for Voice SOAR)
- **Databases**: PostgreSQL (Relational), Neo4j (Attack Graphs), Qdrant (Vector/RAG), ClickHouse (Telemetry), Redis (Caching & WAF)
- **Message Broker**: Kafka + Zookeeper

## Setup & Running

1. **Configure environment:**
   Create a `.env` file in the root directory:
   ```env
   GEMINI_API_KEY=your_gemini_api_key_here
   ```

2. **Run the stack:**
   ```bash
   docker compose up --build -d
   ```
   This provisions Postgres, Redis, Kafka, ClickHouse, Qdrant, Neo4j, Jaeger, the Honeypots, the FastAPI backend (port 8000), and the React frontend (port 5173).

3. **Access the Dashboard:**
   Navigate to: `http://localhost:5173`

