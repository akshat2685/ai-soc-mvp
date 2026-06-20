# 🛡️ EDYSOR - Next-Gen AI Security Operations Center

EDYSOR (Enterprise Defense & Yield Security Operations Responder) is an ambitious, AI-native security operations platform designed to augment security teams. 

Traditional SIEMs rely on static correlation rules and trigger thousands of false positives per day. EDYSOR uses an asynchronous Kafka event bus, ClickHouse OLAP, and an autonomous multi-agent Swarm (powered by Gemini 2.0 Flash) to ingest, cluster, analyze, and automatically remediate security threats in real-time.

---

## 🏗️ Architecture

The platform follows a modern, highly-scalable 12-factor architecture:

*   **Ingestion (Kafka KRaft):** Stateless FastAPI ingest nodes accept high-throughput telemetry and publish instantly to an Apache Kafka event stream.
*   **Data Lakehouse (ClickHouse):** Telemetry is routed directly to a massive, columnar ClickHouse `MergeTree` for lightning-fast dashboard aggregations and time-series analysis.
*   **State & Configuration (PostgreSQL + Alembic):** All relational state (Users, RBAC, Alert Status, Playbooks) is stored securely in PostgreSQL with Alembic handling schema migrations.
*   **AI Detection Engine:** A pool of Kafka Consumers pull telemetry off the wire, run it through `scikit-learn` DBSCAN clustering, and query the Gemini Multi-Agent Swarm for a triage verdict.
*   **Continuous Autonomous Learning:** A daily background loop trains an Unsupervised `IsolationForest` on your most recent traffic to catch zero-days dynamically, while adjusting rule confidence based on false-positive decay.
*   **Digital Twin Simulation:** A Neo4j graph engine calculates Blast Radius for every incident, running theoretical "What-If" containment simulations before acting.
*   **Automated LLM Fine-Tuning:** Includes a built-in CLI (`gemini_tuner.py`) to extract ground truth and autonomously fine-tune your Gemini model via the Google AI Studio API.
*   **Vector Memory (Qdrant):** The AI Swarm utilizes Qdrant to recall past incidents and analyst feedback, allowing the system to continuously learn from your environment.
*   **Frontend:** A React + Vite SPA served via NGINX.

## 🔐 Security Posture (Score: 5/5)
EDYSOR is built with zero-trust principles:
*   **Active Defense WAF:** Tiered Response Engine autonomously rate-limits and IP-blocks attackers via Redis.
*   **Hardened DB Routing:** Strict separation of OLTP/OLAP queries using 100% Parameterized queries to eliminate SQL Injection.
*   **RBAC & JWT:** Full JSON Web Token authentication with bcrypt password hashing and tiered analyst roles.
*   **Secrets Management:** No hardcoded credentials. All containers rely on secure environment variables.

## 🚀 Quickstart (Docker Compose)

The easiest way to run the entire stack locally is via `docker-compose`.

### 1. Configure Environment
Create a `.env` file in the root directory:
```bash
JWT_SECRET="generate_a_secure_random_string_here"
GEMINI_API_KEY="your_google_gemini_api_key_here"
```

### 2. Launch the Stack
```bash
docker-compose up --build -d
```

This will spin up:
- The React Frontend (Port `80`)
- The FastAPI Backend (Port `8000`)
- Kafka KRaft Broker
- ClickHouse Server
- PostgreSQL Database
- Redis (Rate Limiting)
- Qdrant (Vector DB)
- Jaeger (OpenTelemetry Tracing)

### 3. Verify Health
Wait 30 seconds for the databases to initialize, then verify the backend:
```bash
curl http://localhost:8000/api/v1/health
```

## ☸️ Enterprise Deployment (Kubernetes)

For production environments, EDYSOR provides standard Kubernetes manifests.

### 1. Apply Secrets
Before applying deployments, create a Kubernetes Secret containing your API keys and database credentials:
```bash
kubectl create secret generic soc-secrets \
  --from-literal=JWT_SECRET="your-secret" \
  --from-literal=GEMINI_API_KEY="your-gemini-key" \
  --from-literal=POSTGRES_PASSWORD="secure-db-password"
```

### 2. Deploy Services
Navigate to the `k8s/` directory and apply the manifests:
```bash
kubectl apply -f k8s/services.yaml
kubectl apply -f k8s/backend-deployment.yaml
kubectl apply -f k8s/consumer-deployment.yaml
kubectl apply -f k8s/frontend-deployment.yaml
```

*Note: You will need to provision your own managed Kafka (e.g., Confluent Cloud or MSK) and ClickHouse instances for a true enterprise deployment, updating the `soc-config` ConfigMap with the connection strings.*

## 🧪 Development & CI/CD

The repository includes a comprehensive `.github/workflows/ci.yml` file that handles Continuous Integration.
On every push to `main`, the CI pipeline will:
1. Run `flake8` to enforce PEP-8 syntax.
2. Execute the `pytest` suite located in `backend/tests/`.
3. Build the Docker images to verify dependencies and multi-stage builds succeed.

To run tests locally:
```bash
cd backend
pytest tests/
```

## 🔐 Security & RBAC

EDYSOR implements strict Attribute-Based and Role-Based Access Control (RBAC). 
Sensitive API endpoints (like `/api/v1/soar/trigger`) are protected by a middleware decorator that enforces specific hierarchical permissions (e.g., `EXECUTE_PLAYBOOK`, `APPROVE_CRITICAL_ACTION`). 

## 🤝 Contributing
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes
4. Push to the branch
5. Open a Pull Request
