# 🕵️ Chatur-Drishti

> **Graph-Correlated OSINT Reconnaissance with LLM-Grounded Attacker Inference**
```
ChaturDrishti (चतुर्दृष्टि) — Sanskrit for "one who sees in all directions"
```

Chatur-Drishti is a **defensive OSINT intelligence platform** that automatically collects, correlates, and reasons over publicly available data about a target organization. It surfaces what a real attacker could learn from open sources — so defenders can act first.

Built with a FastAPI backend, a Neo4j knowledge graph, a local LLM inference engine (via Ollama), and a React dashboard.

---

## ✨ Features

### 🔍 Multi-Source Data Collection
Parallel collectors that run concurrently and feed a shared graph:

| Collector | What it collects |
|---|---|
| **DNS** | Subdomains, A/AAAA/MX/TXT/NS records |
| **Certificate Transparency** | All certs ever issued for the domain (crt.sh) |
| **Wayback Machine** | Historical URLs, endpoints, exposed paths |
| **GitHub** | Public repos, contributors, secrets, tech stack, Docker/K8s configs |
| **WHOIS** | Registrant identity, registration metadata |
| **Shodan** | Open ports, banners, CVEs, exposed services |
| **Google Dork** | Sensitive files/pages indexed by Google | 

*Google Dork* is **UNDER MAINTENANCE** 

### 🧠 AI-Powered Inference Engine
- Retrieves high/critical sensitivity signals from the graph
- Builds a structured attacker-reasoning prompt with tagged citations (`[S1]`, `[S2]`, …)
- Runs a **local LLM** (Llama 3.1 via Ollama) — no data leaves your machine
- **Citation guardrail**: findings with no grounded evidence are automatically dropped — prevents hallucinations
- Deterministic risk score: `critical×30 + high×15 + medium×5 + low×1`, capped at 100

### 🔗 Correlation Engine
Cross-source signal analysis that builds a structured **Attack Surface**:
- **Confirmed hosts** — subdomains seen by 2+ independent sources
- **Sensitive hosts** — flagged by naming patterns (e.g. `vpn.`, `admin.`, `k8s.`, `staging.`)
- **Technology stack** fingerprinting
- **Cloud profile** — providers, regions, services (AWS, GCP, Azure)
- **People profiles** — contributors, emails, GitHub users (spearphishing surface)
- **Exposed ports** — SSH, RDP, Docker API, databases, Kubernetes API, and more
- **CVE tracking** — from Shodan banner data
- **Secret detection** — leaked credentials in public GitHub repos

### 🗄️ Neo4j Knowledge Graph
All signals and entities are stored as a property graph:
- `Organization → [:EXPOSES] → Entity`
- Entities: `HOSTNAME`, `IP_ADDRESS`, `TECHNOLOGY`, `PERSON`, `CVE`, `OPEN_PORT`, `EMAIL_ADDRESS`, `GITHUB_USER`, and many more
- Queryable via Cypher; graph browser available at `http://localhost:7474`

### 📊 React Dashboard
TypeScript + React frontend with:
- Live analysis trigger per target domain
- Signal feed with sensitivity classification
- Interactive attack surface visualization (Cytoscape.js graph)
- Inference report with evidence-backed findings and risk scores

---

## 🏗️ Architecture
```
Target Domain
      │
      ▼
┌─────────────────────────────────────────┐
│  Layer 1: Multi-Source Collector        │
│  DNS · CRT · GitHub · Shodan ·          │
│  WHOIS · Wayback · Google Dorks         │
│  (7 collectors, run in parallel)        │
└────────────────────┬────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────┐
│  Layer 2: Source-Aware Processing       │
│  Entity Extraction · Sensitivity        │
│  Classification (critical/high/med/low) │
└────────────────────┬────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────┐
│  Layer 3: Neo4j Knowledge Graph         │
│  MERGE-based deduplication · sources[]  │
│  source_count tracked per entity node   │
└────────────────────┬────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────┐
│  Layer 4: Correlation Engine            │
│  Cypher queries → AttackSurface object  │
│  Confirmed hosts · Tech stack · People  │
│  CVEs · Secrets · Risk score            │
└────────────────────┬────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────┐
│  Layer 5: LLM Inference Engine          │
│  Llama 3.1 8B (local via Ollama)        │
│  Citation guardrail: every evidence     │
│  claim must cite a real signal tag [Sn] │
└────────────────────┬────────────────────┘
                     │
                     ▼
┌─────────────────────────────────────────┐
│  Layer 6: React Dashboard               │
│  Attack surface · Findings · KG graph   │
│  Deterministic risk score (0–100)       │
└─────────────────────────────────────────┘
```

---

## 🚀 Installation

### Prerequisites

- Python 3.11+
- Node.js 18+
- Docker & Docker Compose
- [Ollama](https://ollama.com) with `llama3.1:8b` pulled

### 1. Clone the repository

```bash
git clone https://github.com/rahulbothraa/Chatur-Drishti.git
cd Chatur-Drishti
```

### 2. Start infrastructure (Neo4j + Redis)

```bash
cd docker
docker compose up -d
cd ..
```

Neo4j browser will be available at `http://localhost:7474` (user: `neo4j`, password: `chaturdrishti123`).

### 3. Set up Python environment

```bash
python -m venv venv
source venv/bin/activate      # Windows: venv\Scripts\activate

pip install -r requirements.txt

# Install spaCy English model
python -m spacy download en_core_web_sm

# Install Playwright browsers (for web scraping)
playwright install chromium
```

### 4. Configure environment variables

Copy `.env` and fill in your API keys:

```bash
cp .env .env.local   # or edit .env directly
```

| Variable | Description |
|---|---|
| `NEO4J_URI` | Neo4j Bolt URI (default: `bolt://localhost:7687`) |
| `NEO4J_USER` | Neo4j username |
| `NEO4J_PASSWORD` | Neo4j password |
| `REDIS_URL` | Redis URL (default: `redis://localhost:6379`) |
| `GITHUB_TOKEN` | GitHub Personal Access Token (for GitHub collector) |
| `SHODAN_API_KEY` | Shodan API key |
| `GOOGLE_API_KEY` | Google API key (for Google Dork collector) |
| `GOOGLE_CSE_ID` | Google Custom Search Engine ID |

### 5. Pull the local LLM

```bash
ollama pull llama3.1:8b
```

### 6. Start the backend API

```bash
source venv/bin/activate
uvicorn api.main:app --reload --host 0.0.0.0 --port 8000
```

API docs available at `http://localhost:8000/docs`.

### 7. Start the frontend dashboard

```bash
cd dashboard
npm install
npm start
```

Dashboard will open at `http://localhost:3000`.

---

## 🎯 Usage

### Run a full analysis via the dashboard

1. Open `http://localhost:3000`
2. Enter a target domain (e.g. `example.com`)
3. Click **Analyze** — the pipeline runs collectors, correlates signals, and fires the LLM
4. Review the **Attack Surface**, **Signal Feed**, and **Inference Report** tabs


```bash
# Activate venv first
source venv/bin/activate

# Run only data collection
python -c "
import asyncio
from collectors.orchestrator import CollectionOrchestrator
asyncio.run(CollectionOrchestrator('example.com').run())
"

# Run only inference (requires prior collection)
python -c "
from inference.engine import InferenceEngine
report = InferenceEngine().analyze('example.com')
print(report.summary)
for f in report.findings:
    print(f'[{f.risk_level.upper()}] {f.title}')
"

# Run only correlation
python -c "
from intelligence.correlation import CorrelationEngine
surface = CorrelationEngine().build_attack_surface('example.com')
print('Risk score:', surface.risk_score)
"
```

---

## ⚠️ Disclaimer

Chatur-Drishti is built for **defensive, authorized security research only**. Only run it against domains you own or have explicit written permission to analyze. The authors are not responsible for any misuse.

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.
