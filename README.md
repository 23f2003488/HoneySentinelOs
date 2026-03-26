
\<div align="center"\>
\<img src="[https://img.shields.io/badge/Status-Hackathon\_Ready-success](https://img.shields.io/badge/Status-Hackathon_Ready-success)" alt="Status"\>
\<img src="[https://img.shields.io/badge/Powered\_by-Azure\_OpenAI-blue](https://img.shields.io/badge/Powered_by-Azure_OpenAI-blue)" alt="Azure OpenAI"\>
\<img src="[https://img.shields.io/badge/Database-Azure\_Cosmos\_DB-blueviolet](https://img.shields.io/badge/Database-Azure_Cosmos_DB-blueviolet)" alt="Cosmos"\>
\</div\>

# ⬡ HoneySentinel-OS

### Multi-Agent Security Intelligence Framework

HoneySentinel-OS is an autonomous, multi-agent vulnerability assessment platform. Moving beyond traditional "LLM wrappers" and static rule-scanners, HoneySentinel-OS uses a true **ReAct (Reason + Act)** architecture.

AI agents dynamically explore codebases, semantically trace vulnerabilities, and intelligently pause to consult human engineers when business context is ambiguous.

-----

## 🚀 Key Differentiators (Why this isn't just an LLM Script)

1.  **Stateful Multi-Agent Orchestration:** Agents (Recon, Analysis, Report) operate independently, reading and writing to a single source of truth (**Azure Cosmos DB**). An Orchestrator agent acts as a QA gate, explicitly validating the output of each phase.
2.  **Deterministic Tools + LLM Reasoning:** Agents don't guess. They execute real tools (`semgrep`, `pip-audit`, `regex`) to gather concrete evidence, then use Azure OpenAI to filter out false positives based on your company's custom YAML security policy.
3.  **Semantic Vision via Azure AI Search:** Unlike traditional scanners that read files linearly, our Recon agent indexes the codebase into **Azure AI Search**. The Analysis agent can then execute semantic queries (e.g., *"Find all API routes that call this vulnerable DB function"*) to trace cross-file attack vectors.
4.  **Dynamic Human-In-The-Loop (HITL):** If an agent's confidence drops below the policy threshold (e.g., it finds an API key but suspects it might be a test-fixture), it pauses its execution loop, extracts the code snippet, and pings the human via the UI for business context.

-----

## 🏗️ System Architecture

  * **Frontend:** React (Vite) polling a REST API, ensuring stateless, massively scalable UI delivery.
  * **Backend:** FastAPI orchestrating asynchronous agent loops.
  * **Storage:** Azure Blob Storage (Cloud-native ingestion of codebases).
  * **Memory:** Azure Cosmos DB NoSQL (Real-time agent state & transparency tracking).
  * **AI Engine:** Azure OpenAI (GPT-4o) + Azure AI Search (Semantic indexing).

-----

## 🛠️ Setup & Deployment

### 1\. Prerequisites

Ensure you have Python 3.10+ and Node.js installed. Install global CLI tools:

```bash
pip install semgrep pip-audit
```

### 2\. Environment Variables

Create a `.env` file in the root directory:

```env
# Azure OpenAI
AZURE_OPENAI_ENDPOINT="https://..."
AZURE_OPENAI_API_KEY="..."
AZURE_OPENAI_DEPLOYMENT="gpt-4o"

# Azure Cosmos DB (Shared Memory)
MEMORY_BACKEND="cosmos"
COSMOS_ENDPOINT="https://..."
COSMOS_KEY="..."
COSMOS_DATABASE_NAME="HoneySentinelDB"
COSMOS_CONTAINER_NAME="AgentMemory"

# Azure Storage & Search
AZURE_STORAGE_CONNECTION_STRING="..."
AZURE_SEARCH_ENDPOINT="https://..."
AZURE_SEARCH_ADMIN_KEY="..."
```

### 3\. Run the Backend

```bash
pip install -r requirements.txt
pip install --upgrade fastapi starlette httpx openai azure-search-documents azure-storage-blob azure-cosmos
uvicorn backend.api.main:app --port 8000
```

### 4\. Run the Frontend (Command Center)

```bash
cd frontend
npm install
npm run dev
```

-----

## 🛡️ The Custom Security Policy

HoneySentinel-OS avoids LLM hallucinations by grounding agents in a configurable `policy.yaml`. Users can upload their own policy to define project sensitivity, frameworks, and custom rule enforcement thresholds. If an uploaded policy is malformed, the Orchestrator safely falls back to a universal default to prevent system crashes.