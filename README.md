# AetherGuard AIOps

AetherGuard is an **Agentic Multi-Cloud AIOps Platform** designed with Cost-Aware Self-Healing and Chaos Resilience. It uses a LangGraph-based multi-agent system to automatically detect anomalies, analyze root causes, generate remediation plans, and test infrastructure resilience via chaos engineering.

## 🚀 Features

- **Agentic Orchestration:** Uses a sophisticated multi-agent pipeline orchestrated with LangGraph.
- **Machine Learning Anomaly Detection:** Real-time ML-powered monitoring (Isolation Forest) of AWS and Network metrics to detect deviations before they escalate.
- **LLM-Powered Root Cause Analysis (RCA):** Automated correlations and textual insights powered by Anthropic's Claude.
- **Cost-Aware Remediation:** Auto-generates fixes prioritizing lower-cost, high-confidence impact strategies.
- **Human-in-the-Loop:** Safety first! Remediation steps pause at an Approval Gate, requiring human sign-off via the dashboard before executing.
- **Automated Chaos Engineering:** Once a fix is applied, the Chaos Engineer Agent injects failures to validate the resilience of the resolution.
- **Interactive Multi-pane Dashboard:** A beautiful Streamlit frontend to visualize data, track incidents, calculate cost savings, and monitor agent thought processes.

## 🏗️ Architecture Stack

- **Backend:** FastAPI, Python 3.11+, LangChain, LangGraph.
- **Frontend:** Streamlit, Plotly, Pandas.
- **Simulators:** Built-in AWS and Network Simulators for safe local testing and development.

## 📂 Project Structure

- `/agents`: Contains LangGraph nodes including Anomaly Detector, RCA Analyst, Remediation Planner, Chaos Engineer, and Supervisor.
- `/backend`: FastAPI application, endpoints for agents, approvals, and websockets.
- `/core`: Event models, config, and system simulators (AWS/Network).
- `/frontend`: Streamlit unified dashboard application.
- `/tests`: Pytest suite spanning unit, integration, and chaos specs.

## 🛠️ Quick Start

### 1. Prerequisites
- Python 3.11+
- An Anthropic API Key (for Claude integration)

### 2. Environment Setup
Rename `.env.example` to `.env` and fill in your keys:
```bash
cp .env.example .env
```

### 3. Install Dependencies
This project uses Hatchling and standard Python tooling. Best used with a virtual environment:
```bash
python -m venv .venv

# On Windows:
.venv\Scripts\activate
# On Mac/Linux:
source .venv/bin/activate

pip install -e ".[dev]"
```

### 4. Running the Platform

You can start the backend API and the UI using standard commands.

**Start the FastAPI Backend:**
```bash
uvicorn backend.main:app --reload --port 8000
```

**Start the Streamlit Dashboard:**
```bash
streamlit run frontend/streamlit_app.py
```

## 🧠 System Agents

A detailed guide strictly dedicated to mapping our Agents and the LangGraph workflow can be found in [AGENTS.md](AGENTS.md).

## 📄 License

MIT
