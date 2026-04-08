# AetherGuard Agent Architecture

AetherGuard utilizes a robust multi-agent orchestration framework built on **LangGraph**. The workflow cascades structurally from detection through verification, ensuring human oversight handles critical decisions.

## Agent Personas & Responsibilities

### 1. 🦸 Supervisor Agent (`supervisor.py`)
- **Role:** The Orchestrator. 
- **Function:** Manages state routing and builds the dynamic graph linking all distinct agents. Handles the ultimate decision tree (e.g. terminating the pipeline on an unrecoverable error, looping back for further context).
- **Core Feature:** Contains the **Approval Gate**. Deliberately halts the pipeline in a `PENDING` state to await dashboard user approval before executing high-risk plans.

### 2. 🕵️ Anomaly Detector Agent (`anomaly_detector.py`)
- **Role:** The Sentry.
- **Function:** Directly interfaces with the data streams (Simulated AWS / Network instances) passing the metrics through a `scikit-learn` Isolation Forest model. 
- **Output:** Emits anomaly triggers and metric snapshots precisely when statistical deviations surpass acceptable baseline thresholds.

### 3. 🧠 Root Cause Analyst Agent (`root_cause_analyst.py`)
- **Role:** The Detective.
- **Function:** Powered by LLMs (Claude), this agent assesses the data snapshot triggered by the Anomaly Detector. It evaluates topological dependencies to hypothesize the core fault point (e.g., separating an actual pod failure from simple upstream latency).
- **Output:** A structured JSON object containing a confidence score, likely root cause, and an actionable summary.

### 4. 👷 Remediation Planner Agent (`remediation_planner.py`)
- **Role:** The Architect.
- **Function:** Receives the structural RCA output and determines the optimal path forward. Distinctly programmed to be **cost-aware**—it weighs the financial impact of its fixes against theoretical downtime costs.
- **Output:** A detailed breakdown of remediation actions with estimated dollar changes, projected recovery timeline, and risk level.

### 5. 🌪️ Chaos Engineer Agent (`chaos_engineer.py`)
- **Role:** The Stress Tester.
- **Function:** Automatically deployed after a remediation plan has been effectively executed and approved. Its goal is to inject controlled faults (`cpu_spike`, `pod_crash`, etc.) matching the newly remediated vector to ensure the system is now resilient.
- **Output:** A quantified Resilience Score (0-100) visible on the Chaos Lab dashboard, guaranteeing confidence in the automated fix.

## 🔄 The Incident Flow (LangGraph Topology)

1. `START` -> **Supervisor** (Initialize Incident State)
2. **Supervisor** -> **Anomaly Detector** (Wait for statistical anomalies)
3. **Anomaly Detector** -> **Root Cause Analyst** (Analyze the anomaly data)
4. **Root Cause Analyst** -> **Remediation Planner** (Formulate a cost-aware fix)
5. **Remediation Planner** -> **Supervisor** (*Human-in-the-loop Approval Gate Pause*)
6. *Upon Approval...*
7. **Supervisor** -> **Chaos Engineer** (Verify system stability post-remediation)
8. **Chaos Engineer** -> `END` (Incident resolved)
