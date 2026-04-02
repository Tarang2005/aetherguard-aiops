"""
agents/supervisor.py

Supervisor (Orchestrator) agent for AetherGuard.
- Builds and runs the LangGraph multi-agent graph
- Routes between agents based on state
- Enforces human-in-the-loop approval gate
- Guards against infinite loops via iteration counter
- Entry point for the entire AetherGuard pipeline
"""

from __future__ import annotations

import time
from typing import Any, Literal, Optional

from langchain_core.messages import AIMessage, SystemMessage
from langgraph.graph import END, START, StateGraph
from langgraph.graph.state import CompiledStateGraph

from agents.anomaly_detector import AnomalyDetectorAgent
from agents.chaos_engineer import ChaosEngineerAgent
from agents.remediation_planner import RemediationPlannerAgent
from agents.root_cause_analyst import RootCauseAnalystAgent
from agents.state import (
    AetherGuardState,
    AgentName,
    ApprovalDecision,
    ApprovalGate,
    IncidentStatus,
    new_incident,
)
from core.simulator.aws_simulator import AWSSimulator
from core.simulator.network_simulator import NetworkSimulator


# ── Supervisor node ───────────────────────────────────────────────────────────

SUPERVISOR_SYSTEM = """You are AetherGuard's Supervisor — the orchestrating AI agent \
responsible for coordinating a team of specialist agents to detect, analyse, \
remediate, and validate cloud infrastructure incidents.

You ensure:
- Agents run in the correct order
- High-risk actions wait for human approval
- The system never loops infinitely
- Every action is logged for audit
"""


def _supervisor_decision(state: AetherGuardState) -> str:
    """
    LangGraph conditional edge function.
    Returns the name of the next node to route to,
    or END if the incident is resolved/dismissed.
    """
    # Hard stop: iteration limit
    if state.iteration_count >= state.max_iterations:
        return END

    # Terminal states
    if state.is_terminal():
        return END

    # Error state
    if state.error:
        return END

    # Route to next agent set by previous node
    if state.next_agent == AgentName.ANOMALY_DETECTOR:
        return "anomaly_detector"
    if state.next_agent == AgentName.ROOT_CAUSE_ANALYST:
        return "root_cause_analyst"
    if state.next_agent == AgentName.REMEDIATION_PLANNER:
        return "remediation_planner"
    if state.next_agent == AgentName.CHAOS_ENGINEER:
        return "chaos_engineer"

    # Pending approval — stay at supervisor until resolved
    if state.status == IncidentStatus.PENDING:
        return "supervisor"

    return END


# ── Graph builder ─────────────────────────────────────────────────────────────

def build_graph(
    anomaly_agent:     AnomalyDetectorAgent,
    rca_agent:         RootCauseAnalystAgent,
    remediation_agent: RemediationPlannerAgent,
    chaos_agent:       ChaosEngineerAgent,
) -> CompiledStateGraph:
    """
    Build and compile the AetherGuard LangGraph state machine.

    Graph topology:
        START
          → supervisor (entry + routing)
          → anomaly_detector
          → root_cause_analyst
          → remediation_planner
          → supervisor (approval gate / re-routing)
          → chaos_engineer (optional, post-remediation)
          → END
    """

    def supervisor_node(state: AetherGuardState) -> AetherGuardState:
        """
        Supervisor node — runs at entry and after each agent.
        Handles approval gate logic and iteration counting.
        """
        state.iteration_count += 1

        state.add_audit(
            agent=AgentName.SUPERVISOR,
            action=f"Supervisor tick #{state.iteration_count}",
            details={
                "status": state.status.value,
                "next_agent": state.next_agent.value if state.next_agent else None,
                "requires_approval": state.requires_human_approval,
            },
        )

        # First tick: kick off with anomaly detection
        if state.iteration_count == 1:
            state.next_agent = AgentName.ANOMALY_DETECTOR
            state.messages.append(AIMessage(
                content=(
                    f"Incident {state.incident_id} opened. "
                    f"Routing to AnomalyDetector. "
                    f"AWS records: {len(state.aws_metrics)}, "
                    f"Network records: {len(state.network_metrics)}."
                ),
                name=AgentName.SUPERVISOR.value,
            ))
            return state

        # Approval gate check
        if state.status == IncidentStatus.PENDING and state.approval_gate:
            gate = state.approval_gate
            elapsed = time.time() - time.mktime(
                time.strptime(gate.requested_at[:19], "%Y-%m-%dT%H:%M:%S")
            )

            if gate.decision == ApprovalDecision.APPROVED:
                state.set_status(IncidentStatus.REMEDIATING, AgentName.SUPERVISOR)
                state.next_agent = (
                    AgentName.CHAOS_ENGINEER
                    if state.run_chaos_after_remediation
                    else None
                )
                state.messages.append(AIMessage(
                    content="Human approval received. Proceeding with remediation.",
                    name=AgentName.SUPERVISOR.value,
                ))

            elif gate.decision == ApprovalDecision.DENIED:
                state.set_status(IncidentStatus.DISMISSED, AgentName.SUPERVISOR)
                state.next_agent = None
                state.messages.append(AIMessage(
                    content="Remediation denied by human reviewer. Incident dismissed.",
                    name=AgentName.SUPERVISOR.value,
                ))

            elif elapsed > gate.timeout_seconds and gate.timeout_seconds > 0:
                # Timeout — auto-dismiss
                gate.decision = ApprovalDecision.TIMEOUT
                gate.decided_by = "timeout"
                state.set_status(IncidentStatus.DISMISSED, AgentName.SUPERVISOR)
                state.next_agent = None
                state.messages.append(AIMessage(
                    content=(
                        f"Approval timed out after {gate.timeout_seconds}s. "
                        f"Incident dismissed — notify on-call team."
                    ),
                    name=AgentName.SUPERVISOR.value,
                ))

            else:
                # Still waiting
                state.messages.append(AIMessage(
                    content=f"Awaiting human approval... ({int(elapsed)}s elapsed).",
                    name=AgentName.SUPERVISOR.value,
                ))

        return state

    # ── Wire the graph ────────────────────────────────────────────────────────
    graph = StateGraph(AetherGuardState)

    # Add nodes
    graph.add_node("supervisor",          supervisor_node)
    graph.add_node("anomaly_detector",    anomaly_agent.run)
    graph.add_node("root_cause_analyst",  rca_agent.run)
    graph.add_node("remediation_planner", remediation_agent.run)
    graph.add_node("chaos_engineer",      chaos_agent.run)

    # Entry point
    graph.add_edge(START, "supervisor")

    # Supervisor routes conditionally
    graph.add_conditional_edges(
        "supervisor",
        _supervisor_decision,
        {
            "anomaly_detector":    "anomaly_detector",
            "root_cause_analyst":  "root_cause_analyst",
            "remediation_planner": "remediation_planner",
            "chaos_engineer":      "chaos_engineer",
            "supervisor":          "supervisor",
            END:                   END,
        },
    )

    # All agents report back to supervisor
    graph.add_edge("anomaly_detector",    "supervisor")
    graph.add_edge("root_cause_analyst",  "supervisor")
    graph.add_edge("remediation_planner", "supervisor")
    graph.add_edge("chaos_engineer",      "supervisor")

    return graph.compile()


# ── Main Supervisor class ─────────────────────────────────────────────────────

class SupervisorAgent:
    """
    High-level interface to the AetherGuard multi-agent pipeline.

    Usage:
        supervisor = SupervisorAgent()

        # Warm up detectors on baseline data
        supervisor.warm_up(ticks=30)

        # Run a full incident cycle
        result = supervisor.run_incident(
            auto_remediate=False,
            run_chaos=True,
        )

        # Approve a pending remediation
        supervisor.approve(result)

        # Get current state summary
        print(result.summary_dict())
    """

    def __init__(
        self,
        aws_simulator:   Optional[AWSSimulator]   = None,
        network_simulator: Optional[NetworkSimulator] = None,
        anthropic_api_key: Optional[str] = None,
        auto_remediate: bool = False,
        run_chaos: bool = True,
        scenario_dir: str = "core/simulator/scenarios",
    ):
        self.aws_sim = aws_simulator or AWSSimulator()
        self.net_sim = network_simulator or NetworkSimulator()

        # Instantiate agents
        self.anomaly_agent = AnomalyDetectorAgent()
        self.rca_agent = RootCauseAnalystAgent()
        self.remediation_agent = RemediationPlannerAgent()
        self.chaos_agent = ChaosEngineerAgent(
            aws_simulator=self.aws_sim,
            network_simulator=self.net_sim,
            anomaly_detector_agent=self.anomaly_agent,
            scenario_dir=scenario_dir,
        )

        self.auto_remediate = auto_remediate
        self.run_chaos = run_chaos

        # Build the compiled graph
        self.graph: CompiledStateGraph = build_graph(
            anomaly_agent=self.anomaly_agent,
            rca_agent=self.rca_agent,
            remediation_agent=self.remediation_agent,
            chaos_agent=self.chaos_agent,
        )

    def warm_up(self, ticks: int = 30) -> None:
        """Feed baseline data to the anomaly detector before going live."""
        self.anomaly_agent.warm_up(self.aws_sim, self.net_sim, ticks=ticks)

    def run_incident(
        self,
        scenario: Optional[str] = None,
        auto_remediate: Optional[bool] = None,
        run_chaos: Optional[bool] = None,
        config: Optional[dict] = None,
    ) -> AetherGuardState:
        from agents.anomaly_detector import NETWORK_METRIC_WEIGHTS

    # Inject scenario if specified
        if scenario:
            try:
                self.aws_sim.load_scenario_by_name(scenario)
            except FileNotFoundError:
                pass

    # Feed 4 ticks of anomalous data directly into detector
    # so flap threshold is met before the agent runs
        for _ in range(4):
            for record in self.aws_sim.get_metrics():
                metric = record.get("metric")
                entity_id = record.get("instance_id")
                value = record.get("value")
                if metric and entity_id and value is not None:
                    self.anomaly_agent.detector.ingest(
                        entity_id, metric, float(value), {}
                )
            for record in self.net_sim.get_metrics():
                device_id = record.get("device_id")
                for m in NETWORK_METRIC_WEIGHTS:
                    v = record.get(m)
                    if device_id and v is not None:
                        self.anomaly_agent.detector.ingest(
                            device_id, m, float(v), {}
                        )

            # Collect metrics
            aws_metrics = self.aws_sim.get_metrics()
            net_metrics = self.net_sim.get_metrics()

    # Build initial state
        state = new_incident(
            aws_metrics=aws_metrics,
            network_metrics=net_metrics,
            active_scenario=scenario,
            auto_remediate=auto_remediate if auto_remediate is not None else self.auto_remediate,
            run_chaos=run_chaos if run_chaos is not None else self.run_chaos,
        )

    # Run the graph
        raw = self.graph.invoke(state, config=config or {})
        if isinstance(raw, dict):
            final_state = AetherGuardState(**raw)
        else:
            final_state = raw

    # Clean up scenario
        if scenario:
            self.aws_sim.clear_scenario()

        return final_state

    def approve(self, state: AetherGuardState, decided_by: str = "human") -> AetherGuardState:
        """
        Approve a pending remediation action.
        Call this from the approval API endpoint.
        """
        if state.approval_gate:
            from datetime import datetime, timezone
            state.approval_gate.decision = ApprovalDecision.APPROVED
            state.approval_gate.decided_by = decided_by
            state.approval_gate.decided_at = datetime.now(timezone.utc).isoformat()
        return state

    def deny(self, state: AetherGuardState, decided_by: str = "human", notes: str = "") -> AetherGuardState:
        """Deny a pending remediation action."""
        if state.approval_gate:
            from datetime import datetime, timezone
            state.approval_gate.decision = ApprovalDecision.DENIED
            state.approval_gate.decided_by = decided_by
            state.approval_gate.decided_at = datetime.now(timezone.utc).isoformat()
            state.approval_gate.notes = notes
        return state

    def get_graph_diagram(self) -> str:
        """Return a Mermaid diagram of the compiled graph (for docs)."""
        try:
            return self.graph.get_graph().draw_mermaid()
        except Exception:
            return "Mermaid diagram unavailable."


# ── Quick demo ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import json

    print("=== AetherGuard Supervisor Demo ===\n")

    supervisor = SupervisorAgent(auto_remediate=True, run_chaos=True)

    print("Warming up anomaly detector (30 ticks)...")
    supervisor.warm_up(ticks=30)

    print("\nRunning incident with cpu_spike scenario...\n")
    result = supervisor.run_incident(scenario="cpu_spike")

    print(f"\n{'='*60}")
    print(f"INCIDENT COMPLETE")
    print(f"{'='*60}")
    print(json.dumps(result.summary_dict(), indent=2))

    print(f"\n--- Agent Conversation ---")
    for msg in result.messages:
        name = getattr(msg, "name", "system")
        content = msg.content[:300].replace("\n", " ")
        print(f"[{name}] {content}")

    print(f"\n--- Audit Log ({len(result.audit_log)} entries) ---")
    for entry in result.audit_log:
        status = "✓" if entry.success else "✗"
        print(f"  {status} [{entry.agent.value}] {entry.action}")

    if result.chaos_results:
        exp = result.chaos_results[-1]
        print(f"\n--- Resilience Score: {exp.resilience_score}/100 ---")
        for obs in exp.observations:
            print(f"  • {obs}")

    print("\n AetherGuard pipeline ready.")