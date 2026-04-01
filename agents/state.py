"""
agents/state.py

Shared LangGraph state schema for AetherGuard.
This is the single source of truth passed between all agents in the graph.

Flow:
    Supervisor
        → AnomalyDetector   (populates anomalies)
        → RootCauseAnalyst  (populates root_cause)
        → RemediationPlanner(populates remediation_plan)
        → ChaosEngineer     (populates chaos_results)
        → Supervisor        (final decision + audit log)
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Annotated, Any, Optional
from pydantic import BaseModel, Field
from langgraph.graph.message import add_messages
from langchain_core.messages import BaseMessage


# ── Enums ────────────────────────────────────────────────────────────────────

class IncidentStatus(str, Enum):
    OPEN         = "open"           # Anomaly detected, investigation starting
    INVESTIGATING= "investigating"  # RCA agent working
    PENDING      = "pending"        # Awaiting human approval
    REMEDIATING  = "remediating"    # Remediation in progress
    CHAOS        = "chaos"          # Chaos engineer testing resilience
    RESOLVED     = "resolved"       # Fully resolved
    DISMISSED    = "dismissed"      # False positive, dismissed


class Severity(str, Enum):
    LOW      = "low"
    MEDIUM   = "medium"
    HIGH     = "high"
    CRITICAL = "critical"


class AnomalySource(str, Enum):
    AWS     = "aws"
    NETWORK = "network"
    BOTH    = "both"


class RemediationAction(str, Enum):
    SCALE_OUT         = "scale_out"          # Add more instances
    SCALE_UP          = "scale_up"           # Upgrade instance type
    RESTART_POD       = "restart_pod"        # Kill + restart K8s pod
    ROLLBACK          = "rollback"           # Revert last deployment
    CLOSE_PORT        = "close_port"         # Zero-trust: revoke SG rule
    THROTTLE_TRAFFIC  = "throttle_traffic"   # WAF rate limit
    INCREASE_MEMORY   = "increase_memory"    # Raise pod memory limits
    NOTIFY_ONLY       = "notify_only"        # Low-risk: alert only
    CUSTOM            = "custom"             # Agent-defined action


class ApprovalDecision(str, Enum):
    APPROVED = "approved"
    DENIED   = "denied"
    TIMEOUT  = "timeout"     # No human response within window
    AUTO     = "auto"        # Low-risk, auto-approved by supervisor


class AgentName(str, Enum):
    SUPERVISOR          = "supervisor"
    ANOMALY_DETECTOR    = "anomaly_detector"
    ROOT_CAUSE_ANALYST  = "root_cause_analyst"
    REMEDIATION_PLANNER = "remediation_planner"
    CHAOS_ENGINEER      = "chaos_engineer"


# ── Sub-models ───────────────────────────────────────────────────────────────

class AnomalyRecord(BaseModel):
    """A single detected anomaly from the AnomalyDetector agent."""
    anomaly_id:       str     = Field(default_factory=lambda: f"ANO-{uuid.uuid4().hex[:8].upper()}")
    source:           AnomalySource
    metric:           str                        # e.g. "cpu_utilization"
    entity_id:        str                        # instance_id or device_id
    entity_type:      str                        # "ec2", "switch", "wan_link", etc.
    site:             Optional[str] = None       # network: site name
    service:          Optional[str] = None       # aws: service name
    observed_value:   float
    expected_range:   tuple[float, float]        # (lower, upper) baseline bounds
    anomaly_score:    float                      # Isolation Forest score (0-1, higher = more anomalous)
    severity:         Severity
    detected_at:      str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    is_flapping:      bool = False               # Anti-flapping: seen < 2 consecutive ticks
    raw_metrics:      dict[str, Any] = Field(default_factory=dict)


class RootCauseAnalysis(BaseModel):
    """Output from the RootCauseAnalyst agent."""
    rca_id:           str  = Field(default_factory=lambda: f"RCA-{uuid.uuid4().hex[:8].upper()}")
    summary:          str                        # 1-2 sentence plain English summary
    detailed_analysis:str                        # Full LLM-generated explanation
    probable_cause:   str                        # Single most likely cause
    contributing_factors: list[str] = Field(default_factory=list)
    affected_services:list[str] = Field(default_factory=list)
    similar_incidents:list[str] = Field(default_factory=list)  # IDs from memory
    confidence:       float = 0.0               # 0.0 – 1.0
    generated_at:     str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    llm_model:        str = "claude-sonnet-4-20250514"


class RemediationOption(BaseModel):
    """A single remediation option evaluated by the RemediationPlanner."""
    action:           RemediationAction
    description:      str
    estimated_cost_delta_usd: float             # +ve = more expensive, -ve = savings
    estimated_recovery_seconds: int
    risk_level:       Severity                  # Risk of the action itself
    requires_approval:bool = True
    confidence:       float = 0.0               # How confident the planner is
    terraform_hint:   Optional[str] = None      # e.g. "scale eks node group"
    k8s_hint:         Optional[str] = None      # e.g. "kubectl rollout restart"
    aws_hint:         Optional[str] = None      # e.g. "modify-instance-attribute"


class RemediationPlan(BaseModel):
    """Output from the RemediationPlanner agent."""
    plan_id:          str  = Field(default_factory=lambda: f"PLAN-{uuid.uuid4().hex[:8].upper()}")
    recommended:      RemediationOption          # Best option
    alternatives:     list[RemediationOption] = Field(default_factory=list)
    rationale:        str                        # Why this action was chosen
    cost_analysis:    dict[str, Any] = Field(default_factory=dict)
    total_options_evaluated: int = 0
    generated_at:     str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


class ApprovalGate(BaseModel):
    """Human-in-the-loop approval record."""
    gate_id:          str  = Field(default_factory=lambda: f"GATE-{uuid.uuid4().hex[:8].upper()}")
    requested_at:     str  = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    decided_at:       Optional[str] = None
    decision:         Optional[ApprovalDecision] = None
    decided_by:       Optional[str] = None      # "human" | "auto" | "timeout"
    timeout_seconds:  int  = 300                # 5 min default
    notes:            Optional[str] = None


class ChaosExperiment(BaseModel):
    """A single chaos experiment run by the ChaosEngineer agent."""
    experiment_id:    str  = Field(default_factory=lambda: f"CHAOS-{uuid.uuid4().hex[:8].upper()}")
    scenario_name:    str
    target_service:   str
    injected_at:      str  = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    resolved_at:      Optional[str] = None
    detection_time_seconds:  Optional[float] = None   # How fast anomaly detector caught it
    recovery_time_seconds:   Optional[float] = None   # How fast system recovered
    remediation_triggered:   bool = False
    resilience_score:        Optional[float] = None   # 0-100
    observations:     list[str] = Field(default_factory=list)


class AuditEntry(BaseModel):
    """One entry in the incident audit trail."""
    entry_id:     str = Field(default_factory=lambda: f"AUD-{uuid.uuid4().hex[:8].upper()}")
    timestamp:    str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    agent:        AgentName
    action:       str                            # Short description of what happened
    details:      dict[str, Any] = Field(default_factory=dict)
    success:      bool = True


class CostSnapshot(BaseModel):
    """Point-in-time cost tracking for the incident lifecycle."""
    snapshot_id:      str = Field(default_factory=lambda: f"COST-{uuid.uuid4().hex[:8].upper()}")
    timestamp:        str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    hourly_rate_usd:  float = 0.0
    incident_cost_usd:float = 0.0               # Cumulative cost since incident opened
    projected_savings_usd: float = 0.0          # From recommended remediation
    instance_breakdown: dict[str, float] = Field(default_factory=dict)


# ── Main state schema ────────────────────────────────────────────────────────

class AetherGuardState(BaseModel):
    """
    Shared LangGraph state for the AetherGuard multi-agent graph.

    Every agent reads from and writes to this state.
    LangGraph passes it between nodes automatically.

    Sections:
        1. Incident identity
        2. Raw inputs (metrics snapshots)
        3. Agent outputs (populated as graph progresses)
        4. Workflow control (routing, approval, next steps)
        5. Conversation history (LLM message thread)
        6. Audit trail
    """

    # ── 1. Incident identity ─────────────────────────────────────────────────
    incident_id: str = Field(
        default_factory=lambda: f"INC-{uuid.uuid4().hex[:8].upper()}",
        description="Unique incident identifier"
    )
    status: IncidentStatus = Field(
        default=IncidentStatus.OPEN,
        description="Current lifecycle status of the incident"
    )
    severity: Optional[Severity] = Field(
        default=None,
        description="Overall incident severity — set by AnomalyDetector, may be upgraded"
    )
    created_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    updated_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    title: Optional[str] = Field(
        default=None,
        description="Short human-readable incident title — set by RCA agent"
    )

    # ── 2. Raw metric inputs ─────────────────────────────────────────────────
    aws_metrics: list[dict[str, Any]] = Field(
        default_factory=list,
        description="Latest AWS CloudWatch-style metrics snapshot"
    )
    network_metrics: list[dict[str, Any]] = Field(
        default_factory=list,
        description="Latest DNAC-style network health metrics snapshot"
    )
    active_scenario: Optional[str] = Field(
        default=None,
        description="Name of the active chaos scenario, if any"
    )

    # ── 3. Agent outputs ─────────────────────────────────────────────────────
    anomalies: list[AnomalyRecord] = Field(
        default_factory=list,
        description="Anomalies detected by AnomalyDetector agent"
    )
    root_cause: Optional[RootCauseAnalysis] = Field(
        default=None,
        description="RCA output from RootCauseAnalyst agent"
    )
    remediation_plan: Optional[RemediationPlan] = Field(
        default=None,
        description="Remediation plan from RemediationPlanner agent"
    )
    chaos_results: list[ChaosExperiment] = Field(
        default_factory=list,
        description="Chaos experiments run by ChaosEngineer agent"
    )
    cost_snapshot: Optional[CostSnapshot] = Field(
        default=None,
        description="Cost tracking for this incident"
    )

    # ── 4. Workflow control ──────────────────────────────────────────────────
    next_agent: Optional[AgentName] = Field(
        default=None,
        description="Which agent the supervisor routes to next"
    )
    approval_gate: Optional[ApprovalGate] = Field(
        default=None,
        description="Human-in-the-loop approval record — set when high-risk action needed"
    )
    requires_human_approval: bool = Field(
        default=False,
        description="Flag set by RemediationPlanner when action risk >= HIGH"
    )
    auto_remediate: bool = Field(
        default=False,
        description="If True, supervisor skips approval gate for LOW/MEDIUM risk actions"
    )
    run_chaos_after_remediation: bool = Field(
        default=False,
        description="If True, ChaosEngineer validates recovery after remediation"
    )
    error: Optional[str] = Field(
        default=None,
        description="Set if any agent encounters an unrecoverable error"
    )
    iteration_count: int = Field(
        default=0,
        description="Number of supervisor loops — guards against infinite cycles"
    )
    max_iterations: int = Field(
        default=10,
        description="Hard limit on supervisor loops"
    )

    # ── 5. Conversation history (LangGraph message accumulator) ──────────────
    messages: Annotated[list[BaseMessage], add_messages] = Field(
        default_factory=list,
        description="Full agent conversation thread — accumulated via LangGraph add_messages"
    )

    # ── 6. Audit trail ───────────────────────────────────────────────────────
    audit_log: list[AuditEntry] = Field(
        default_factory=list,
        description="Append-only audit trail of every agent action"
    )

    # ── Helpers ──────────────────────────────────────────────────────────────

    def touch(self) -> None:
        """Update the updated_at timestamp."""
        self.updated_at = datetime.now(timezone.utc).isoformat()

    def add_audit(
        self,
        agent: AgentName,
        action: str,
        details: dict[str, Any] | None = None,
        success: bool = True,
    ) -> None:
        """Append an entry to the audit log."""
        self.audit_log.append(AuditEntry(
            agent=agent,
            action=action,
            details=details or {},
            success=success,
        ))
        self.touch()

    def set_status(self, status: IncidentStatus, agent: AgentName) -> None:
        """Transition incident status and log it."""
        old = self.status
        self.status = status
        self.add_audit(
            agent=agent,
            action=f"Status transition: {old.value} → {status.value}",
        )

    def highest_anomaly_severity(self) -> Optional[Severity]:
        """Return the highest severity across all detected anomalies."""
        if not self.anomalies:
            return None
        order = [Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        return max(self.anomalies, key=lambda a: order.index(a.severity)).severity

    def is_terminal(self) -> bool:
        """True if the incident has reached a terminal state."""
        return self.status in (IncidentStatus.RESOLVED, IncidentStatus.DISMISSED)

    def summary_dict(self) -> dict[str, Any]:
        """Compact summary for dashboard / logging."""
        return {
            "incident_id":   self.incident_id,
            "status":        self.status.value,
            "severity":      self.severity.value if self.severity else None,
            "title":         self.title,
            "anomaly_count": len(self.anomalies),
            "has_rca":       self.root_cause is not None,
            "has_plan":      self.remediation_plan is not None,
            "chaos_runs":    len(self.chaos_results),
            "audit_entries": len(self.audit_log),
            "created_at":    self.created_at,
            "updated_at":    self.updated_at,
        }

    class Config:
        arbitrary_types_allowed = True  # needed for BaseMessage


# ── Factory ──────────────────────────────────────────────────────────────────

def new_incident(
    aws_metrics: list[dict] | None = None,
    network_metrics: list[dict] | None = None,
    active_scenario: str | None = None,
    auto_remediate: bool = False,
    run_chaos: bool = False,
) -> AetherGuardState:
    """
    Factory function — create a fresh incident state.

    Usage:
        state = new_incident(
            aws_metrics=sim.get_metrics(),
            network_metrics=net_sim.get_metrics(),
            active_scenario="cpu_spike",
            auto_remediate=False,
            run_chaos=True,
        )
    """
    return AetherGuardState(
        aws_metrics=aws_metrics or [],
        network_metrics=network_metrics or [],
        active_scenario=active_scenario,
        auto_remediate=auto_remediate,
        run_chaos_after_remediation=run_chaos,
    )


# ── Quick demo ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import json

    print("=== AetherGuardState Demo ===\n")

    # Create a fresh incident
    state = new_incident(
        active_scenario="cpu_spike",
        auto_remediate=False,
        run_chaos=True,
    )
    print(f"New incident: {state.incident_id}")
    print(f"Status: {state.status.value}")

    # Simulate anomaly detector populating anomalies
    state.anomalies.append(AnomalyRecord(
        source=AnomalySource.AWS,
        metric="cpu_utilization",
        entity_id="i-0aetherguard01",
        entity_type="ec2",
        service="api-server",
        observed_value=93.4,
        expected_range=(20.0, 60.0),
        anomaly_score=0.91,
        severity=Severity.HIGH,
    ))
    state.severity = state.highest_anomaly_severity()
    state.set_status(IncidentStatus.INVESTIGATING, AgentName.ANOMALY_DETECTOR)

    # Simulate approval gate
    state.requires_human_approval = True
    state.approval_gate = ApprovalGate(timeout_seconds=300)

    # Audit log entry
    state.add_audit(
        agent=AgentName.SUPERVISOR,
        action="Routed to RootCauseAnalyst",
        details={"anomaly_count": len(state.anomalies)},
    )

    print(f"\nSummary:")
    print(json.dumps(state.summary_dict(), indent=2))
    print(f"\nAudit log ({len(state.audit_log)} entries):")
    for entry in state.audit_log:
        print(f"  [{entry.timestamp}] {entry.agent.value}: {entry.action}")

    print("\n AetherGuardState ready.")