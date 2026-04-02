"""
agents/remediation_planner.py

RemediationPlanner agent for AetherGuard.
- Evaluates multiple remediation options for the detected incident
- Calculates AWS cost impact for each option
- Uses Claude to rank and recommend the best action
- Sets approval gate for high-risk actions (human-in-the-loop)
- Writes RemediationPlan into AetherGuardState
- Designed as a LangGraph node function
"""

from __future__ import annotations

import json
import time
from typing import Any, Optional

from langchain_anthropic import ChatAnthropic
from langchain_core.messages import AIMessage, HumanMessage, SystemMessage

from agents.state import (
    AetherGuardState,
    AgentName,
    ApprovalDecision,
    ApprovalGate,
    IncidentStatus,
    RemediationAction,
    RemediationOption,
    RemediationPlan,
    Severity,
)
from agents.prompts.remediation_prompt import (
    REMEDIATION_SYSTEM_PROMPT,
    build_remediation_user_prompt,
)
from core.simulator.cost_simulator import CostSimulator


# ── Risk classification ───────────────────────────────────────────────────────

# Actions that always require human approval regardless of severity
HIGH_RISK_ACTIONS = {
    RemediationAction.SCALE_UP,
    RemediationAction.ROLLBACK,
    RemediationAction.CLOSE_PORT,
    RemediationAction.THROTTLE_TRAFFIC,
}

# Actions that can be auto-approved if severity <= MEDIUM
AUTO_APPROVABLE_ACTIONS = {
    RemediationAction.NOTIFY_ONLY,
    RemediationAction.RESTART_POD,
    RemediationAction.SCALE_OUT,
}


# ── RemediationPlanner agent ──────────────────────────────────────────────────

class RemediationPlannerAgent:
    """
    LangGraph node agent that:
    1. Reads anomalies + RCA from state
    2. Generates candidate remediation options with cost estimates
    3. Calls Claude to rank and recommend the best option
    4. Sets approval gate if action is high-risk
    5. Writes RemediationPlan back to state

    Usage (standalone):
        agent = RemediationPlannerAgent()
        state = agent.run(state)

    Usage (LangGraph node):
        graph.add_node("remediation_planner", agent.run)
    """

    def __init__(
        self,
        model: str = "claude-sonnet-4-20250514",
        temperature: float = 0.1,
        approval_timeout_seconds: int = 300,
        cost_simulator: Optional[CostSimulator] = None,
    ):
        self.llm = ChatAnthropic(
            model=model,
            temperature=temperature,
            max_tokens=2048,
        )
        self.model_name = model
        self.approval_timeout = approval_timeout_seconds
        self.cost_sim = cost_simulator or CostSimulator()

    # ── Candidate generation ─────────────────────────────────────────────────

    def _build_candidates(self, state: AetherGuardState) -> list[dict[str, Any]]:
        """
        Build a list of candidate remediation options based on anomaly types.
        Each candidate is a dict that gets passed to the LLM for ranking.
        """
        metrics = {a.metric for a in state.anomalies}
        sources = {a.source.value for a in state.anomalies}
        severity = state.severity or Severity.MEDIUM

        candidates = []

        # High CPU / latency → scale options
        if any(m in metrics for m in ("cpu_utilization", "request_latency")):
            candidates.append({
                "action": RemediationAction.SCALE_OUT.value,
                "description": "Add 2 new instances to the Auto Scaling Group to distribute load.",
                "estimated_cost_delta_usd": self.cost_sim.scale_out_cost(instance_count=2),
                "estimated_recovery_seconds": 180,
                "risk_level": Severity.LOW.value,
                "requires_approval": False,
                "aws_hint": "aws autoscaling set-desired-capacity --auto-scaling-group-name aetherguard-asg --desired-capacity +2",
            })
            candidates.append({
                "action": RemediationAction.SCALE_UP.value,
                "description": "Upgrade api-server instances from m5.xlarge to m5.2xlarge.",
                "estimated_cost_delta_usd": self.cost_sim.scale_up_cost("m5.xlarge", "m5.2xlarge"),
                "estimated_recovery_seconds": 420,
                "risk_level": Severity.MEDIUM.value,
                "requires_approval": True,
                "aws_hint": "aws ec2 modify-instance-attribute (requires stop/start)",
            })

        # High memory / pod crash → restart or memory increase
        if any(m in metrics for m in ("memory_usage", "memory_load")):
            candidates.append({
                "action": RemediationAction.RESTART_POD.value,
                "description": "Restart the affected Kubernetes pod to clear memory leak.",
                "estimated_cost_delta_usd": 0.0,
                "estimated_recovery_seconds": 60,
                "risk_level": Severity.LOW.value,
                "requires_approval": False,
                "k8s_hint": "kubectl rollout restart deployment/ml-worker -n aetherguard",
            })
            candidates.append({
                "action": RemediationAction.INCREASE_MEMORY.value,
                "description": "Increase pod memory limit from 2Gi to 4Gi in the K8s manifest.",
                "estimated_cost_delta_usd": self.cost_sim.memory_increase_cost(from_gi=2, to_gi=4),
                "estimated_recovery_seconds": 120,
                "risk_level": Severity.MEDIUM.value,
                "requires_approval": True,
                "k8s_hint": "kubectl set resources deployment/ml-worker --limits=memory=4Gi",
            })

        # High error rate → rollback
        if "error_rate" in metrics:
            candidates.append({
                "action": RemediationAction.ROLLBACK.value,
                "description": "Roll back to the previous stable deployment revision.",
                "estimated_cost_delta_usd": 0.0,
                "estimated_recovery_seconds": 300,
                "risk_level": Severity.HIGH.value,
                "requires_approval": True,
                "k8s_hint": "kubectl rollout undo deployment/api-server -n aetherguard",
            })

        # Network anomalies → traffic throttling
        if "network" in sources and any(
            m in metrics for m in ("packet_loss", "link_utilization", "interface_errors")
        ):
            candidates.append({
                "action": RemediationAction.THROTTLE_TRAFFIC.value,
                "description": "Apply WAF rate-limiting rule to cap inbound requests at 1000 req/s.",
                "estimated_cost_delta_usd": self.cost_sim.waf_rule_cost(),
                "estimated_recovery_seconds": 30,
                "risk_level": Severity.MEDIUM.value,
                "requires_approval": True,
                "aws_hint": "aws wafv2 update-rule-group (rate-based rule)",
            })

        # Security anomaly → zero-trust port closure
        if "port_exposure" in (state.active_scenario or ""):
            candidates.append({
                "action": RemediationAction.CLOSE_PORT.value,
                "description": "Auto-revoke the exposed security group rule via Lambda.",
                "estimated_cost_delta_usd": 0.0,
                "estimated_recovery_seconds": 15,
                "risk_level": Severity.HIGH.value,
                "requires_approval": True,
                "aws_hint": "aws ec2 revoke-security-group-ingress (Lambda-triggered)",
                "terraform_hint": "Update security_group_rules in terraform/modules/agent_iam",
            })

        # Always include notify-only as a safe fallback
        candidates.append({
            "action": RemediationAction.NOTIFY_ONLY.value,
            "description": "Send alert to on-call team via PagerDuty/Slack. No automated action.",
            "estimated_cost_delta_usd": 0.0,
            "estimated_recovery_seconds": 900,
            "risk_level": Severity.LOW.value,
            "requires_approval": False,
            "aws_hint": "aws sns publish to on-call topic",
        })

        return candidates

    # ── LLM ranking ──────────────────────────────────────────────────────────

    def _rank_with_llm(
        self,
        state: AetherGuardState,
        candidates: list[dict],
    ) -> tuple[dict, list[dict], str]:
        """
        Call Claude to rank candidates and return:
            (recommended, alternatives, rationale)
        """
        user_prompt = build_remediation_user_prompt(
            incident_id=state.incident_id,
            severity=state.severity.value if state.severity else "medium",
            rca_summary=state.root_cause.summary if state.root_cause else "No RCA available.",
            probable_cause=state.root_cause.probable_cause if state.root_cause else "Unknown.",
            candidates=candidates,
        )

        messages = [
            SystemMessage(content=REMEDIATION_SYSTEM_PROMPT),
            HumanMessage(content=user_prompt),
        ]

        response = self.llm.invoke(messages)
        raw = response.content.strip()

        try:
            if raw.startswith("```"):
                raw = "\n".join(raw.split("\n")[1:-1])
            data = json.loads(raw)
            recommended_action = data.get("recommended_action")
            rationale = data.get("rationale", "No rationale provided.")

            # Find recommended in candidates list
            recommended = next(
                (c for c in candidates if c["action"] == recommended_action),
                candidates[0],
            )
            alternatives = [c for c in candidates if c["action"] != recommended_action]
            return recommended, alternatives, rationale

        except (json.JSONDecodeError, StopIteration):
            # Fallback: pick lowest risk, lowest cost
            sorted_candidates = sorted(
                candidates,
                key=lambda c: (
                    ["low", "medium", "high", "critical"].index(c["risk_level"]),
                    c["estimated_cost_delta_usd"],
                ),
            )
            return sorted_candidates[0], sorted_candidates[1:], "Fallback: lowest-risk option selected."

    # ── Approval gate logic ──────────────────────────────────────────────────

    def _needs_approval(
        self,
        recommended: RemediationOption,
        state: AetherGuardState,
    ) -> bool:
        """Determine if this action needs human approval."""
        if state.auto_remediate and recommended.action in AUTO_APPROVABLE_ACTIONS:
            return False
        if recommended.action in HIGH_RISK_ACTIONS:
            return True
        if recommended.risk_level in (Severity.HIGH, Severity.CRITICAL):
            return True
        return recommended.requires_approval

    # ── Main node function ───────────────────────────────────────────────────

    def run(self, state: AetherGuardState) -> AetherGuardState:
        """LangGraph node entry point."""
        start = time.time()

        state.add_audit(
            agent=AgentName.REMEDIATION_PLANNER,
            action="Starting remediation planning",
            details={"anomaly_count": len(state.anomalies)},
        )

        if not state.anomalies:
            state.add_audit(
                agent=AgentName.REMEDIATION_PLANNER,
                action="No anomalies — skipping remediation",
                success=False,
            )
            state.next_agent = None
            return state

        # Build candidates
        candidates = self._build_candidates(state)

        # Rank with LLM
        try:
            rec_dict, alt_dicts, rationale = self._rank_with_llm(state, candidates)
        except Exception as e:
            state.error = f"Remediation LLM failed: {e}"
            state.add_audit(
                agent=AgentName.REMEDIATION_PLANNER,
                action="LLM ranking failed — using fallback",
                details={"error": str(e)},
                success=False,
            )
            rec_dict = candidates[0]
            alt_dicts = candidates[1:]
            rationale = "LLM unavailable — lowest-risk fallback selected."

        # Build RemediationOption objects
        def _to_option(d: dict) -> RemediationOption:
            return RemediationOption(
                action=RemediationAction(d["action"]),
                description=d["description"],
                estimated_cost_delta_usd=d["estimated_cost_delta_usd"],
                estimated_recovery_seconds=d["estimated_recovery_seconds"],
                risk_level=Severity(d["risk_level"]),
                requires_approval=d.get("requires_approval", True),
                confidence=d.get("confidence", 0.7),
                terraform_hint=d.get("terraform_hint"),
                k8s_hint=d.get("k8s_hint"),
                aws_hint=d.get("aws_hint"),
            )

        recommended = _to_option(rec_dict)
        alternatives = [_to_option(d) for d in alt_dicts]

        # Cost analysis
        cost_analysis = self.cost_sim.analyse(
            recommended=rec_dict,
            alternatives=alt_dicts,
        )

        # Build plan
        plan = RemediationPlan(
            recommended=recommended,
            alternatives=alternatives,
            rationale=rationale,
            cost_analysis=cost_analysis,
            total_options_evaluated=len(candidates),
        )

        state.remediation_plan = plan

        # Approval gate
        needs_approval = self._needs_approval(recommended, state)
        state.requires_human_approval = needs_approval

        if needs_approval:
            state.approval_gate = ApprovalGate(
                timeout_seconds=self.approval_timeout,
            )
            state.set_status(IncidentStatus.PENDING, AgentName.REMEDIATION_PLANNER)
            state.next_agent = None  # Supervisor waits for approval webhook
        else:
            # Auto-approve low-risk actions
            state.approval_gate = ApprovalGate(timeout_seconds=0)
            state.approval_gate.decision = ApprovalDecision.AUTO
            state.approval_gate.decided_by = "auto"
            state.set_status(IncidentStatus.REMEDIATING, AgentName.REMEDIATION_PLANNER)
            state.next_agent = AgentName.CHAOS_ENGINEER if state.run_chaos_after_remediation else None

        elapsed = round(time.time() - start, 3)

        state.messages.append(AIMessage(
            content=(
                f"**Remediation Plan** [{elapsed}s | {len(candidates)} options evaluated]\n\n"
                f"**Recommended:** `{recommended.action.value}` "
                f"(risk={recommended.risk_level.value}, "
                f"cost_delta=${recommended.estimated_cost_delta_usd:+.2f}/hr, "
                f"recovery~{recommended.estimated_recovery_seconds}s)\n\n"
                f"**Rationale:** {rationale}\n\n"
                f"**Approval required:** {'YES — awaiting human decision' if needs_approval else 'NO — auto-approved'}"
            ),
            name=AgentName.REMEDIATION_PLANNER.value,
        ))

        state.add_audit(
            agent=AgentName.REMEDIATION_PLANNER,
            action="Remediation plan generated",
            details={
                "plan_id": plan.plan_id,
                "recommended_action": recommended.action.value,
                "requires_approval": needs_approval,
                "cost_delta_usd": recommended.estimated_cost_delta_usd,
                "elapsed_seconds": elapsed,
            },
        )

        return state