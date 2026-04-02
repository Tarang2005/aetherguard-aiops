"""
backend/routes/dashboard.py

Dashboard endpoints — metrics snapshots, incident list, health summaries.
These are the endpoints Streamlit polls to render its charts.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends

from agents.supervisor import SupervisorAgent
from core.simulator.aws_simulator import AWSSimulator
from core.simulator.network_simulator import NetworkSimulator
from backend.dependencies import (
    get_all_incidents,
    get_aws_simulator,
    get_network_simulator,
    get_supervisor,
)

router = APIRouter()


@router.get("/metrics/aws")
async def get_aws_metrics(aws_sim: AWSSimulator = Depends(get_aws_simulator)):
    """Latest AWS CloudWatch-style metrics snapshot."""
    return {"metrics": aws_sim.get_metrics(), "summary": aws_sim.get_summary()}


@router.get("/metrics/network")
async def get_network_metrics(net_sim: NetworkSimulator = Depends(get_network_simulator)):
    """Latest DNAC-style network health snapshot."""
    return {
        "metrics": net_sim.get_metrics(),
        "health_summary": net_sim.get_health_summary(),
    }


@router.get("/incidents")
async def list_incidents():
    """List all incidents with their summary dicts."""
    incidents = get_all_incidents()
    return {
        "total": len(incidents),
        "incidents": [i.summary_dict() for i in incidents],
    }


@router.get("/incidents/{incident_id}")
async def get_incident_detail(incident_id: str):
    """Full detail for a single incident."""
    from backend.dependencies import get_incident
    state = get_incident(incident_id)
    return {
        "summary": state.summary_dict(),
        "anomalies": [a.dict() for a in state.anomalies],
        "root_cause": state.root_cause.dict() if state.root_cause else None,
        "remediation_plan": state.remediation_plan.dict() if state.remediation_plan else None,
        "chaos_results": [c.dict() for c in state.chaos_results],
        "audit_log": [e.dict() for e in state.audit_log],
        "messages": [
            {"agent": getattr(m, "name", "system"), "content": m.content}
            for m in state.messages
        ],
    }


@router.get("/resilience")
async def get_resilience_scores():
    """Resilience scores from all chaos experiments across all incidents."""
    incidents = get_all_incidents()
    scores = []
    for inc in incidents:
        for exp in inc.chaos_results:
            scores.append({
                "incident_id":    inc.incident_id,
                "experiment_id":  exp.experiment_id,
                "scenario":       exp.scenario_name,
                "target_service": exp.target_service,
                "resilience_score": exp.resilience_score,
                "detection_time": exp.detection_time_seconds,
                "recovery_time":  exp.recovery_time_seconds,
            })
    return {"experiments": scores, "total": len(scores)}


@router.get("/cost")
async def get_cost_summary():
    """Aggregate cost analysis across all incidents."""
    incidents = get_all_incidents()
    total_delta = 0.0
    total_savings = 0.0
    actions_taken = []

    for inc in incidents:
        if inc.remediation_plan:
            delta = inc.remediation_plan.recommended.estimated_cost_delta_usd
            total_delta += delta
            if delta < 0:
                total_savings += abs(delta)
            actions_taken.append({
                "incident_id": inc.incident_id,
                "action": inc.remediation_plan.recommended.action.value,
                "cost_delta_usd": delta,
            })

    return {
        "total_cost_delta_usd_per_hour": round(total_delta, 4),
        "total_projected_savings_usd_monthly": round(total_savings * 730, 2),
        "actions": actions_taken,
    }