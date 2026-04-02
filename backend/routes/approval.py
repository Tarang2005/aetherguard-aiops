"""
backend/routes/approval.py

Human-in-the-loop approval endpoints.
Called by the Streamlit dashboard approve/deny buttons.
"""

from __future__ import annotations

from fastapi import APIRouter
from pydantic import BaseModel

from backend.dependencies import get_incident, update_incident

router = APIRouter()


class ApprovalRequest(BaseModel):
    decided_by: str = "human"
    notes:      str = ""


@router.post("/{incident_id}/approve")
async def approve_remediation(incident_id: str, request: ApprovalRequest):
    """Approve the pending remediation action for an incident."""
    from agents.state import ApprovalDecision
    from datetime import datetime, timezone

    state = get_incident(incident_id)

    if not state.approval_gate:
        return {"error": "No approval gate found for this incident."}
    if state.approval_gate.decision is not None:
        return {"error": f"Already decided: {state.approval_gate.decision.value}"}

    state.approval_gate.decision = ApprovalDecision.APPROVED
    state.approval_gate.decided_by = request.decided_by
    state.approval_gate.decided_at = datetime.now(timezone.utc).isoformat()
    state.approval_gate.notes = request.notes
    update_incident(state)

    return {
        "incident_id": incident_id,
        "decision": "approved",
        "decided_by": request.decided_by,
        "message": "Remediation approved. Supervisor will proceed.",
    }


@router.post("/{incident_id}/deny")
async def deny_remediation(incident_id: str, request: ApprovalRequest):
    """Deny the pending remediation action for an incident."""
    from agents.state import ApprovalDecision
    from datetime import datetime, timezone

    state = get_incident(incident_id)

    if not state.approval_gate:
        return {"error": "No approval gate found for this incident."}
    if state.approval_gate.decision is not None:
        return {"error": f"Already decided: {state.approval_gate.decision.value}"}

    state.approval_gate.decision = ApprovalDecision.DENIED
    state.approval_gate.decided_by = request.decided_by
    state.approval_gate.decided_at = datetime.now(timezone.utc).isoformat()
    state.approval_gate.notes = request.notes
    update_incident(state)

    return {
        "incident_id": incident_id,
        "decision": "denied",
        "decided_by": request.decided_by,
        "notes": request.notes,
    }


@router.get("/{incident_id}/status")
async def approval_status(incident_id: str):
    """Get the current approval gate status for an incident."""
    state = get_incident(incident_id)
    if not state.approval_gate:
        return {"has_gate": False}
    gate = state.approval_gate
    return {
        "has_gate": True,
        "gate_id": gate.gate_id,
        "requested_at": gate.requested_at,
        "decided_at": gate.decided_at,
        "decision": gate.decision.value if gate.decision else None,
        "decided_by": gate.decided_by,
        "timeout_seconds": gate.timeout_seconds,
        "notes": gate.notes,
    }