"""
backend/routes/agents.py

Agent endpoints — trigger incident runs, get agent status.
"""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, BackgroundTasks, Depends
from pydantic import BaseModel

from agents.state import AetherGuardState, new_incident
from agents.supervisor import SupervisorAgent
from backend.dependencies import get_supervisor, store_incident

router = APIRouter()


class RunIncidentRequest(BaseModel):
    scenario:       Optional[str] = None
    auto_remediate: Optional[bool] = None
    run_chaos:      Optional[bool] = None


class RunIncidentResponse(BaseModel):
    incident_id: str
    status:      str
    message:     str


@router.post("/run", response_model=RunIncidentResponse)
async def run_incident(
    request: RunIncidentRequest,
    background_tasks: BackgroundTasks,
    supervisor: SupervisorAgent = Depends(get_supervisor),
):
    """
    Trigger a full incident pipeline.
    Returns immediately — pipeline runs in the background.
    Check the Incidents page after 30-60s for results.
    """
    # Create placeholder incident and return immediately
    placeholder = new_incident(active_scenario=request.scenario)
    store_incident(placeholder)
    incident_id = placeholder.incident_id

    def _run():
        result = supervisor.run_incident(
            scenario=request.scenario,
            auto_remediate=request.auto_remediate,
            run_chaos=request.run_chaos,
        )
        # LangGraph returns a dict — convert back to AetherGuardState
        if isinstance(result, dict):
            result = AetherGuardState(**result)
        # Keep the same incident_id so dashboard can find it
        result.incident_id = incident_id
        store_incident(result)

    background_tasks.add_task(_run)

    return RunIncidentResponse(
        incident_id=incident_id,
        status="investigating",
        message=f"Incident {incident_id} started — check Incidents page in ~30s.",
    )


@router.get("/scenarios")
async def list_scenarios():
    """List available chaos scenarios."""
    from agents.chaos_engineer import SCENARIO_CATALOGUE
    return {
        "scenarios": [
            {
                "name": name,
                "target_service": info["target_service"],
                "source": info["source"].value,
            }
            for name, info in SCENARIO_CATALOGUE.items()
        ]
    }


@router.get("/status")
async def agent_status(supervisor: SupervisorAgent = Depends(get_supervisor)):
    """Return current agent system status."""
    return {
        "status": "ready",
        "detector": supervisor.anomaly_agent.detector.stats(),
        "auto_remediate": supervisor.auto_remediate,
        "run_chaos": supervisor.run_chaos,
    }