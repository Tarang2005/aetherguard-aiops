"""
backend/routes/agents.py

Agent endpoints — trigger incident runs, get agent status.
"""

from __future__ import annotations

import asyncio
from typing import Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from pydantic import BaseModel

from agents.supervisor import SupervisorAgent
from backend.dependencies import (
    get_supervisor,
    store_incident,
)

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
    Trigger a full incident detection → RCA → remediation → chaos cycle.
    Runs in the background so the API returns immediately.
    """

    def _run():
        result = supervisor.run_incident(
            scenario=request.scenario,
            auto_remediate=request.auto_remediate,
            run_chaos=request.run_chaos,
        )
        store_incident(result)
        return result

    loop = asyncio.get_event_loop()
    result = await loop.run_in_executor(None, _run)

    return RunIncidentResponse(
        incident_id=result.incident_id,
        status=result.status.value,
        message=f"Incident {result.incident_id} completed with status: {result.status.value}",
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
    detector_stats = supervisor.anomaly_agent.detector.stats()
    return {
        "status": "ready",
        "detector": detector_stats,
        "auto_remediate": supervisor.auto_remediate,
        "run_chaos": supervisor.run_chaos,
    }