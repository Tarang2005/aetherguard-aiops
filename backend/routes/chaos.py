"""
backend/routes/chaos.py

Chaos engineering endpoints — inject scenarios, get experiment results.
"""

from __future__ import annotations

from typing import Optional

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from agents.supervisor import SupervisorAgent
from backend.dependencies import get_supervisor, store_incident
import asyncio

router = APIRouter()


class ChaosRunRequest(BaseModel):
    scenario:  str
    run_chaos: bool = True


@router.post("/inject")
async def inject_chaos(
    request: ChaosRunRequest,
    supervisor: SupervisorAgent = Depends(get_supervisor),
):
    """Inject a specific chaos scenario and run the full pipeline."""

    def _run():
        return supervisor.run_incident(
            scenario=request.scenario,
            run_chaos=request.run_chaos,
        )

    loop = asyncio.get_event_loop()
    result = await loop.run_in_executor(None, _run)
    store_incident(result)

    chaos_summary = None
    if result.chaos_results:
        exp = result.chaos_results[-1]
        chaos_summary = {
            "experiment_id":   exp.experiment_id,
            "scenario":        exp.scenario_name,
            "resilience_score": exp.resilience_score,
            "detection_time":  exp.detection_time_seconds,
            "recovery_time":   exp.recovery_time_seconds,
            "observations":    exp.observations,
        }

    return {
        "incident_id":   result.incident_id,
        "status":        result.status.value,
        "chaos_summary": chaos_summary,
    }


@router.get("/experiments")
async def list_experiments():
    """List all chaos experiments across all incidents."""
    from backend.dependencies import get_all_incidents
    incidents = get_all_incidents()
    experiments = []
    for inc in incidents:
        for exp in inc.chaos_results:
            experiments.append({
                "incident_id":    inc.incident_id,
                "experiment_id":  exp.experiment_id,
                "scenario":       exp.scenario_name,
                "target_service": exp.target_service,
                "resilience_score": exp.resilience_score,
                "detection_time": exp.detection_time_seconds,
                "recovery_time":  exp.recovery_time_seconds,
                "injected_at":    exp.injected_at,
            })
    return {"experiments": experiments, "total": len(experiments)}