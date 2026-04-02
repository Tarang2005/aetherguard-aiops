"""
backend/dependencies.py

Shared dependency injection for FastAPI routes.
Supervisor and simulators are initialised once at startup
and injected into routes via FastAPI's Depends() system.
"""

from __future__ import annotations

from typing import Optional

from fastapi import HTTPException

from agents.supervisor import SupervisorAgent
from agents.state import AetherGuardState
from core.simulator.aws_simulator import AWSSimulator
from core.simulator.network_simulator import NetworkSimulator

# ── Module-level singletons (set during lifespan startup) ────────────────────

_supervisor:   Optional[SupervisorAgent]   = None
_aws_sim:      Optional[AWSSimulator]      = None
_net_sim:      Optional[NetworkSimulator]  = None

# In-memory incident store  {incident_id: AetherGuardState}
_incidents: dict[str, AetherGuardState] = {}


# ── Setters (called from main.py lifespan) ───────────────────────────────────

def set_supervisor(supervisor: SupervisorAgent) -> None:
    global _supervisor
    _supervisor = supervisor


def set_simulators(aws_sim: AWSSimulator, net_sim: NetworkSimulator) -> None:
    global _aws_sim, _net_sim
    _aws_sim = aws_sim
    _net_sim = net_sim


# ── FastAPI dependency functions ──────────────────────────────────────────────

def get_supervisor() -> SupervisorAgent:
    if _supervisor is None:
        raise HTTPException(status_code=503, detail="Supervisor not initialised.")
    return _supervisor


def get_aws_simulator() -> AWSSimulator:
    if _aws_sim is None:
        raise HTTPException(status_code=503, detail="AWS simulator not initialised.")
    return _aws_sim


def get_network_simulator() -> NetworkSimulator:
    if _net_sim is None:
        raise HTTPException(status_code=503, detail="Network simulator not initialised.")
    return _net_sim


# ── Incident store helpers ────────────────────────────────────────────────────

def store_incident(state: AetherGuardState) -> None:
    _incidents[state.incident_id] = state


def get_incident(incident_id: str) -> AetherGuardState:
    state = _incidents.get(incident_id)
    if state is None:
        raise HTTPException(
            status_code=404,
            detail=f"Incident '{incident_id}' not found.",
        )
    return state


def get_all_incidents() -> list[AetherGuardState]:
    return list(_incidents.values())


def update_incident(state: AetherGuardState) -> None:
    _incidents[state.incident_id] = state