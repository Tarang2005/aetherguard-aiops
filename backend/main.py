"""
backend/main.py

FastAPI application entry point for AetherGuard.
Mounts all routers and sets up lifespan (startup/shutdown).
"""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from core.config import get_settings
from core.simulator.aws_simulator import AWSSimulator
from core.simulator.network_simulator import NetworkSimulator
from agents.supervisor import SupervisorAgent
from backend.dependencies import set_supervisor, set_simulators
from backend.routes import agents, approval, chaos, dashboard, websocket

settings = get_settings()


# ── Lifespan (startup + shutdown) ─────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Startup: warm up simulators and anomaly detector.
    Shutdown: clean up resources.
    """
    print(f"[AetherGuard] Starting up — env={settings.environment}")

    # Init simulators
    aws_sim = AWSSimulator(seed=settings.simulator_seed)
    net_sim = NetworkSimulator(seed=settings.simulator_seed)
    set_simulators(aws_sim, net_sim)

    # Init supervisor (builds the full LangGraph)
    supervisor = SupervisorAgent(
        aws_simulator=aws_sim,
        network_simulator=net_sim,
        auto_remediate=settings.auto_remediate,
        run_chaos=settings.run_chaos_after_remediation,
        scenario_dir=settings.scenario_dir,
    )

    # Warm up anomaly detector in background
    loop = asyncio.get_event_loop()
    await loop.run_in_executor(
        None,
        supervisor.warm_up,
        settings.simulator_warmup_ticks,
    )

    set_supervisor(supervisor)
    print(f"[AetherGuard] Ready — {settings.simulator_warmup_ticks} warmup ticks complete.")

    yield

    print("[AetherGuard] Shutting down.")


# ── App factory ───────────────────────────────────────────────────────────────

def create_app() -> FastAPI:
    app = FastAPI(
        title=settings.app_name,
        version=settings.app_version,
        description="Agentic Multi-Cloud AIOps Platform",
        lifespan=lifespan,
    )

    # CORS — allow Streamlit dashboard and Next.js dev server
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Mount routers
    app.include_router(dashboard.router,   prefix="/api/dashboard",   tags=["dashboard"])
    app.include_router(agents.router,      prefix="/api/agents",      tags=["agents"])
    app.include_router(approval.router,    prefix="/api/approval",    tags=["approval"])
    app.include_router(chaos.router,       prefix="/api/chaos",       tags=["chaos"])
    app.include_router(websocket.router,   prefix="/ws",              tags=["websocket"])

    @app.get("/health")
    async def health_check():
        return {"status": "ok", "version": settings.app_version}

    return app


app = create_app()


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "backend.main:app",
        host=settings.api_host,
        port=settings.api_port,
        reload=settings.api_reload,
    )