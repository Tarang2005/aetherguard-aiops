"""
core/config.py

Centralised configuration for AetherGuard using Pydantic Settings.
All values can be overridden via environment variables or .env file.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Optional

from pydantic import Field
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # ── App ──────────────────────────────────────────────────────────────────
    app_name:    str = "AetherGuard"
    app_version: str = "0.1.0"
    environment: str = Field(default="development", alias="ENVIRONMENT")
    debug:       bool = Field(default=True, alias="DEBUG")
    log_level:   str = Field(default="INFO", alias="LOG_LEVEL")

    # ── API ──────────────────────────────────────────────────────────────────
    api_host: str = Field(default="0.0.0.0", alias="API_HOST")
    api_port: int = Field(default=8000,      alias="API_PORT")
    api_reload: bool = Field(default=True,   alias="API_RELOAD")

    # ── Anthropic ────────────────────────────────────────────────────────────
    anthropic_api_key: Optional[str] = Field(default=None, alias="ANTHROPIC_API_KEY")
    llm_model:         str = Field(
        default="claude-sonnet-4-20250514", alias="LLM_MODEL"
    )
    llm_temperature: float = Field(default=0.2, alias="LLM_TEMPERATURE")

    # ── Simulator ────────────────────────────────────────────────────────────
    simulator_seed:          Optional[int]  = Field(default=42,  alias="SIMULATOR_SEED")
    simulator_warmup_ticks:  int            = Field(default=30,  alias="SIMULATOR_WARMUP_TICKS")
    simulator_poll_interval: float          = Field(default=5.0, alias="SIMULATOR_POLL_INTERVAL")
    scenario_dir:            str            = Field(
        default="core/simulator/scenarios", alias="SCENARIO_DIR"
    )

    # ── Anomaly Detection ────────────────────────────────────────────────────
    if_contamination:  float = Field(default=0.05, alias="IF_CONTAMINATION")
    flap_threshold:    int   = Field(default=2,    alias="FLAP_THRESHOLD")

    # ── Remediation ──────────────────────────────────────────────────────────
    auto_remediate:          bool = Field(default=False, alias="AUTO_REMEDIATE")
    run_chaos_after_remediation: bool = Field(default=True, alias="RUN_CHAOS")
    approval_timeout_seconds:    int  = Field(default=300, alias="APPROVAL_TIMEOUT_SECONDS")

    # ── AWS ──────────────────────────────────────────────────────────────────
    aws_region:            str           = Field(default="us-east-1", alias="AWS_REGION")
    aws_access_key_id:     Optional[str] = Field(default=None, alias="AWS_ACCESS_KEY_ID")
    aws_secret_access_key: Optional[str] = Field(default=None, alias="AWS_SECRET_ACCESS_KEY")

    # ── WebSocket ────────────────────────────────────────────────────────────
    ws_heartbeat_seconds: float = Field(default=2.0, alias="WS_HEARTBEAT_SECONDS")

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        populate_by_name = True


@lru_cache()
def get_settings() -> Settings:
    """Cached settings singleton — use this everywhere."""
    return Settings()