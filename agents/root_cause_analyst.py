"""
agents/root_cause_analyst.py

RootCauseAnalyst agent for AetherGuard.
- Uses Claude (via LangChain) to generate natural language RCA
- Correlates AWS + network anomalies into a unified explanation
- Pulls similar past incidents from agent memory
- Writes RootCauseAnalysis into AetherGuardState
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
    AnomalyRecord,
    AnomalySource,
    IncidentStatus,
    RootCauseAnalysis,
    Severity,
)
from agents.prompts.rca_prompt import RCA_SYSTEM_PROMPT, build_rca_user_prompt


# ── RootCauseAnalyst agent ───────────────────────────────────────────────────

class RootCauseAnalystAgent:
    """
    LangGraph node agent that:
    1. Reads anomalies from state
    2. Pulls similar incidents from memory (if available)
    3. Calls Claude to generate a structured RCA
    4. Parses LLM output into RootCauseAnalysis model
    5. Writes result back to state

    Usage (standalone):
        agent = RootCauseAnalystAgent()
        state = agent.run(state)

    Usage (LangGraph node):
        graph.add_node("root_cause_analyst", agent.run)
    """

    def __init__(
        self,
        model: str = "claude-sonnet-4-20250514",
        temperature: float = 0.2,
        memory_store: Optional[Any] = None,
    ):
        self.llm = ChatAnthropic(
            model=model,
            temperature=temperature,
            max_tokens=2048,
        )
        self.model_name = model
        self.memory_store = memory_store  # agents/memory/incident_history.py

    # ── Helpers ──────────────────────────────────────────────────────────────

    def _format_anomalies(self, anomalies: list[AnomalyRecord]) -> str:
        """Serialize anomaly list into a clean string for the LLM prompt."""
        lines = []
        for i, a in enumerate(anomalies, 1):
            lines.append(
                f"{i}. [{a.severity.value.upper()}] {a.source.value.upper()} | "
                f"Metric: {a.metric} | Entity: {a.entity_id} "
                f"({'service=' + a.service if a.service else 'site=' + (a.site or 'unknown')}) | "
                f"Observed: {a.observed_value} | "
                f"Expected range: {a.expected_range[0]}–{a.expected_range[1]} | "
                f"Anomaly score: {a.anomaly_score}"
            )
        return "\n".join(lines)

    def _fetch_similar_incidents(self, anomalies: list[AnomalyRecord]) -> list[str]:
        """Query memory store for similar past incidents."""
        if not self.memory_store:
            return []
        try:
            metrics = list({a.metric for a in anomalies})
            return self.memory_store.search_similar(metrics=metrics, top_k=3)
        except Exception:
            return []

    def _parse_llm_response(self, raw: str, anomalies: list[AnomalyRecord]) -> RootCauseAnalysis:
        """
        Parse LLM JSON response into RootCauseAnalysis.
        Falls back to a safe default if JSON parsing fails.
        """
        try:
            # Strip markdown code fences if present
            cleaned = raw.strip()
            if cleaned.startswith("```"):
                cleaned = "\n".join(cleaned.split("\n")[1:-1])
            data = json.loads(cleaned)

            return RootCauseAnalysis(
                summary=data.get("summary", "RCA unavailable."),
                detailed_analysis=data.get("detailed_analysis", raw),
                probable_cause=data.get("probable_cause", "Unknown"),
                contributing_factors=data.get("contributing_factors", []),
                affected_services=data.get("affected_services", []),
                similar_incidents=data.get("similar_incidents", []),
                confidence=float(data.get("confidence", 0.5)),
                llm_model=self.model_name,
            )
        except (json.JSONDecodeError, KeyError, ValueError):
            # Graceful fallback — use raw text as detailed analysis
            affected = list({a.service or a.site or a.entity_id for a in anomalies})
            return RootCauseAnalysis(
                summary=f"Anomalies detected across {len(anomalies)} metric(s). Manual review required.",
                detailed_analysis=raw,
                probable_cause="Unable to parse structured RCA — see detailed_analysis.",
                contributing_factors=[a.metric for a in anomalies],
                affected_services=affected,
                confidence=0.3,
                llm_model=self.model_name,
            )

    # ── Main node function ───────────────────────────────────────────────────

    def run(self, state: AetherGuardState) -> AetherGuardState:
        """LangGraph node entry point."""
        start = time.time()

        state.add_audit(
            agent=AgentName.ROOT_CAUSE_ANALYST,
            action="Starting root cause analysis",
            details={"anomaly_count": len(state.anomalies)},
        )

        if not state.anomalies:
            state.add_audit(
                agent=AgentName.ROOT_CAUSE_ANALYST,
                action="No anomalies to analyse — skipping",
                success=False,
            )
            state.next_agent = None
            return state

        # Fetch similar past incidents from memory
        similar = self._fetch_similar_incidents(state.anomalies)

        # Build prompt
        anomaly_text = self._format_anomalies(state.anomalies)
        user_prompt = build_rca_user_prompt(
            incident_id=state.incident_id,
            anomaly_text=anomaly_text,
            active_scenario=state.active_scenario,
            similar_incidents=similar,
            severity=state.severity.value if state.severity else "unknown",
        )

        # Call Claude
        try:
            messages = [
                SystemMessage(content=RCA_SYSTEM_PROMPT),
                HumanMessage(content=user_prompt),
            ]
            response = self.llm.invoke(messages)
            raw_output = response.content

        except Exception as e:
            error_msg = f"LLM call failed: {str(e)}"
            state.error = error_msg
            state.add_audit(
                agent=AgentName.ROOT_CAUSE_ANALYST,
                action="LLM call failed",
                details={"error": error_msg},
                success=False,
            )
            state.next_agent = AgentName.REMEDIATION_PLANNER
            return state

        # Parse response
        rca = self._parse_llm_response(raw_output, state.anomalies)
        rca.similar_incidents = similar

        # Write to state
        state.root_cause = rca
        state.title = rca.summary[:120]  # Use summary as incident title
        state.next_agent = AgentName.REMEDIATION_PLANNER

        elapsed = round(time.time() - start, 3)

        state.messages.append(AIMessage(
            content=(
                f"**RCA Complete** [{elapsed}s | confidence={rca.confidence:.0%}]\n\n"
                f"**Summary:** {rca.summary}\n\n"
                f"**Probable cause:** {rca.probable_cause}\n\n"
                f"**Contributing factors:** {', '.join(rca.contributing_factors)}\n\n"
                f"**Affected services:** {', '.join(rca.affected_services)}"
            ),
            name=AgentName.ROOT_CAUSE_ANALYST.value,
        ))

        state.add_audit(
            agent=AgentName.ROOT_CAUSE_ANALYST,
            action="RCA generated",
            details={
                "rca_id": rca.rca_id,
                "confidence": rca.confidence,
                "probable_cause": rca.probable_cause,
                "elapsed_seconds": elapsed,
            },
        )

        return state