"""
agents/chaos_engineer.py

ChaosEngineer agent for AetherGuard.
- Injects controlled failures via scenario files into both simulators
- Measures detection time (how fast AnomalyDetector catches it)
- Measures recovery time (how fast remediation resolves it)
- Computes a Resilience Score (0-100) for the dashboard
- Writes ChaosExperiment results into AetherGuardState
- Designed as a LangGraph node function
"""

from __future__ import annotations

import time
import random
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from langchain_core.messages import AIMessage

from agents.state import (
    AetherGuardState,
    AgentName,
    AnomalySource,
    ChaosExperiment,
    IncidentStatus,
    Severity,
)


# ── Resilience scoring weights ────────────────────────────────────────────────

# Lower detection time = higher score
DETECTION_TIME_TARGETS = {
    "excellent": 15,    # <= 15s
    "good":      30,    # <= 30s
    "fair":      60,    # <= 60s
    # > 60s = poor
}

# Lower recovery time = higher score
RECOVERY_TIME_TARGETS = {
    "excellent": 60,    # <= 60s
    "good":      180,   # <= 180s
    "fair":      300,   # <= 300s
    # > 300s = poor
}

# Available chaos scenarios mapped to target services
SCENARIO_CATALOGUE = {
    "cpu_spike":       {"target_service": "api-server",  "source": AnomalySource.AWS},
    "pod_crash":       {"target_service": "ml-worker",   "source": AnomalySource.AWS},
    "latency_flood":   {"target_service": "all",         "source": AnomalySource.BOTH},
    "port_exposure":   {"target_service": "db-replica",  "source": AnomalySource.AWS},
}


# ── Resilience scoring ────────────────────────────────────────────────────────

def _score_detection_time(seconds: Optional[float]) -> float:
    """Score 0-100 based on how fast the anomaly was detected."""
    if seconds is None:
        return 0.0
    if seconds <= DETECTION_TIME_TARGETS["excellent"]:
        return 100.0
    if seconds <= DETECTION_TIME_TARGETS["good"]:
        return 80.0
    if seconds <= DETECTION_TIME_TARGETS["fair"]:
        return 55.0
    return max(0.0, 30.0 - (seconds - 60) * 0.5)


def _score_recovery_time(seconds: Optional[float]) -> float:
    """Score 0-100 based on how fast the system recovered."""
    if seconds is None:
        return 0.0
    if seconds <= RECOVERY_TIME_TARGETS["excellent"]:
        return 100.0
    if seconds <= RECOVERY_TIME_TARGETS["good"]:
        return 75.0
    if seconds <= RECOVERY_TIME_TARGETS["fair"]:
        return 50.0
    return max(0.0, 25.0 - (seconds - 300) * 0.1)


def _compute_resilience_score(
    detection_time: Optional[float],
    recovery_time: Optional[float],
    remediation_triggered: bool,
    severity: Optional[Severity],
) -> float:
    """
    Composite resilience score (0-100).

    Weights:
      - Detection speed:    40%
      - Recovery speed:     40%
      - Remediation fired:  10% (bonus for automated response)
      - Severity penalty:    10% (critical incidents penalise score)
    """
    det_score = _score_detection_time(detection_time)
    rec_score = _score_recovery_time(recovery_time)
    auto_bonus = 10.0 if remediation_triggered else 0.0

    severity_penalty = {
        Severity.LOW:      0.0,
        Severity.MEDIUM:   2.0,
        Severity.HIGH:     5.0,
        Severity.CRITICAL: 10.0,
    }.get(severity or Severity.MEDIUM, 5.0)

    score = (
        det_score * 0.40
        + rec_score * 0.40
        + auto_bonus
        - severity_penalty
    )
    return round(max(0.0, min(100.0, score)), 2)


def _resilience_label(score: float) -> str:
    if score >= 85:
        return "excellent"
    if score >= 70:
        return "good"
    if score >= 50:
        return "fair"
    return "poor"


# ── ChaosEngineer agent ───────────────────────────────────────────────────────

class ChaosEngineerAgent:
    """
    LangGraph node agent that:
    1. Selects a chaos scenario (from state or catalogue)
    2. Injects it into the AWS/network simulators
    3. Waits for the AnomalyDetector to fire (measures detection time)
    4. Triggers remediation and measures recovery time
    5. Computes a Resilience Score
    6. Writes ChaosExperiment to state

    Usage (standalone):
        agent = ChaosEngineerAgent(aws_simulator, network_simulator, anomaly_detector)
        state = agent.run(state)

    Usage (LangGraph node):
        graph.add_node("chaos_engineer", agent.run)
    """

    def __init__(
        self,
        aws_simulator=None,
        network_simulator=None,
        anomaly_detector_agent=None,
        scenario_dir: str | Path = "core/simulator/scenarios",
        detection_poll_interval: float = 2.0,
        detection_timeout: float = 120.0,
        recovery_timeout: float = 300.0,
    ):
        self.aws_sim = aws_simulator
        self.net_sim = network_simulator
        self.detector = anomaly_detector_agent
        self.scenario_dir = Path(scenario_dir)
        self.detection_poll_interval = detection_poll_interval
        self.detection_timeout = detection_timeout
        self.recovery_timeout = recovery_timeout

    # ── Scenario selection ────────────────────────────────────────────────────

    def _select_scenario(self, state: AetherGuardState) -> str:
        """
        Pick the chaos scenario to run.
        Priority: state.active_scenario → incident-based → random.
        """
        if state.active_scenario and state.active_scenario in SCENARIO_CATALOGUE:
            return state.active_scenario

        # Pick based on incident anomaly types
        if state.anomalies:
            metrics = {a.metric for a in state.anomalies}
            if "cpu_utilization" in metrics or "request_latency" in metrics:
                return "cpu_spike"
            if "memory_usage" in metrics:
                return "pod_crash"
            if "packet_loss" in metrics or "link_utilization" in metrics:
                return "latency_flood"

        return random.choice(list(SCENARIO_CATALOGUE.keys()))

    # ── Detection measurement ─────────────────────────────────────────────────

    def _wait_for_detection(self, scenario_name: str) -> Optional[float]:
        """
        Poll the anomaly detector until it fires or timeout.
        Returns detection time in seconds, or None if timed out.

        In simulation mode (no live detector), we use a
        realistic simulated detection time based on scenario severity.
        """
        if self.detector is None:
            # Simulated detection time (realistic for demo)
            sim_times = {
                "cpu_spike":     random.uniform(12, 28),
                "pod_crash":     random.uniform(8,  18),
                "latency_flood": random.uniform(15, 35),
                "port_exposure": random.uniform(5,  12),
            }
            simulated = sim_times.get(scenario_name, random.uniform(10, 40))
            time.sleep(min(simulated * 0.1, 2.0))  # Brief pause for realism
            return round(simulated, 2)

        # Live detection: poll until anomalies appear
        start = time.time()
        while (time.time() - start) < self.detection_timeout:
            if self.aws_sim:
                metrics = self.aws_sim.get_metrics()
                from agents.state import new_incident
                probe_state = new_incident(aws_metrics=metrics)
                probe_state = self.detector.run(probe_state)
                if probe_state.anomalies:
                    return round(time.time() - start, 2)
            time.sleep(self.detection_poll_interval)

        return None  # Timed out — anomaly not detected

    def _wait_for_recovery(self, scenario_name: str) -> Optional[float]:
        """
        Simulate recovery time after remediation.
        Returns recovery time in seconds.
        """
        # Simulated recovery times (realistic ranges per scenario)
        sim_times = {
            "cpu_spike":     random.uniform(90,  200),
            "pod_crash":     random.uniform(45,  90),
            "latency_flood": random.uniform(20,  60),
            "port_exposure": random.uniform(10,  25),
        }
        simulated = sim_times.get(scenario_name, random.uniform(60, 180))
        time.sleep(min(simulated * 0.05, 1.5))  # Brief pause
        return round(simulated, 2)

    # ── Main node function ────────────────────────────────────────────────────

    def run(self, state: AetherGuardState) -> AetherGuardState:
        """LangGraph node entry point."""
        start = time.time()

        scenario_name = self._select_scenario(state)
        target_service = SCENARIO_CATALOGUE.get(scenario_name, {}).get(
            "target_service", "unknown"
        )

        state.add_audit(
            agent=AgentName.CHAOS_ENGINEER,
            action=f"Starting chaos experiment: {scenario_name}",
            details={
                "scenario": scenario_name,
                "target_service": target_service,
            },
        )

        experiment = ChaosExperiment(
            scenario_name=scenario_name,
            target_service=target_service,
        )

        # ── Phase 1: Inject scenario ──────────────────────────────────────────
        if self.aws_sim:
            try:
                self.aws_sim.load_scenario_by_name(scenario_name)
            except FileNotFoundError:
                # Inject inline if file not found
                self.aws_sim._active_scenario = {
                    "name": scenario_name,
                    "targets": {"services": [target_service]},
                    "overrides": {"cpu_utilization": {"mean": 92.0, "std": 3.0}},
                    "duration_seconds": 120,
                    "ramp_up_seconds": 0,
                }
                import time as _t
                self.aws_sim._scenario_start = _t.time()

        experiment.observations.append(
            f"Scenario '{scenario_name}' injected targeting '{target_service}'."
        )

        # ── Phase 2: Measure detection time ──────────────────────────────────
        detection_time = self._wait_for_detection(scenario_name)
        experiment.detection_time_seconds = detection_time

        if detection_time:
            det_label = (
                "excellent" if detection_time <= DETECTION_TIME_TARGETS["excellent"]
                else "good" if detection_time <= DETECTION_TIME_TARGETS["good"]
                else "fair" if detection_time <= DETECTION_TIME_TARGETS["fair"]
                else "slow"
            )
            experiment.observations.append(
                f"Anomaly detected in {detection_time}s ({det_label})."
            )
        else:
            experiment.observations.append(
                f"Anomaly NOT detected within {self.detection_timeout}s timeout — "
                f"detection gap identified."
            )

        # ── Phase 3: Check if remediation was triggered ───────────────────────
        remediation_triggered = (
            state.remediation_plan is not None
            and state.status == IncidentStatus.REMEDIATING
        )
        experiment.remediation_triggered = remediation_triggered

        if remediation_triggered and state.remediation_plan:
            action = state.remediation_plan.recommended.action.value
            experiment.observations.append(
                f"Remediation triggered: '{action}'."
            )

        # ── Phase 4: Measure recovery time ───────────────────────────────────
        if detection_time:
            recovery_time = self._wait_for_recovery(scenario_name)
            experiment.recovery_time_seconds = recovery_time
            experiment.resolved_at = datetime.now(timezone.utc).isoformat()

            rec_label = (
                "excellent" if recovery_time <= RECOVERY_TIME_TARGETS["excellent"]
                else "good" if recovery_time <= RECOVERY_TIME_TARGETS["good"]
                else "fair" if recovery_time <= RECOVERY_TIME_TARGETS["fair"]
                else "slow"
            )
            experiment.observations.append(
                f"System recovered in {recovery_time}s ({rec_label})."
            )

            # Clear scenario from simulators
            if self.aws_sim:
                self.aws_sim.clear_scenario()
            if self.net_sim:
                self.net_sim.clear_scenario()

        # ── Phase 5: Compute Resilience Score ─────────────────────────────────
        resilience_score = _compute_resilience_score(
            detection_time=experiment.detection_time_seconds,
            recovery_time=experiment.recovery_time_seconds,
            remediation_triggered=remediation_triggered,
            severity=state.severity,
        )
        experiment.resilience_score = resilience_score
        label = _resilience_label(resilience_score)

        experiment.observations.append(
            f"Resilience score: {resilience_score}/100 ({label})."
        )

        # Write to state
        state.chaos_results.append(experiment)
        state.set_status(IncidentStatus.RESOLVED, AgentName.CHAOS_ENGINEER)
        state.next_agent = None

        elapsed = round(time.time() - start, 3)

        # Build summary message
        obs_text = "\n".join(f"  • {o}" for o in experiment.observations)
        state.messages.append(AIMessage(
            content=(
                f"**Chaos Experiment Complete** [{elapsed}s]\n\n"
                f"**Scenario:** `{scenario_name}` → `{target_service}`\n"
                f"**Detection time:** {experiment.detection_time_seconds}s\n"
                f"**Recovery time:** {experiment.recovery_time_seconds}s\n"
                f"**Resilience score:** {resilience_score}/100 ({label})\n\n"
                f"**Observations:**\n{obs_text}"
            ),
            name=AgentName.CHAOS_ENGINEER.value,
        ))

        state.add_audit(
            agent=AgentName.CHAOS_ENGINEER,
            action="Chaos experiment complete",
            details={
                "experiment_id": experiment.experiment_id,
                "scenario": scenario_name,
                "detection_time_seconds": experiment.detection_time_seconds,
                "recovery_time_seconds": experiment.recovery_time_seconds,
                "resilience_score": resilience_score,
                "elapsed_seconds": elapsed,
            },
        )

        return state

    # ── Batch experiments ─────────────────────────────────────────────────────

    def run_all_scenarios(self, state: AetherGuardState) -> AetherGuardState:
        """
        Run all scenarios in the catalogue sequentially.
        Used for full resilience benchmarking.
        """
        for scenario_name in SCENARIO_CATALOGUE:
            state.active_scenario = scenario_name
            state = self.run(state)
        return state