"""
agents/anomaly_detector.py

AnomalyDetector agent for AetherGuard.
- Uses Isolation Forest (scikit-learn) to detect anomalies in AWS + network metrics
- Anti-flapping logic: anomaly must appear in N consecutive ticks before firing
- Severity scoring based on anomaly score + metric type
- Writes detected anomalies directly into AetherGuardState
- Designed as a LangGraph node function
"""

from __future__ import annotations

import time
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Optional

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from langchain_core.messages import AIMessage

from agents.state import (
    AetherGuardState,
    AgentName,
    AnomalyRecord,
    AnomalySource,
    IncidentStatus,
    Severity,
)


# ── Constants ────────────────────────────────────────────────────────────────

# AWS metrics and their anomaly severity weights
# Higher weight = more critical if anomalous
AWS_METRIC_WEIGHTS: dict[str, float] = {
    "cpu_utilization":  0.85,
    "memory_usage":     0.80,
    "request_latency":  0.90,
    "error_rate":       0.95,
    "network_in":       0.60,
    "network_out":      0.60,
    "disk_io_read":     0.55,
    "disk_io_write":    0.55,
}

# Network metrics and their severity weights
NETWORK_METRIC_WEIGHTS: dict[str, float] = {
    "cpu_load":         0.70,
    "memory_load":      0.65,
    "link_utilization": 0.75,
    "packet_loss":      0.95,   # very high — packet loss is serious
    "reachability":     1.00,   # highest — unreachable = critical
    "interface_errors": 0.80,
}

# Severity thresholds based on combined anomaly score × metric weight
SEVERITY_THRESHOLDS = {
    Severity.CRITICAL: 0.85,
    Severity.HIGH:     0.65,
    Severity.MEDIUM:   0.45,
    # below 0.45 = LOW
}

# Anti-flapping: anomaly must persist for this many consecutive ticks
FLAP_THRESHOLD = 2

# Isolation Forest contamination — expected % of anomalies in normal data
IF_CONTAMINATION = 0.05

# Minimum number of data points needed to fit the model
MIN_FIT_SAMPLES = 20


# ── Severity scoring ─────────────────────────────────────────────────────────

def _score_to_severity(anomaly_score: float, metric_weight: float) -> Severity:
    """
    Map combined (anomaly_score × metric_weight) to a Severity level.
    anomaly_score: 0.0–1.0 (higher = more anomalous, from IF)
    metric_weight: 0.0–1.0 (how critical this metric type is)
    """
    combined = anomaly_score * metric_weight
    if combined >= SEVERITY_THRESHOLDS[Severity.CRITICAL]:
        return Severity.CRITICAL
    if combined >= SEVERITY_THRESHOLDS[Severity.HIGH]:
        return Severity.HIGH
    if combined >= SEVERITY_THRESHOLDS[Severity.MEDIUM]:
        return Severity.MEDIUM
    return Severity.LOW


def _expected_range(values: list[float]) -> tuple[float, float]:
    """Compute expected (normal) range as mean ± 2 std."""
    arr = np.array(values)
    mean, std = arr.mean(), arr.std()
    return (round(float(mean - 2 * std), 4), round(float(mean + 2 * std), 4))


# ── Isolation Forest wrapper ─────────────────────────────────────────────────

class IsolationForestDetector:
    """
    Wraps sklearn IsolationForest with:
    - Per-entity model fitting (one model per instance/device)
    - Rolling history window for online detection
    - StandardScaler normalisation
    - Anti-flapping consecutive-tick counter

    This is the core ML component, reused and enhanced from SICRO.
    """

    def __init__(
        self,
        contamination: float = IF_CONTAMINATION,
        n_estimators: int = 100,
        window_size: int = 50,        # rolling history window per entity
        flap_threshold: int = FLAP_THRESHOLD,
        random_state: int = 42,
    ):
        self.contamination = contamination
        self.n_estimators = n_estimators
        self.window_size = window_size
        self.flap_threshold = flap_threshold
        self.random_state = random_state

        # Per-entity state
        self._models:    dict[str, IsolationForest] = {}
        self._scalers:   dict[str, StandardScaler]  = {}
        self._history:   dict[str, list[dict]]      = defaultdict(list)
        self._flap_counts: dict[str, int]           = defaultdict(int)
        self._fit_counts:  dict[str, int]           = defaultdict(int)

    def _entity_key(self, entity_id: str, metric: str) -> str:
        return f"{entity_id}::{metric}"

    def ingest(self, entity_id: str, metric: str, value: float, metadata: dict) -> None:
        """
        Add a new data point to the rolling history for this entity+metric.
        Automatically refits the model every 10 new points.
        """
        key = self._entity_key(entity_id, metric)
        self._history[key].append({"value": value, **metadata})

        # Keep only the rolling window
        if len(self._history[key]) > self.window_size:
            self._history[key] = self._history[key][-self.window_size:]

        self._fit_counts[key] += 1

        # Refit every 10 new points once we have enough history
        if (
            len(self._history[key]) >= MIN_FIT_SAMPLES
            and self._fit_counts[key] % 10 == 0
        ):
            self._fit(key)

    def _fit(self, key: str) -> None:
        """Fit (or refit) the Isolation Forest for a specific entity+metric."""
        values = np.array(
            [r["value"] for r in self._history[key]]
        ).reshape(-1, 1)

        scaler = StandardScaler()
        values_scaled = scaler.fit_transform(values)

        model = IsolationForest(
            n_estimators=self.n_estimators,
            contamination=self.contamination,
            random_state=self.random_state,
            n_jobs=-1,
        )
        model.fit(values_scaled)

        self._models[key] = model
        self._scalers[key] = scaler

    def predict(
        self,
        entity_id: str,
        metric: str,
        value: float,
    ) -> tuple[bool, float, bool]:
        """
        Predict whether a value is anomalous.

        Returns:
            (is_anomaly, anomaly_score, is_flapping)

            is_anomaly:   True if IF flags as anomaly AND flap threshold met
            anomaly_score: 0.0–1.0 normalised anomaly score
            is_flapping:  True if anomaly seen but flap threshold NOT yet met
        """
        key = self._entity_key(entity_id, metric)

        # Not enough history yet — can't predict
        if key not in self._models:
            if len(self._history[key]) >= MIN_FIT_SAMPLES:
                self._fit(key)
            else:
                return False, 0.0, False

        values_scaled = self._scalers[key].transform([[value]])
        prediction = self._models[key].predict(values_scaled)[0]  # -1 = anomaly, 1 = normal

        # Raw IF score: more negative = more anomalous
        raw_score = self._models[key].score_samples(values_scaled)[0]

        # Normalise to 0–1 (higher = more anomalous)
        # IF scores typically range from -0.5 to 0.5
        normalised_score = round(float(np.clip((raw_score * -1 + 0.5), 0.0, 1.0)), 4)

        is_raw_anomaly = prediction == -1

        # Anti-flapping logic
        if is_raw_anomaly:
            self._flap_counts[key] += 1
        else:
            self._flap_counts[key] = 0  # Reset on normal reading

        is_flapping = is_raw_anomaly and self._flap_counts[key] < self.flap_threshold
        is_confirmed = is_raw_anomaly and self._flap_counts[key] >= self.flap_threshold

        return is_confirmed, normalised_score, is_flapping

    def reset_entity(self, entity_id: str, metric: str) -> None:
        """Clear history and model for a specific entity+metric (post-remediation)."""
        key = self._entity_key(entity_id, metric)
        self._history.pop(key, None)
        self._models.pop(key, None)
        self._scalers.pop(key, None)
        self._flap_counts.pop(key, None)
        self._fit_counts.pop(key, None)

    def stats(self) -> dict[str, Any]:
        """Return diagnostics for logging/dashboard."""
        return {
            "tracked_entities": len(self._history),
            "fitted_models":    len(self._models),
            "flap_counts":      dict(self._flap_counts),
        }


# ── AnomalyDetector agent ────────────────────────────────────────────────────

class AnomalyDetectorAgent:
    """
    LangGraph node agent that:
    1. Ingests AWS + network metrics from state
    2. Runs Isolation Forest per entity+metric
    3. Applies anti-flapping logic
    4. Writes AnomalyRecord list back to state
    5. Sets incident severity and status

    Usage (standalone):
        agent = AnomalyDetectorAgent()
        state = new_incident(aws_metrics=..., network_metrics=...)
        state = agent.run(state)

    Usage (LangGraph node):
        graph.add_node("anomaly_detector", agent.run)
    """

    def __init__(
        self,
        contamination: float = IF_CONTAMINATION,
        flap_threshold: int = FLAP_THRESHOLD,
        min_anomalies_to_escalate: int = 1,
    ):
        self.detector = IsolationForestDetector(
            contamination=contamination,
            flap_threshold=flap_threshold,
        )
        self.min_anomalies_to_escalate = min_anomalies_to_escalate

    # ── AWS metric processing ────────────────────────────────────────────────

    def _process_aws_metrics(
        self,
        aws_metrics: list[dict[str, Any]],
    ) -> list[AnomalyRecord]:
        """Detect anomalies in AWS CloudWatch-style metrics."""
        anomalies: list[AnomalyRecord] = []

        for record in aws_metrics:
            metric = record.get("metric")
            entity_id = record.get("instance_id")
            value = record.get("value")

            if not all([metric, entity_id, value is not None]):
                continue
            if metric not in AWS_METRIC_WEIGHTS:
                continue

            weight = AWS_METRIC_WEIGHTS[metric]

            # Ingest into rolling history
            self.detector.ingest(
                entity_id=entity_id,
                metric=metric,
                value=float(value),
                metadata={"timestamp": record.get("timestamp"), "service": record.get("service")},
            )

            # Predict
            is_anomaly, score, is_flapping = self.detector.predict(entity_id, metric, float(value))

            if is_anomaly or is_flapping:
                history = self.detector._history[
                    self.detector._entity_key(entity_id, metric)
                ]
                historical_values = [r["value"] for r in history[:-1]] or [value]

                anomalies.append(AnomalyRecord(
                    source=AnomalySource.AWS,
                    metric=metric,
                    entity_id=entity_id,
                    entity_type=record.get("instance_type", "ec2"),
                    service=record.get("service"),
                    observed_value=float(value),
                    expected_range=_expected_range(historical_values),
                    anomaly_score=score,
                    severity=_score_to_severity(score, weight),
                    is_flapping=is_flapping,
                    raw_metrics=record,
                ))

        return anomalies

    # ── Network metric processing ────────────────────────────────────────────

    def _process_network_metrics(
        self,
        network_metrics: list[dict[str, Any]],
    ) -> list[AnomalyRecord]:
        """Detect anomalies in DNAC-style network health metrics."""
        anomalies: list[AnomalyRecord] = []

        network_metric_fields = list(NETWORK_METRIC_WEIGHTS.keys())

        for record in network_metrics:
            device_id = record.get("device_id")
            device_type = record.get("device_type")
            if not device_id:
                continue

            for metric in network_metric_fields:
                value = record.get(metric)
                if value is None:
                    continue

                weight = NETWORK_METRIC_WEIGHTS[metric]

                self.detector.ingest(
                    entity_id=device_id,
                    metric=metric,
                    value=float(value),
                    metadata={"timestamp": record.get("timestamp"), "site": record.get("site")},
                )

                is_anomaly, score, is_flapping = self.detector.predict(
                    device_id, metric, float(value)
                )

                if is_anomaly or is_flapping:
                    history = self.detector._history[
                        self.detector._entity_key(device_id, metric)
                    ]
                    historical_values = [r["value"] for r in history[:-1]] or [value]

                    anomalies.append(AnomalyRecord(
                        source=AnomalySource.NETWORK,
                        metric=metric,
                        entity_id=device_id,
                        entity_type=device_type or "network_device",
                        site=record.get("site"),
                        observed_value=float(value),
                        expected_range=_expected_range(historical_values),
                        anomaly_score=score,
                        severity=_score_to_severity(score, weight),
                        is_flapping=is_flapping,
                        raw_metrics=record,
                    ))

        return anomalies

    # ── Main node function ───────────────────────────────────────────────────

    def run(self, state: AetherGuardState) -> AetherGuardState:
        """
        LangGraph node entry point.
        Processes metrics in state, detects anomalies, updates state.
        """
        start = time.time()

        state.add_audit(
            agent=AgentName.ANOMALY_DETECTOR,
            action="Starting anomaly detection",
            details={
                "aws_metric_records": len(state.aws_metrics),
                "network_metric_records": len(state.network_metrics),
            },
        )

        # Run detection on both sources
        aws_anomalies = self._process_aws_metrics(state.aws_metrics)
        net_anomalies = self._process_network_metrics(state.network_metrics)
        all_anomalies = aws_anomalies + net_anomalies

        # Confirmed (non-flapping) anomalies only
        confirmed = [a for a in all_anomalies if not a.is_flapping]
        flapping  = [a for a in all_anomalies if a.is_flapping]

        # Write to state
        state.anomalies = confirmed

        elapsed = round(time.time() - start, 3)

        if confirmed:
            # Set overall severity to highest detected
            state.severity = state.highest_anomaly_severity()
            state.set_status(IncidentStatus.INVESTIGATING, AgentName.ANOMALY_DETECTOR)
            state.next_agent = AgentName.ROOT_CAUSE_ANALYST

            summary_lines = [
                f"Detected {len(confirmed)} anomal{'y' if len(confirmed) == 1 else 'ies'} "
                f"({len(flapping)} suppressed by anti-flapping) in {elapsed}s.",
                "",
            ]
            for a in confirmed:
                summary_lines.append(
                    f"  • [{a.severity.value.upper()}] {a.metric} on {a.entity_id} "
                    f"— observed {a.observed_value} "
                    f"(expected {a.expected_range[0]}–{a.expected_range[1]}) "
                    f"score={a.anomaly_score}"
                )
            summary = "\n".join(summary_lines)

        else:
            # No anomalies — dismiss incident
            state.set_status(IncidentStatus.DISMISSED, AgentName.ANOMALY_DETECTOR)
            state.next_agent = None
            summary = (
                f"No anomalies detected across {len(state.aws_metrics)} AWS records "
                f"and {len(state.network_metrics)} network records "
                f"({len(flapping)} flapping suppressed). "
                f"Incident dismissed. [{elapsed}s]"
            )

        # Add message to conversation thread
        state.messages.append(AIMessage(
            content=summary,
            name=AgentName.ANOMALY_DETECTOR.value,
        ))

        state.add_audit(
            agent=AgentName.ANOMALY_DETECTOR,
            action="Anomaly detection complete",
            details={
                "confirmed_anomalies": len(confirmed),
                "flapping_suppressed": len(flapping),
                "severity": state.severity.value if state.severity else None,
                "elapsed_seconds": elapsed,
                "detector_stats": self.detector.stats(),
            },
        )

        return state

    # ── Warm-up helper ───────────────────────────────────────────────────────

    def warm_up(
        self,
        aws_simulator,
        network_simulator,
        ticks: int = 30,
        interval: float = 0.0,
    ) -> None:
        """
        Feed N ticks of baseline data to the detector before going live.
        This builds up enough history for the Isolation Forest to fit.

        Call this once at startup before the first real incident.

        Usage:
            detector = AnomalyDetectorAgent()
            detector.warm_up(aws_sim, net_sim, ticks=30)
        """
        print(f"[AnomalyDetector] Warming up with {ticks} baseline ticks...")
        for i in range(ticks):
            for record in aws_simulator.get_metrics():
                metric = record.get("metric")
                entity_id = record.get("instance_id")
                value = record.get("value")
                if metric and entity_id and value is not None:
                    self.detector.ingest(entity_id, metric, float(value), {})

            for record in network_simulator.get_metrics():
                device_id = record.get("device_id")
                for m in NETWORK_METRIC_WEIGHTS:
                    value = record.get(m)
                    if device_id and value is not None:
                        self.detector.ingest(device_id, m, float(value), {})

            if interval > 0:
                time.sleep(interval)

        print(
            f"[AnomalyDetector] Warm-up complete. "
            f"Tracking {self.detector.stats()['tracked_entities']} entity-metric pairs, "
            f"{self.detector.stats()['fitted_models']} models fitted."
        )


# ── Quick demo ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import json
    import sys
    import os

    sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

    from core.simulator.aws_simulator import AWSSimulator
    from core.simulator.network_simulator import NetworkSimulator
    from agents.state import new_incident

    print("=== AnomalyDetector Demo ===\n")

    aws_sim = AWSSimulator(seed=42)
    net_sim = NetworkSimulator(seed=42)
    agent   = AnomalyDetectorAgent()

    # Step 1: warm up on 30 ticks of baseline data
    agent.warm_up(aws_sim, net_sim, ticks=30)

    # Step 2: inject a CPU spike scenario
    aws_sim._active_scenario = {
        "name": "cpu_spike_demo",
        "targets": {"services": ["api-server"]},
        "overrides": {
            "cpu_utilization": {"mean": 95.0, "std": 1.5},
            "request_latency": {"mean": 920.0, "std": 50.0},
            "error_rate":      {"mean": 8.0,   "std": 1.0},
        },
        "duration_seconds": 60,
        "ramp_up_seconds":  0,
    }
    import time as _time
    aws_sim._scenario_start = _time.time()

    # Step 3: run a few anomalous ticks so flap threshold is met
    for _ in range(FLAP_THRESHOLD + 1):
        for record in aws_sim.get_metrics():
            metric = record.get("metric")
            entity_id = record.get("instance_id")
            value = record.get("value")
            if metric and entity_id and value is not None:
                agent.detector.ingest(entity_id, metric, float(value), {})

    # Step 4: run the agent
    state = new_incident(
        aws_metrics=aws_sim.get_metrics(),
        network_metrics=net_sim.get_metrics(),
        active_scenario="cpu_spike_demo",
    )
    state = agent.run(state)

    # Step 5: print results
    print(f"\nIncident: {state.incident_id} | Status: {state.status.value} | Severity: {state.severity}")
    print(f"Anomalies detected: {len(state.anomalies)}")
    for a in state.anomalies:
        print(
            f"  [{a.severity.value.upper()}] {a.source.value}/{a.metric} "
            f"on {a.entity_id} — {a.observed_value} "
            f"(expected {a.expected_range[0]}–{a.expected_range[1]})"
        )

    print(f"\nNext agent: {state.next_agent}")
    print(f"\nMessages:")
    for m in state.messages:
        print(f"  {m.name}: {m.content[:200]}")

    print(f"\nAudit log:")
    for e in state.audit_log:
        print(f"  {e.agent.value}: {e.action}")

    print("\n AnomalyDetector ready.")