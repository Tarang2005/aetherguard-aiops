"""
core/simulator/aws_simulator.py

Simulates AWS CloudWatch-style metrics for AetherGuard.
- Generates realistic baseline metrics with natural noise
- Injects anomalies from YAML scenario files
- Outputs as Python dict/JSON or Pandas DataFrame
"""

import random
import math
import time
import yaml
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
import pandas as pd


# ── Default baseline profiles per metric ────────────────────────────────────

METRIC_BASELINES = {
    "cpu_utilization":   {"mean": 35.0,  "std": 5.0,  "min": 0.0,   "max": 100.0, "unit": "Percent"},
    "memory_usage":      {"mean": 55.0,  "std": 4.0,  "min": 0.0,   "max": 100.0, "unit": "Percent"},
    "network_in":        {"mean": 150.0, "std": 20.0, "min": 0.0,   "max": 5000.0,"unit": "MB/s"},
    "network_out":       {"mean": 80.0,  "std": 15.0, "min": 0.0,   "max": 5000.0,"unit": "MB/s"},
    "disk_io_read":      {"mean": 40.0,  "std": 8.0,  "min": 0.0,   "max": 1000.0,"unit": "MB/s"},
    "disk_io_write":     {"mean": 25.0,  "std": 6.0,  "min": 0.0,   "max": 1000.0,"unit": "MB/s"},
    "request_latency":   {"mean": 120.0, "std": 15.0, "min": 1.0,   "max": 10000.0,"unit": "ms"},
    "error_rate":        {"mean": 0.5,   "std": 0.2,  "min": 0.0,   "max": 100.0, "unit": "Percent"},
}

# ── Instance registry (simulated EC2/ECS instances) ──────────────────────────

DEFAULT_INSTANCES = [
    {"id": "i-0aetherguard01", "type": "m5.xlarge",  "az": "us-east-1a", "service": "api-server"},
    {"id": "i-0aetherguard02", "type": "m5.xlarge",  "az": "us-east-1b", "service": "api-server"},
    {"id": "i-0aetherguard03", "type": "c5.2xlarge", "az": "us-east-1a", "service": "ml-worker"},
    {"id": "i-0aetherguard04", "type": "r5.large",   "az": "us-east-1b", "service": "db-replica"},
]


# ── Noise helpers ────────────────────────────────────────────────────────────

def _gaussian_noise(mean: float, std: float, min_val: float, max_val: float) -> float:
    """Generate a single Gaussian-noised metric value, clamped to valid range."""
    value = random.gauss(mean, std)
    return round(max(min_val, min(max_val, value)), 4)


def _diurnal_offset(metric: str, hour: int) -> float:
    """
    Add realistic time-of-day variation.
    CPU/memory/latency peak during business hours (9-17 UTC).
    Network peaks slightly later (12-20 UTC).
    """
    if metric in ("cpu_utilization", "memory_usage", "request_latency"):
        # Business hours bump: +15% peak at hour 13
        return 15.0 * math.sin(math.pi * max(0, hour - 6) / 12) if 6 <= hour <= 22 else 0.0
    if metric in ("network_in", "network_out"):
        return 30.0 * math.sin(math.pi * max(0, hour - 8) / 14) if 8 <= hour <= 22 else 0.0
    return 0.0


# ── Scenario loader ──────────────────────────────────────────────────────────

def load_scenario(scenario_path: str | Path) -> dict:
    """
    Load a chaos/anomaly scenario from a YAML file.

    Expected YAML structure:
        name: cpu_spike
        description: "Sudden CPU spike on api-server instances"
        targets:
          services: [api-server]          # or instance_ids: [i-0aetherguard01]
        overrides:
          cpu_utilization:
            mean: 92.0
            std: 3.0
          request_latency:
            mean: 850.0
            std: 50.0
        duration_seconds: 120             # how long the scenario stays active
        ramp_up_seconds: 10               # gradual ramp before full override
    """
    path = Path(scenario_path)
    if not path.exists():
        raise FileNotFoundError(f"Scenario file not found: {path}")
    with open(path, "r") as f:
        scenario = yaml.safe_load(f)
    _validate_scenario(scenario)
    return scenario


def _validate_scenario(scenario: dict) -> None:
    required = {"name", "targets", "overrides"}
    missing = required - set(scenario.keys())
    if missing:
        raise ValueError(f"Scenario missing required keys: {missing}")
    for metric in scenario["overrides"]:
        if metric not in METRIC_BASELINES:
            raise ValueError(f"Unknown metric in scenario overrides: '{metric}'. "
                             f"Valid metrics: {list(METRIC_BASELINES.keys())}")


# ── Core simulator class ─────────────────────────────────────────────────────

class AWSSimulator:
    """
    Simulates AWS CloudWatch-style metrics for a fleet of instances.

    Usage:
        sim = AWSSimulator()
        
        # Normal metrics
        metrics = sim.get_metrics()
        
        # Inject a scenario
        sim.load_scenario("core/simulator/scenarios/cpu_spike.yaml")
        metrics = sim.get_metrics()
        
        # Get as DataFrame
        df = sim.get_metrics_dataframe()
        
        # Clear active scenario
        sim.clear_scenario()
    """

    def __init__(
        self,
        instances: Optional[list[dict]] = None,
        scenario_dir: str | Path = "core/simulator/scenarios",
        seed: Optional[int] = None,
    ):
        self.instances = instances or DEFAULT_INSTANCES
        self.scenario_dir = Path(scenario_dir)
        self._active_scenario: Optional[dict] = None
        self._scenario_start: Optional[float] = None

        if seed is not None:
            random.seed(seed)

    # ── Scenario management ──────────────────────────────────────────────────

    def load_scenario(self, scenario_path: str | Path) -> None:
        """Activate an anomaly scenario from a YAML file."""
        self._active_scenario = load_scenario(scenario_path)
        self._scenario_start = time.time()
        print(f"[AWSSimulator] Scenario loaded: '{self._active_scenario['name']}'")

    def load_scenario_by_name(self, name: str) -> None:
        """Load a scenario by filename stem from the default scenario directory."""
        path = self.scenario_dir / f"{name}.yaml"
        self.load_scenario(path)

    def clear_scenario(self) -> None:
        """Remove the active scenario, returning metrics to baseline."""
        if self._active_scenario:
            print(f"[AWSSimulator] Scenario cleared: '{self._active_scenario['name']}'")
        self._active_scenario = None
        self._scenario_start = None

    def is_scenario_active(self) -> bool:
        """Check if the scenario is still within its duration window."""
        if not self._active_scenario or not self._scenario_start:
            return False
        duration = self._active_scenario.get("duration_seconds", float("inf"))
        return (time.time() - self._scenario_start) < duration

    def _get_scenario_multiplier(self) -> float:
        """
        Returns a 0.0–1.0 ramp multiplier based on ramp_up_seconds.
        Full effect (1.0) after the ramp period.
        """
        if not self._active_scenario or not self._scenario_start:
            return 1.0
        ramp = self._active_scenario.get("ramp_up_seconds", 0)
        if ramp <= 0:
            return 1.0
        elapsed = time.time() - self._scenario_start
        return min(1.0, elapsed / ramp)

    def _scenario_targets_instance(self, instance: dict) -> bool:
        """Check if the active scenario targets a given instance."""
        if not self._active_scenario:
            return False
        targets = self._active_scenario.get("targets", {})
        if "instance_ids" in targets:
            return instance["id"] in targets["instance_ids"]
        if "services" in targets:
            return instance["service"] in targets["services"]
        if "all" in targets:
            return True
        return False

    # ── Metric generation ────────────────────────────────────────────────────

    def _generate_metric_value(
        self,
        metric: str,
        instance: dict,
        hour: int,
    ) -> float:
        """Generate a single metric value for one instance."""
        baseline = METRIC_BASELINES[metric].copy()

        # Apply diurnal pattern
        baseline["mean"] += _diurnal_offset(metric, hour)

        # Apply scenario override if this instance is targeted
        if self.is_scenario_active() and self._scenario_targets_instance(instance):
            overrides = self._active_scenario.get("overrides", {})
            if metric in overrides:
                multiplier = self._get_scenario_multiplier()
                override = overrides[metric]
                # Blend baseline → override based on ramp multiplier
                baseline["mean"] = (
                    baseline["mean"] * (1 - multiplier)
                    + override.get("mean", baseline["mean"]) * multiplier
                )
                baseline["std"] = override.get("std", baseline["std"])

        return _gaussian_noise(
            baseline["mean"],
            baseline["std"],
            baseline["min"],
            baseline["max"],
        )

    def get_metrics(self) -> list[dict]:
        """
        Generate one snapshot of metrics for all instances.

        Returns a list of metric records (one per instance × metric).
        Each record matches the CloudWatch PutMetricData shape:
            {
                "timestamp": "2026-04-02T10:00:00Z",
                "instance_id": "i-0aetherguard01",
                "instance_type": "m5.xlarge",
                "availability_zone": "us-east-1a",
                "service": "api-server",
                "metric": "cpu_utilization",
                "value": 38.4,
                "unit": "Percent",
                "anomaly_injected": False,
            }
        """
        now = datetime.now(timezone.utc)
        hour = now.hour
        records = []

        for instance in self.instances:
            is_targeted = self.is_scenario_active() and self._scenario_targets_instance(instance)

            for metric, meta in METRIC_BASELINES.items():
                value = self._generate_metric_value(metric, instance, hour)
                records.append({
                    "timestamp": now.isoformat(),
                    "instance_id": instance["id"],
                    "instance_type": instance["type"],
                    "availability_zone": instance["az"],
                    "service": instance["service"],
                    "metric": metric,
                    "value": value,
                    "unit": meta["unit"],
                    "anomaly_injected": is_targeted,
                    "active_scenario": self._active_scenario["name"] if is_targeted else None,
                })

        return records

    def get_metrics_dataframe(self) -> pd.DataFrame:
        """Return metrics snapshot as a Pandas DataFrame."""
        return pd.DataFrame(self.get_metrics())

    def get_metrics_json(self, indent: int = 2) -> str:
        """Return metrics snapshot as a formatted JSON string."""
        return json.dumps(self.get_metrics(), indent=indent)

    def stream_metrics(self, interval_seconds: float = 5.0, ticks: int = 10):
        """
        Generator that yields metric snapshots at a fixed interval.
        Useful for feeding the anomaly detector in real time.

        Usage:
            for snapshot in sim.stream_metrics(interval_seconds=5, ticks=20):
                df = pd.DataFrame(snapshot)
                detector.ingest(df)
        """
        for _ in range(ticks):
            yield self.get_metrics()
            time.sleep(interval_seconds)

    # ── Instance management ──────────────────────────────────────────────────

    def add_instance(self, instance_id: str, instance_type: str, az: str, service: str) -> None:
        """Dynamically add an instance to the fleet."""
        self.instances.append({
            "id": instance_id,
            "type": instance_type,
            "az": az,
            "service": service,
        })

    def remove_instance(self, instance_id: str) -> None:
        """Remove an instance from the fleet by ID."""
        self.instances = [i for i in self.instances if i["id"] != instance_id]

    def list_instances(self) -> list[dict]:
        """Return the current instance fleet."""
        return self.instances

    # ── Summary helpers ──────────────────────────────────────────────────────

    def get_summary(self) -> dict:
        """
        Return a high-level summary dict suitable for the dashboard.
        Aggregates mean values per metric across all instances.
        """
        df = self.get_metrics_dataframe()
        summary = df.groupby("metric")["value"].agg(["mean", "max", "min"]).round(2)
        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "instance_count": len(self.instances),
            "active_scenario": self._active_scenario["name"] if self.is_scenario_active() else None,
            "metrics": summary.to_dict(orient="index"),
        }

    def __repr__(self) -> str:
        scenario = self._active_scenario["name"] if self.is_scenario_active() else "none"
        return (
            f"AWSSimulator("
            f"instances={len(self.instances)}, "
            f"active_scenario={scenario!r})"
        )


# ── Quick demo ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=== AWSSimulator Demo ===\n")

    sim = AWSSimulator(seed=42)

    # 1. Baseline metrics
    print("── Baseline snapshot (DataFrame) ──")
    df = sim.get_metrics_dataframe()
    print(df[["instance_id", "service", "metric", "value", "unit"]].to_string(index=False))

    # 2. Summary
    print("\n── Summary ──")
    summary = sim.get_summary()
    print(json.dumps(summary, indent=2))

    # 3. Simulate scenario (inline dict, no file needed for demo)
    print("\n── Injecting inline CPU spike scenario ──")
    sim._active_scenario = {
        "name": "cpu_spike_demo",
        "targets": {"services": ["api-server"]},
        "overrides": {
            "cpu_utilization": {"mean": 94.0, "std": 2.0},
            "request_latency": {"mean": 900.0, "std": 60.0},
        },
        "duration_seconds": 60,
        "ramp_up_seconds": 0,
    }
    sim._scenario_start = time.time()

    df_anomaly = sim.get_metrics_dataframe()
    api_metrics = df_anomaly[df_anomaly["service"] == "api-server"][
        ["instance_id", "metric", "value", "anomaly_injected"]
    ]
    print(api_metrics.to_string(index=False))

    print("\n✅ AWSSimulator ready.")