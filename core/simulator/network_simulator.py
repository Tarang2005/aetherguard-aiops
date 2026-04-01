"""
core/simulator/network_simulator.py

Simulates Cisco DNAC-style network health metrics for AetherGuard.
- Models Switches, Routers, Wireless APs, WAN links, and Firewalls
- Generates realistic per-device health metrics with natural noise
- Supports YAML scenario injection (same pattern as aws_simulator)
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


# ── Device type definitions ──────────────────────────────────────────────────

DEVICE_TYPES = ["switch", "router", "wireless_ap", "wan_link", "firewall"]

# Baseline metric profiles per device type
# Values reflect realistic DNAC health score ranges
DEVICE_BASELINES = {
    "switch": {
        "cpu_load":          {"mean": 22.0,  "std": 4.0,  "min": 0.0,   "max": 100.0, "unit": "Percent"},
        "memory_load":       {"mean": 45.0,  "std": 5.0,  "min": 0.0,   "max": 100.0, "unit": "Percent"},
        "link_utilization":  {"mean": 35.0,  "std": 8.0,  "min": 0.0,   "max": 100.0, "unit": "Percent"},
        "packet_loss":       {"mean": 0.05,  "std": 0.02, "min": 0.0,   "max": 100.0, "unit": "Percent"},
        "reachability":      {"mean": 99.9,  "std": 0.05, "min": 0.0,   "max": 100.0, "unit": "Percent"},
        "interface_errors":  {"mean": 0.2,   "std": 0.1,  "min": 0.0,   "max": 10000.0,"unit": "Errors/min"},
    },
    "router": {
        "cpu_load":          {"mean": 30.0,  "std": 6.0,  "min": 0.0,   "max": 100.0, "unit": "Percent"},
        "memory_load":       {"mean": 52.0,  "std": 6.0,  "min": 0.0,   "max": 100.0, "unit": "Percent"},
        "link_utilization":  {"mean": 48.0,  "std": 10.0, "min": 0.0,   "max": 100.0, "unit": "Percent"},
        "packet_loss":       {"mean": 0.08,  "std": 0.03, "min": 0.0,   "max": 100.0, "unit": "Percent"},
        "reachability":      {"mean": 99.8,  "std": 0.08, "min": 0.0,   "max": 100.0, "unit": "Percent"},
        "interface_errors":  {"mean": 0.5,   "std": 0.2,  "min": 0.0,   "max": 10000.0,"unit": "Errors/min"},
    },
    "wireless_ap": {
        "cpu_load":          {"mean": 18.0,  "std": 3.0,  "min": 0.0,   "max": 100.0, "unit": "Percent"},
        "memory_load":       {"mean": 38.0,  "std": 4.0,  "min": 0.0,   "max": 100.0, "unit": "Percent"},
        "link_utilization":  {"mean": 42.0,  "std": 12.0, "min": 0.0,   "max": 100.0, "unit": "Percent"},
        "packet_loss":       {"mean": 0.3,   "std": 0.1,  "min": 0.0,   "max": 100.0, "unit": "Percent"},
        "reachability":      {"mean": 99.5,  "std": 0.2,  "min": 0.0,   "max": 100.0, "unit": "Percent"},
        "interface_errors":  {"mean": 1.2,   "std": 0.4,  "min": 0.0,   "max": 10000.0,"unit": "Errors/min"},
    },
    "wan_link": {
        "cpu_load":          {"mean": 10.0,  "std": 2.0,  "min": 0.0,   "max": 100.0, "unit": "Percent"},
        "memory_load":       {"mean": 28.0,  "std": 3.0,  "min": 0.0,   "max": 100.0, "unit": "Percent"},
        "link_utilization":  {"mean": 58.0,  "std": 12.0, "min": 0.0,   "max": 100.0, "unit": "Percent"},
        "packet_loss":       {"mean": 0.15,  "std": 0.05, "min": 0.0,   "max": 100.0, "unit": "Percent"},
        "reachability":      {"mean": 99.7,  "std": 0.1,  "min": 0.0,   "max": 100.0, "unit": "Percent"},
        "interface_errors":  {"mean": 0.8,   "std": 0.3,  "min": 0.0,   "max": 10000.0,"unit": "Errors/min"},
    },
    "firewall": {
        "cpu_load":          {"mean": 40.0,  "std": 7.0,  "min": 0.0,   "max": 100.0, "unit": "Percent"},
        "memory_load":       {"mean": 60.0,  "std": 6.0,  "min": 0.0,   "max": 100.0, "unit": "Percent"},
        "link_utilization":  {"mean": 45.0,  "std": 10.0, "min": 0.0,   "max": 100.0, "unit": "Percent"},
        "packet_loss":       {"mean": 0.02,  "std": 0.01, "min": 0.0,   "max": 100.0, "unit": "Percent"},
        "reachability":      {"mean": 100.0, "std": 0.01, "min": 0.0,   "max": 100.0, "unit": "Percent"},
        "interface_errors":  {"mean": 0.1,   "std": 0.05, "min": 0.0,   "max": 10000.0,"unit": "Errors/min"},
    },
}

# DNAC health score thresholds (mirrors real DNAC scoring)
HEALTH_THRESHOLDS = {
    "good":  90.0,   # green
    "fair":  70.0,   # yellow
    # below fair = poor (red)
}


# ── Default device fleet ─────────────────────────────────────────────────────

DEFAULT_DEVICES = [
    # Switches
    {"id": "SW-CORE-01",  "type": "switch",      "site": "HQ",      "location": "DC-Floor1", "vendor": "Cisco Catalyst 9300"},
    {"id": "SW-CORE-02",  "type": "switch",      "site": "HQ",      "location": "DC-Floor1", "vendor": "Cisco Catalyst 9300"},
    {"id": "SW-ACCESS-01","type": "switch",      "site": "Branch-A","location": "IDF-Room",  "vendor": "Cisco Catalyst 9200"},
    # Routers
    {"id": "RTR-EDGE-01", "type": "router",      "site": "HQ",      "location": "DC-Floor1", "vendor": "Cisco ISR 4451"},
    {"id": "RTR-EDGE-02", "type": "router",      "site": "Branch-A","location": "MDF-Room",  "vendor": "Cisco ISR 4331"},
    # Wireless APs
    {"id": "AP-HQ-01",    "type": "wireless_ap", "site": "HQ",      "location": "Floor-2",   "vendor": "Cisco Catalyst 9130"},
    {"id": "AP-HQ-02",    "type": "wireless_ap", "site": "HQ",      "location": "Floor-3",   "vendor": "Cisco Catalyst 9130"},
    {"id": "AP-BR-01",    "type": "wireless_ap", "site": "Branch-A","location": "Open-Office","vendor": "Cisco Aironet 2800"},
    # WAN links
    {"id": "WAN-HQ-ISP1", "type": "wan_link",    "site": "HQ",      "location": "DC-Floor1", "vendor": "ISP-Primary"},
    {"id": "WAN-HQ-ISP2", "type": "wan_link",    "site": "HQ",      "location": "DC-Floor1", "vendor": "ISP-Backup"},
    # Firewalls
    {"id": "FW-PERIMETER","type": "firewall",    "site": "HQ",      "location": "DC-Floor1", "vendor": "Cisco Firepower 2140"},
    {"id": "FW-BRANCH-A", "type": "firewall",    "site": "Branch-A","location": "MDF-Room",  "vendor": "Cisco Firepower 1120"},
]


# ── Noise + health helpers ───────────────────────────────────────────────────

def _gaussian_noise(mean: float, std: float, min_val: float, max_val: float) -> float:
    value = random.gauss(mean, std)
    return round(max(min_val, min(max_val, value)), 4)


def _diurnal_offset(metric: str, device_type: str, hour: int) -> float:
    """
    Realistic time-of-day variation per device type.
    - Office APs peak during business hours (client density).
    - WAN links peak at midday and early evening.
    - Firewalls stay relatively flat (always on).
    """
    if device_type == "wireless_ap" and metric in ("cpu_load", "link_utilization"):
        # Strong business-hours peak for APs
        return 25.0 * math.sin(math.pi * max(0, hour - 7) / 11) if 7 <= hour <= 18 else 0.0
    if device_type == "wan_link" and metric == "link_utilization":
        return 20.0 * math.sin(math.pi * max(0, hour - 8) / 14) if 8 <= hour <= 22 else 0.0
    if device_type in ("switch", "router") and metric == "cpu_load":
        return 10.0 * math.sin(math.pi * max(0, hour - 8) / 12) if 8 <= hour <= 20 else 0.0
    return 0.0


def _compute_health_score(metrics: dict) -> float:
    """
    Compute a DNAC-style composite health score (0–100).
    Weighted average penalising high packet loss, low reachability,
    high CPU/memory, and interface errors most heavily.
    """
    weights = {
        "reachability":     0.35,
        "packet_loss":      0.25,  # inverted: high loss = low score
        "cpu_load":         0.15,  # inverted
        "memory_load":      0.10,  # inverted
        "link_utilization": 0.10,  # inverted
        "interface_errors": 0.05,  # inverted, normalised to 0-100
    }
    score = 0.0
    score += weights["reachability"] * metrics["reachability"]
    score += weights["packet_loss"]  * max(0.0, 100.0 - metrics["packet_loss"] * 100)
    score += weights["cpu_load"]     * (100.0 - metrics["cpu_load"])
    score += weights["memory_load"]  * (100.0 - metrics["memory_load"])
    score += weights["link_utilization"] * (100.0 - metrics["link_utilization"])
    # Normalise interface errors: 0 errors = 100, 100+ errors = 0
    err_score = max(0.0, 100.0 - metrics["interface_errors"])
    score += weights["interface_errors"] * err_score
    return round(min(100.0, max(0.0, score)), 2)


def _health_label(score: float) -> str:
    if score >= HEALTH_THRESHOLDS["good"]:
        return "good"
    if score >= HEALTH_THRESHOLDS["fair"]:
        return "fair"
    return "poor"


# ── Scenario loader (mirrors aws_simulator) ──────────────────────────────────

def load_scenario(scenario_path: str | Path) -> dict:
    """
    Load a network chaos scenario from YAML.

    Expected YAML structure:
        name: wan_degradation
        description: "WAN link packet loss spike"
        targets:
          device_types: [wan_link]        # or device_ids: [WAN-HQ-ISP1]
          sites: [HQ]                     # optional site filter
        overrides:
          packet_loss:
            mean: 12.0
            std: 2.0
          link_utilization:
            mean: 95.0
            std: 3.0
        duration_seconds: 180
        ramp_up_seconds: 10
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
    all_metrics = set(next(iter(DEVICE_BASELINES.values())).keys())
    for metric in scenario["overrides"]:
        if metric not in all_metrics:
            raise ValueError(
                f"Unknown metric in scenario overrides: '{metric}'. "
                f"Valid metrics: {sorted(all_metrics)}"
            )


# ── Core simulator class ─────────────────────────────────────────────────────

class NetworkSimulator:
    """
    Simulates Cisco DNAC-style network health for a fleet of devices.

    Usage:
        sim = NetworkSimulator()

        # Normal snapshot
        metrics = sim.get_metrics()

        # Inject a scenario
        sim.load_scenario_by_name("wan_degradation")
        df = sim.get_metrics_dataframe()

        # DNAC-style health summary
        summary = sim.get_health_summary()

        # Clear scenario
        sim.clear_scenario()
    """

    def __init__(
        self,
        devices: Optional[list[dict]] = None,
        scenario_dir: str | Path = "core/simulator/scenarios",
        seed: Optional[int] = None,
    ):
        self.devices = devices or DEFAULT_DEVICES
        self.scenario_dir = Path(scenario_dir)
        self._active_scenario: Optional[dict] = None
        self._scenario_start: Optional[float] = None

        if seed is not None:
            random.seed(seed)

    # ── Scenario management ──────────────────────────────────────────────────

    def load_scenario(self, scenario_path: str | Path) -> None:
        """Activate a network anomaly scenario from a YAML file."""
        self._active_scenario = load_scenario(scenario_path)
        self._scenario_start = time.time()
        print(f"[NetworkSimulator] Scenario loaded: '{self._active_scenario['name']}'")

    def load_scenario_by_name(self, name: str) -> None:
        """Load by filename stem from the default scenario directory."""
        self.load_scenario(self.scenario_dir / f"{name}.yaml")

    def clear_scenario(self) -> None:
        if self._active_scenario:
            print(f"[NetworkSimulator] Scenario cleared: '{self._active_scenario['name']}'")
        self._active_scenario = None
        self._scenario_start = None

    def is_scenario_active(self) -> bool:
        if not self._active_scenario or not self._scenario_start:
            return False
        duration = self._active_scenario.get("duration_seconds", float("inf"))
        return (time.time() - self._scenario_start) < duration

    def _get_scenario_multiplier(self) -> float:
        if not self._active_scenario or not self._scenario_start:
            return 1.0
        ramp = self._active_scenario.get("ramp_up_seconds", 0)
        if ramp <= 0:
            return 1.0
        elapsed = time.time() - self._scenario_start
        return min(1.0, elapsed / ramp)

    def _scenario_targets_device(self, device: dict) -> bool:
        if not self._active_scenario:
            return False
        targets = self._active_scenario.get("targets", {})
        # Check device ID match
        if "device_ids" in targets and device["id"] in targets["device_ids"]:
            return True
        # Check device type match
        type_match = "device_types" not in targets or device["type"] in targets["device_types"]
        # Check site match
        site_match = "sites" not in targets or device["site"] in targets["sites"]
        # all: true overrides everything
        if "all" in targets:
            return True
        return type_match and site_match and ("device_types" in targets or "sites" in targets)

    # ── Metric generation ────────────────────────────────────────────────────

    def _generate_device_metrics(self, device: dict, hour: int) -> dict:
        """Generate all metrics for a single device."""
        device_type = device["type"]
        baselines = DEVICE_BASELINES[device_type]
        result = {}

        for metric, meta in baselines.items():
            baseline = meta.copy()
            baseline["mean"] += _diurnal_offset(metric, device_type, hour)

            # Apply scenario override
            if self.is_scenario_active() and self._scenario_targets_device(device):
                overrides = self._active_scenario.get("overrides", {})
                if metric in overrides:
                    m = self._get_scenario_multiplier()
                    override = overrides[metric]
                    baseline["mean"] = (
                        baseline["mean"] * (1 - m)
                        + override.get("mean", baseline["mean"]) * m
                    )
                    baseline["std"] = override.get("std", baseline["std"])

            result[metric] = _gaussian_noise(
                baseline["mean"],
                baseline["std"],
                baseline["min"],
                baseline["max"],
            )

        return result

    # ── Public output methods ────────────────────────────────────────────────

    def get_metrics(self) -> list[dict]:
        """
        Generate one snapshot of health metrics for all devices.

        Each record mirrors the Cisco DNAC Device Health API shape:
            {
                "timestamp": "2026-04-02T10:00:00Z",
                "device_id": "SW-CORE-01",
                "device_type": "switch",
                "site": "HQ",
                "location": "DC-Floor1",
                "vendor": "Cisco Catalyst 9300",
                "cpu_load": 24.3,
                "memory_load": 46.1,
                "link_utilization": 33.8,
                "packet_loss": 0.04,
                "reachability": 99.9,
                "interface_errors": 0.2,
                "health_score": 95.4,
                "health_label": "good",
                "anomaly_injected": False,
                "active_scenario": None,
            }
        """
        now = datetime.now(timezone.utc)
        hour = now.hour
        records = []

        for device in self.devices:
            is_targeted = (
                self.is_scenario_active()
                and self._scenario_targets_device(device)
            )
            metrics = self._generate_device_metrics(device, hour)
            health_score = _compute_health_score(metrics)

            record = {
                "timestamp": now.isoformat(),
                "device_id": device["id"],
                "device_type": device["type"],
                "site": device["site"],
                "location": device["location"],
                "vendor": device["vendor"],
                **metrics,
                "health_score": health_score,
                "health_label": _health_label(health_score),
                "anomaly_injected": is_targeted,
                "active_scenario": (
                    self._active_scenario["name"] if is_targeted else None
                ),
            }
            records.append(record)

        return records

    def get_metrics_dataframe(self) -> pd.DataFrame:
        """Return metrics snapshot as a Pandas DataFrame."""
        return pd.DataFrame(self.get_metrics())

    def get_metrics_json(self, indent: int = 2) -> str:
        """Return metrics snapshot as a formatted JSON string."""
        return json.dumps(self.get_metrics(), indent=indent)

    def get_health_summary(self) -> dict:
        """
        Return a DNAC-style health summary — device counts per health label,
        per device type, and overall network health score.
        """
        df = self.get_metrics_dataframe()
        overall_score = round(df["health_score"].mean(), 2)

        by_type = (
            df.groupby("device_type")["health_score"]
            .agg(["mean", "min", "count"])
            .round(2)
            .rename(columns={"mean": "avg_health", "min": "worst_health", "count": "device_count"})
            .to_dict(orient="index")
        )

        label_counts = df["health_label"].value_counts().to_dict()

        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "overall_health_score": overall_score,
            "overall_health_label": _health_label(overall_score),
            "device_count": len(self.devices),
            "active_scenario": (
                self._active_scenario["name"] if self.is_scenario_active() else None
            ),
            "health_distribution": {
                "good": label_counts.get("good", 0),
                "fair": label_counts.get("fair", 0),
                "poor": label_counts.get("poor", 0),
            },
            "by_device_type": by_type,
        }

    def stream_metrics(self, interval_seconds: float = 5.0, ticks: int = 10):
        """
        Generator yielding metric snapshots on a fixed interval.
        Same interface as AWSSimulator.stream_metrics for unified ingestion.
        """
        for _ in range(ticks):
            yield self.get_metrics()
            time.sleep(interval_seconds)

    # ── Device management ────────────────────────────────────────────────────

    def add_device(
        self,
        device_id: str,
        device_type: str,
        site: str,
        location: str,
        vendor: str,
    ) -> None:
        if device_type not in DEVICE_TYPES:
            raise ValueError(
                f"Invalid device_type '{device_type}'. Must be one of: {DEVICE_TYPES}"
            )
        self.devices.append({
            "id": device_id,
            "type": device_type,
            "site": site,
            "location": location,
            "vendor": vendor,
        })

    def remove_device(self, device_id: str) -> None:
        self.devices = [d for d in self.devices if d["id"] != device_id]

    def list_devices(self) -> list[dict]:
        return self.devices

    def __repr__(self) -> str:
        scenario = (
            self._active_scenario["name"] if self.is_scenario_active() else "none"
        )
        return (
            f"NetworkSimulator("
            f"devices={len(self.devices)}, "
            f"active_scenario={scenario!r})"
        )


# ── Quick demo ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=== NetworkSimulator Demo ===\n")

    sim = NetworkSimulator(seed=42)

    # 1. Baseline snapshot
    print("── Baseline snapshot (DataFrame) ──")
    df = sim.get_metrics_dataframe()
    print(df[[
        "device_id", "device_type", "site",
        "cpu_load", "packet_loss", "health_score", "health_label"
    ]].to_string(index=False))

    # 2. DNAC health summary
    print("\n── DNAC Health Summary ──")
    summary = sim.get_health_summary()
    print(json.dumps(summary, indent=2))

    # 3. Inject inline WAN degradation scenario
    print("\n── Injecting WAN degradation scenario ──")
    sim._active_scenario = {
        "name": "wan_degradation_demo",
        "targets": {"device_types": ["wan_link"]},
        "overrides": {
            "packet_loss":      {"mean": 14.0, "std": 2.5},
            "link_utilization": {"mean": 96.0, "std": 2.0},
            "interface_errors": {"mean": 85.0, "std": 10.0},
        },
        "duration_seconds": 60,
        "ramp_up_seconds": 0,
    }
    sim._scenario_start = time.time()

    df_anomaly = sim.get_metrics_dataframe()
    wan = df_anomaly[df_anomaly["device_type"] == "wan_link"][[
        "device_id", "packet_loss", "link_utilization",
        "health_score", "health_label", "anomaly_injected"
    ]]
    print(wan.to_string(index=False))

    print("\n── Health summary during scenario ──")
    print(json.dumps(sim.get_health_summary(), indent=2))

    print("\n NetworkSimulator ready.")