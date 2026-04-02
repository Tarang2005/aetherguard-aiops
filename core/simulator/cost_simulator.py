from __future__ import annotations
from typing import Any

EC2_PRICING: dict[str, float] = {
    "t3.medium":   0.0416,
    "t3.large":    0.0832,
    "m5.large":    0.096,
    "m5.xlarge":   0.192,
    "m5.2xlarge":  0.384,
    "m5.4xlarge":  0.768,
    "c5.xlarge":   0.17,
    "c5.2xlarge":  0.34,
    "r5.large":    0.126,
    "r5.xlarge":   0.252,
}

WAF_RULE_HOURLY_USD = 1.00 / 730
FARGATE_MEMORY_GB_HOUR = 0.004445


class CostSimulator:
    def scale_out_cost(self, instance_type: str = "m5.xlarge", instance_count: int = 2) -> float:
        return round(EC2_PRICING.get(instance_type, 0.192) * instance_count, 4)

    def scale_up_cost(self, from_type: str, to_type: str) -> float:
        return round(EC2_PRICING.get(to_type, 0.384) - EC2_PRICING.get(from_type, 0.192), 4)

    def memory_increase_cost(self, from_gi: int, to_gi: int) -> float:
        return round((to_gi - from_gi) * FARGATE_MEMORY_GB_HOUR, 4)

    def waf_rule_cost(self) -> float:
        return round(WAF_RULE_HOURLY_USD, 4)

    def analyse(self, recommended: dict[str, Any], alternatives: list[dict[str, Any]]) -> dict[str, Any]:
        all_options = [recommended] + alternatives
        costs = {o["action"]: o.get("estimated_cost_delta_usd", 0.0) for o in all_options}
        return {
            "recommended_cost_delta_usd_per_hour": recommended.get("estimated_cost_delta_usd", 0.0),
            "cheapest_option": min(costs, key=costs.get),
            "most_expensive_option": max(costs, key=costs.get),
            "cost_breakdown": costs,
            "monthly_projection_usd": round(recommended.get("estimated_cost_delta_usd", 0.0) * 730, 2),
        }