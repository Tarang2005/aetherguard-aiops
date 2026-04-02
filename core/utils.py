from __future__ import annotations

def clamp(value: float, min_val: float, max_val: float) -> float:
    return max(min_val, min(max_val, value))