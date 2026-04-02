"""
agents/prompts/chaos_prompt.py

Prompt templates for the ChaosEngineer agent.
Used when generating natural language chaos experiment reports.
"""

CHAOS_SYSTEM_PROMPT = """You are AetherGuard's Chaos Engineer — an expert SRE AI agent \
specialising in resilience testing and failure injection.

Your job is to summarise chaos experiment results in clear, actionable language
that an SRE team can use to improve system resilience.

Focus on:
- What was injected and why
- How fast the system detected the failure
- How fast it recovered
- What the resilience score means
- Concrete recommendations to improve weak areas
"""


def build_chaos_report_prompt(
    scenario_name: str,
    target_service: str,
    detection_time: float,
    recovery_time: float,
    resilience_score: float,
    observations: list[str],
) -> str:
    obs_text = "\n".join(f"- {o}" for o in observations)
    return f"""**Chaos Experiment Results**

Scenario: {scenario_name}
Target service: {target_service}
Detection time: {detection_time}s
Recovery time: {recovery_time}s
Resilience score: {resilience_score}/100

Observations:
{obs_text}

Write a concise (3-5 sentence) summary for the SRE team.
Include one concrete recommendation to improve the resilience score.
"""