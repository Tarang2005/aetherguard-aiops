"""
frontend/streamlit_app.py

AetherGuard MVP Streamlit Dashboard.
Multi-page app with real-time metrics, incident management,
chaos results, cost analysis, and agent conversation logs.

Run with:
    streamlit run frontend/streamlit_app.py
"""

from __future__ import annotations

import json
import time
from datetime import datetime
from typing import Any

import pandas as pd
import requests
import streamlit as st

# ── Config ────────────────────────────────────────────────────────────────────

API_BASE = "http://localhost:8000/api"
REFRESH_INTERVAL = 5  # seconds

st.set_page_config(
    page_title="AetherGuard AIOps",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Helpers ───────────────────────────────────────────────────────────────────

def api_get(path: str) -> dict | None:
    try:
        r = requests.get(f"{API_BASE}{path}", timeout=5)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        st.sidebar.error(f"API error: {e}")
        return None


def api_post(path: str, payload: dict = {}) -> dict | None:
    try:
        r = requests.post(f"{API_BASE}{path}", json=payload, timeout=30)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        st.error(f"API error: {e}")
        return None


def severity_badge(severity: str) -> str:
    colours = {
        "critical": "🔴",
        "high":     "🟠",
        "medium":   "🟡",
        "low":      "🟢",
    }
    return colours.get(severity or "", "⚪") + f" {(severity or 'unknown').upper()}"


def status_badge(status: str) -> str:
    icons = {
        "open":          "🆕",
        "investigating": "🔍",
        "pending":       "⏳",
        "remediating":   "🔧",
        "chaos":         "💥",
        "resolved":      "✅",
        "dismissed":     "❌",
    }
    return icons.get(status, "❓") + f" {status.upper()}"


def resilience_color(score: float) -> str:
    if score >= 85:
        return "🟢"
    if score >= 70:
        return "🟡"
    if score >= 50:
        return "🟠"
    return "🔴"


# ── Sidebar ───────────────────────────────────────────────────────────────────

with st.sidebar:
    st.image("https://img.shields.io/badge/AetherGuard-AIOps-blue?style=for-the-badge")
    st.markdown("---")

    page = st.radio(
        "Navigation",
        ["📊 Overview", "🚨 Incidents", "💥 Chaos Lab", "💰 Cost", "🤖 Agents"],
        label_visibility="collapsed",
    )

    st.markdown("---")
    st.markdown("**Quick Actions**")

    scenario = st.selectbox(
        "Scenario",
        ["cpu_spike", "pod_crash", "latency_flood", "port_exposure"],
    )

    auto_remediate = st.toggle("Auto-remediate", value=False)
    run_chaos      = st.toggle("Run chaos after", value=True)

    if st.button("🚀 Run Incident", use_container_width=True, type="primary"):
        with st.spinner("Running incident pipeline..."):
            result = api_post("/agents/run", {
                "scenario":       scenario,
                "auto_remediate": auto_remediate,
                "run_chaos":      run_chaos,
            })
            if result:
                st.success(f"✅ {result['incident_id']} — {result['status']}")
                st.rerun()

    st.markdown("---")
    st.caption(f"Refresh: every {REFRESH_INTERVAL}s")
    auto_refresh = st.toggle("Auto-refresh", value=False)


# ── Page: Overview ────────────────────────────────────────────────────────────

if page == "📊 Overview":
    st.title("🛡️ AetherGuard — Live Overview")

    # Top KPI row
    incidents_data = api_get("/dashboard/incidents")
    aws_data       = api_get("/dashboard/metrics/aws")
    net_data       = api_get("/dashboard/metrics/network")
    resilience_data = api_get("/dashboard/resilience")
    cost_data      = api_get("/dashboard/cost")

    incidents = incidents_data.get("incidents", []) if incidents_data else []
    open_inc  = [i for i in incidents if i["status"] not in ("resolved", "dismissed")]
    resolved  = [i for i in incidents if i["status"] == "resolved"]

    col1, col2, col3, col4, col5 = st.columns(5)
    col1.metric("Total Incidents",  len(incidents))
    col2.metric("Open",             len(open_inc),  delta=len(open_inc) or None, delta_color="inverse")
    col3.metric("Resolved",         len(resolved))

    if resilience_data and resilience_data.get("experiments"):
        scores = [e["resilience_score"] for e in resilience_data["experiments"] if e["resilience_score"]]
        avg_score = round(sum(scores) / len(scores), 1) if scores else 0
        col4.metric("Avg Resilience", f"{avg_score}/100")
    else:
        col4.metric("Avg Resilience", "—")

    if cost_data:
        col5.metric(
            "Cost Δ/hr",
            f"${cost_data['total_cost_delta_usd_per_hour']:+.3f}",
        )

    st.markdown("---")

    # AWS metrics chart
    col_aws, col_net = st.columns(2)

    with col_aws:
        st.subheader("☁️ AWS Metrics")
        if aws_data and aws_data.get("metrics"):
            df = pd.DataFrame(aws_data["metrics"])
            pivot = df.pivot_table(
                index="instance_id", columns="metric", values="value", aggfunc="mean"
            ).round(2)
            st.dataframe(pivot, use_container_width=True)

            # CPU chart
            cpu_df = df[df["metric"] == "cpu_utilization"][["instance_id", "value"]]
            if not cpu_df.empty:
                st.bar_chart(cpu_df.set_index("instance_id"), color="#FF6B6B")

    with col_net:
        st.subheader("🌐 Network Health")
        if net_data and net_data.get("metrics"):
            df = pd.DataFrame(net_data["metrics"])
            hs = df[["device_id", "device_type", "site", "health_score", "health_label"]]
            st.dataframe(hs, use_container_width=True)

            # Health score chart
            st.bar_chart(df.set_index("device_id")["health_score"], color="#4ECDC4")

    # Recent incidents table
    st.markdown("---")
    st.subheader("🚨 Recent Incidents")
    if incidents:
        rows = []
        for i in incidents[-10:][::-1]:
            rows.append({
                "ID":       i["incident_id"],
                "Status":   status_badge(i["status"]),
                "Severity": severity_badge(i["severity"]),
                "Title":    i.get("title") or "—",
                "Anomalies": i["anomaly_count"],
                "RCA":      "✅" if i["has_rca"] else "—",
                "Plan":     "✅" if i["has_plan"] else "—",
            })
        st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)
    else:
        st.info("No incidents yet. Run one from the sidebar →")


# ── Page: Incidents ───────────────────────────────────────────────────────────

elif page == "🚨 Incidents":
    st.title("🚨 Incident Management")

    incidents_data = api_get("/dashboard/incidents")
    incidents = incidents_data.get("incidents", []) if incidents_data else []

    if not incidents:
        st.info("No incidents yet. Use the sidebar to trigger one.")
    else:
        selected_id = st.selectbox(
            "Select incident",
            [i["incident_id"] for i in reversed(incidents)],
        )

        detail = api_get(f"/dashboard/incidents/{selected_id}")

        if detail:
            summary = detail["summary"]

            # Header row
            c1, c2, c3 = st.columns(3)
            c1.markdown(f"**Status:** {status_badge(summary['status'])}")
            c2.markdown(f"**Severity:** {severity_badge(summary['severity'])}")
            c3.markdown(f"**Anomalies:** {summary['anomaly_count']}")

            if summary.get("title"):
                st.info(f"📋 {summary['title']}")

            tab1, tab2, tab3, tab4, tab5 = st.tabs(
                ["🔍 Anomalies", "🧠 RCA", "🔧 Remediation", "💬 Agent Log", "📋 Audit"]
            )

            with tab1:
                anomalies = detail.get("anomalies", [])
                if anomalies:
                    df = pd.DataFrame(anomalies)
                    cols = ["metric", "entity_id", "service", "observed_value",
                            "anomaly_score", "severity", "source"]
                    st.dataframe(df[[c for c in cols if c in df.columns]],
                                 use_container_width=True, hide_index=True)
                else:
                    st.info("No anomalies detected.")

            with tab2:
                rca = detail.get("root_cause")
                if rca:
                    st.markdown(f"**Summary:** {rca['summary']}")
                    st.markdown(f"**Probable cause:** {rca['probable_cause']}")
                    st.markdown(f"**Confidence:** {rca['confidence']:.0%}")
                    with st.expander("Detailed analysis"):
                        st.write(rca["detailed_analysis"])
                    if rca.get("contributing_factors"):
                        st.markdown("**Contributing factors:**")
                        for f in rca["contributing_factors"]:
                            st.markdown(f"  - {f}")
                else:
                    st.info("RCA not yet generated.")

            with tab3:
                plan = detail.get("remediation_plan")
                if plan:
                    rec = plan["recommended"]
                    st.success(f"**Recommended:** `{rec['action']}` — {rec['description']}")
                    col1, col2, col3 = st.columns(3)
                    col1.metric("Cost Δ/hr", f"${rec['estimated_cost_delta_usd']:+.4f}")
                    col2.metric("Recovery ~", f"{rec['estimated_recovery_seconds']}s")
                    col3.metric("Risk", rec["risk_level"].upper())
                    st.markdown(f"**Rationale:** {plan['rationale']}")

                    # Approval buttons
                    approval = api_get(f"/approval/{selected_id}/status")
                    if approval and approval.get("has_gate"):
                        decision = approval.get("decision")
                        if decision is None:
                            st.warning("⏳ Awaiting human approval")
                            bc1, bc2 = st.columns(2)
                            if bc1.button("✅ Approve", type="primary", use_container_width=True):
                                api_post(f"/approval/{selected_id}/approve", {"decided_by": "dashboard_user"})
                                st.success("Approved!")
                                st.rerun()
                            if bc2.button("❌ Deny", use_container_width=True):
                                api_post(f"/approval/{selected_id}/deny", {"decided_by": "dashboard_user"})
                                st.error("Denied.")
                                st.rerun()
                        else:
                            st.info(f"Decision: {decision} by {approval.get('decided_by')}")
                else:
                    st.info("Remediation plan not yet generated.")

            with tab4:
                messages = detail.get("messages", [])
                for msg in messages:
                    agent = msg.get("agent", "system")
                    content = msg.get("content", "")
                    with st.chat_message(agent if agent != "system" else "assistant"):
                        st.markdown(content)

            with tab5:
                audit = detail.get("audit_log", [])
                if audit:
                    rows = [
                        {
                            "Time": e["timestamp"][11:19],
                            "Agent": e["agent"],
                            "Action": e["action"],
                            "✓": "✅" if e["success"] else "❌",
                        }
                        for e in audit
                    ]
                    st.dataframe(pd.DataFrame(rows), use_container_width=True, hide_index=True)


# ── Page: Chaos Lab ───────────────────────────────────────────────────────────

elif page == "💥 Chaos Lab":
    st.title("💥 Chaos Resilience Lab")

    resilience_data = api_get("/dashboard/resilience")
    experiments = resilience_data.get("experiments", []) if resilience_data else []

    if experiments:
        # Summary KPIs
        scores = [e["resilience_score"] for e in experiments if e["resilience_score"] is not None]
        det_times = [e["detection_time"] for e in experiments if e["detection_time"]]
        rec_times = [e["recovery_time"] for e in experiments if e["recovery_time"]]

        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Experiments Run", len(experiments))
        c2.metric("Avg Resilience", f"{sum(scores)/len(scores):.1f}/100" if scores else "—")
        c3.metric("Avg Detection", f"{sum(det_times)/len(det_times):.1f}s" if det_times else "—")
        c4.metric("Avg Recovery", f"{sum(rec_times)/len(rec_times):.1f}s" if rec_times else "—")

        st.markdown("---")

        # Resilience score chart
        st.subheader("Resilience Scores by Scenario")
        df = pd.DataFrame(experiments)
        if not df.empty and "resilience_score" in df.columns:
            chart_df = df[["scenario", "resilience_score"]].dropna()
            st.bar_chart(chart_df.set_index("scenario"), color="#9B59B6")

        # Full table
        st.subheader("All Experiments")
        display = df[["scenario", "target_service", "resilience_score",
                       "detection_time", "recovery_time"]].round(2)
        display.insert(0, "Score", display["resilience_score"].apply(
            lambda s: resilience_color(s) + f" {s}" if s else "—"
        ))
        st.dataframe(display, use_container_width=True, hide_index=True)

    else:
        st.info("No chaos experiments yet. Run an incident with 'Run chaos after' enabled.")

    # Manual injection
    st.markdown("---")
    st.subheader("🧪 Inject Scenario")
    col1, col2 = st.columns(2)
    inject_scenario = col1.selectbox(
        "Scenario", ["cpu_spike", "pod_crash", "latency_flood", "port_exposure"]
    )
    if col2.button("💉 Inject Now", type="primary", use_container_width=True):
        with st.spinner(f"Injecting {inject_scenario}..."):
            result = api_post("/chaos/inject", {
                "scenario": inject_scenario,
                "run_chaos": True,
            })
            if result and result.get("chaos_summary"):
                cs = result["chaos_summary"]
                st.success(
                    f"✅ Resilience score: **{cs['resilience_score']}/100** | "
                    f"Detection: {cs['detection_time']}s | "
                    f"Recovery: {cs['recovery_time']}s"
                )
                st.rerun()


# ── Page: Cost ────────────────────────────────────────────────────────────────

elif page == "💰 Cost":
    st.title("💰 Cost Optimization")

    cost_data = api_get("/dashboard/cost")

    if cost_data:
        c1, c2, c3 = st.columns(3)
        c1.metric("Total Cost Δ/hr",    f"${cost_data['total_cost_delta_usd_per_hour']:+.4f}")
        c2.metric("Projected Savings/mo", f"${cost_data['total_projected_savings_usd_monthly']:+.2f}")
        c3.metric("Actions Taken",        len(cost_data.get("actions", [])))

        st.markdown("---")

        actions = cost_data.get("actions", [])
        if actions:
            st.subheader("Remediation Actions & Cost Impact")
            df = pd.DataFrame(actions)
            df["cost_delta_usd"] = df["cost_delta_usd"].round(4)
            st.dataframe(df, use_container_width=True, hide_index=True)

            # Cost chart
            cost_chart = df.set_index("incident_id")["cost_delta_usd"]
            st.bar_chart(cost_chart, color="#F39C12")
        else:
            st.info("No remediation actions recorded yet.")
    else:
        st.info("No cost data available yet.")


# ── Page: Agents ──────────────────────────────────────────────────────────────

elif page == "🤖 Agents":
    st.title("🤖 Agent System Status")

    status = api_get("/agents/status")
    scenarios = api_get("/agents/scenarios")

    if status:
        c1, c2, c3 = st.columns(3)
        c1.metric("Status", status.get("status", "—").upper())
        c2.metric("Auto-remediate", "ON" if status.get("auto_remediate") else "OFF")
        c3.metric("Chaos enabled", "ON" if status.get("run_chaos") else "OFF")

        st.markdown("---")
        st.subheader("🔬 Anomaly Detector")
        detector = status.get("detector", {})
        dc1, dc2 = st.columns(2)
        dc1.metric("Tracked entity-metrics", detector.get("tracked_entities", 0))
        dc2.metric("Fitted models",          detector.get("fitted_models", 0))

    st.markdown("---")
    st.subheader("📋 Agent Pipeline")

    agents_info = [
        {"Agent": "Supervisor",           "Role": "Orchestrates the full pipeline, manages approval gates"},
        {"Agent": "Anomaly Detector",     "Role": "Isolation Forest ML — detects metric anomalies"},
        {"Agent": "Root Cause Analyst",   "Role": "Claude LLM — explains and correlates anomalies"},
        {"Agent": "Remediation Planner",  "Role": "Claude LLM — cost-aware action recommendation"},
        {"Agent": "Chaos Engineer",       "Role": "Injects failures, measures resilience score"},
    ]
    st.dataframe(pd.DataFrame(agents_info), use_container_width=True, hide_index=True)

    if scenarios:
        st.markdown("---")
        st.subheader("🎭 Available Scenarios")
        st.dataframe(pd.DataFrame(scenarios["scenarios"]), use_container_width=True, hide_index=True)


# ── Auto-refresh ──────────────────────────────────────────────────────────────

if auto_refresh:
    time.sleep(REFRESH_INTERVAL)
    st.rerun()