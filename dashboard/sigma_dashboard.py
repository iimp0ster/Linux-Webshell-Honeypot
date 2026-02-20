"""
Sigma Detection Lab Dashboard
Streamlit application for analyzing webshell honeypot telemetry and managing Sigma rules.
"""

import os
import json
import hashlib
import glob
from datetime import datetime
from pathlib import Path

import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import yaml

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

LOG_DIR = "/logs/honeypot"
UPLOAD_LOG = os.path.join(LOG_DIR, "uploads.log")
SIGMA_RULES_DIR = "/sigma_rules"
SAMPLES_DIR = "/samples"
UPLOADS_DIR = "/uploads"
HOST_AUDIT_LOG = "/host_audit/audit.log"
HOST_SYSLOG = "/host_syslog"

DASHBOARD_PASSWORD = os.environ.get("DASHBOARD_PASSWORD", "ChangeMe123!")


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------

def check_password() -> bool:
    """Simple password gate using session state."""
    if st.session_state.get("authenticated"):
        return True

    st.set_page_config(page_title="Sigma Detection Lab", page_icon="🛡️", layout="centered")
    st.title("🛡️ Sigma Detection Lab")
    st.subheader("Dashboard Login")

    password = st.text_input("Password", type="password", key="login_password")
    if st.button("Login"):
        if hashlib.sha256(password.encode()).hexdigest() == hashlib.sha256(DASHBOARD_PASSWORD.encode()).hexdigest():
            st.session_state["authenticated"] = True
            st.rerun()
        else:
            st.error("Incorrect password.")
    return False


# ---------------------------------------------------------------------------
# Data loading helpers
# ---------------------------------------------------------------------------

def load_upload_logs() -> pd.DataFrame:
    """Parse the NDJSON upload log into a DataFrame."""
    rows = []
    if not os.path.exists(UPLOAD_LOG):
        return pd.DataFrame()

    with open(UPLOAD_LOG, "r", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                pass  # skip malformed lines

    if not rows:
        return pd.DataFrame()

    df = pd.DataFrame(rows)
    if "timestamp" in df.columns:
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
    if "size" in df.columns:
        df["size"] = pd.to_numeric(df["size"], errors="coerce").fillna(0).astype(int)
    return df


def load_sigma_rules() -> dict:
    """Load all Sigma YAML rules from the rules directory."""
    rules = {}
    if not os.path.isdir(SIGMA_RULES_DIR):
        return rules
    for path in sorted(Path(SIGMA_RULES_DIR).glob("*.yml")):
        try:
            with open(path, "r") as fh:
                rules[path.name] = {"path": str(path), "content": fh.read(), "parsed": yaml.safe_load(fh.read() or "")}
        except Exception as exc:
            rules[path.name] = {"path": str(path), "content": f"# Error reading file: {exc}", "parsed": None}
    return rules


def load_uploaded_files() -> list:
    """List files in the uploads directory."""
    if not os.path.isdir(UPLOADS_DIR):
        return []
    entries = []
    for p in sorted(Path(UPLOADS_DIR).iterdir()):
        if p.is_file():
            stat = p.stat()
            entries.append({
                "name": p.name,
                "size": stat.st_size,
                "modified": datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
                "extension": p.suffix.lower(),
            })
    return entries


def load_sample_webshells() -> list:
    """Load sample webshell source code for educational display."""
    shells = []
    if not os.path.isdir(SAMPLES_DIR):
        return shells
    for p in sorted(Path(SAMPLES_DIR).glob("*.php")):
        try:
            shells.append({"name": p.name, "content": p.read_text(errors="replace")})
        except Exception:
            pass
    return shells


def tail_log(path: str, lines: int = 200) -> str:
    """Return the last N lines of a log file."""
    if not os.path.exists(path):
        return f"Log file not found: {path}"
    try:
        with open(path, "r", errors="replace") as fh:
            all_lines = fh.readlines()
        return "".join(all_lines[-lines:])
    except PermissionError:
        return f"Permission denied reading: {path}"


# ---------------------------------------------------------------------------
# Page renderers
# ---------------------------------------------------------------------------

def page_overview(df: pd.DataFrame) -> None:
    st.header("📊 Attack Overview")

    # --- Metrics row ---
    total_uploads = len(df)
    unique_ips = df["ip"].nunique() if "ip" in df.columns and total_uploads else 0
    php_uploads = df[df["filename"].str.lower().str.endswith(".php")].shape[0] if "filename" in df.columns and total_uploads else 0
    today_uploads = df[df["timestamp"].dt.date == datetime.utcnow().date()].shape[0] if "timestamp" in df.columns and total_uploads else 0

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Total Uploads", total_uploads)
    c2.metric("Unique Attacker IPs", unique_ips)
    c3.metric("PHP Files Uploaded", php_uploads)
    c4.metric("Uploads Today", today_uploads)

    if df.empty:
        st.info("No upload telemetry yet. The honeypot is waiting for attackers.")
        return

    st.divider()

    # --- Timeline ---
    if "timestamp" in df.columns:
        st.subheader("Upload Timeline")
        timeline = df.dropna(subset=["timestamp"]).set_index("timestamp").resample("1h").size().reset_index()
        timeline.columns = ["hour", "count"]
        fig = px.bar(timeline, x="hour", y="count", title="Uploads per Hour", labels={"count": "Uploads", "hour": "Time"})
        st.plotly_chart(fig, use_container_width=True)

    col_a, col_b = st.columns(2)

    # --- Top IPs ---
    if "ip" in df.columns:
        with col_a:
            st.subheader("Top Attacker IPs")
            top_ips = df["ip"].value_counts().head(10).reset_index()
            top_ips.columns = ["IP Address", "Count"]
            fig2 = px.bar(top_ips, x="Count", y="IP Address", orientation="h", title="Top 10 Source IPs")
            fig2.update_layout(yaxis={"categoryorder": "total ascending"})
            st.plotly_chart(fig2, use_container_width=True)

    # --- File extensions ---
    if "filename" in df.columns:
        with col_b:
            st.subheader("File Extensions")
            exts = df["filename"].apply(lambda f: Path(str(f)).suffix.lower() or "(none)").value_counts().head(10).reset_index()
            exts.columns = ["Extension", "Count"]
            fig3 = px.pie(exts, names="Extension", values="Count", title="File Types Uploaded")
            st.plotly_chart(fig3, use_container_width=True)

    # --- User-Agent breakdown ---
    if "user_agent" in df.columns:
        st.subheader("Top User-Agents")
        ua_counts = df["user_agent"].fillna("(empty)").value_counts().head(10).reset_index()
        ua_counts.columns = ["User-Agent", "Count"]
        st.dataframe(ua_counts, use_container_width=True)


def page_upload_log(df: pd.DataFrame) -> None:
    st.header("📋 Upload Log")

    if df.empty:
        st.info("No uploads recorded yet.")
        return

    # Filters
    col1, col2 = st.columns(2)
    with col1:
        ip_filter = st.text_input("Filter by IP", "")
    with col2:
        ext_filter = st.text_input("Filter by extension (e.g. .php)", "")

    filtered = df.copy()
    if ip_filter and "ip" in filtered.columns:
        filtered = filtered[filtered["ip"].str.contains(ip_filter, na=False)]
    if ext_filter and "filename" in filtered.columns:
        filtered = filtered[filtered["filename"].str.lower().str.endswith(ext_filter.lower())]

    st.write(f"Showing {len(filtered):,} of {len(df):,} records")
    display_cols = [c for c in ["timestamp", "ip", "filename", "size", "type", "user_agent", "x_forwarded_for", "referer"] if c in filtered.columns]
    st.dataframe(filtered[display_cols].sort_values("timestamp", ascending=False) if "timestamp" in display_cols else filtered[display_cols],
                 use_container_width=True)


def page_uploaded_files() -> None:
    st.header("📂 Captured Webshells")
    files = load_uploaded_files()

    if not files:
        st.info("No files in the uploads directory yet.")
        return

    df_files = pd.DataFrame(files)
    php_count = df_files[df_files["extension"] == ".php"].shape[0]
    st.metric("Total Captured Files", len(files), f"{php_count} PHP files")

    # Highlight PHP files
    st.dataframe(df_files, use_container_width=True)

    # Read a selected file
    selected = st.selectbox("Inspect file content", ["(select a file)"] + [f["name"] for f in files])
    if selected != "(select a file)":
        file_path = os.path.join(UPLOADS_DIR, selected)
        try:
            content = Path(file_path).read_text(errors="replace")
            st.subheader(f"Content of {selected}")
            ext = Path(selected).suffix.lower()
            lang = "php" if ext == ".php" else "text"
            st.code(content, language=lang)
        except Exception as exc:
            st.error(f"Cannot read file: {exc}")


def page_sigma_rules() -> None:
    st.header("📏 Sigma Detection Rules")
    rules = load_sigma_rules()

    if not rules:
        st.warning(f"No Sigma rules found in `{SIGMA_RULES_DIR}`.")
        return

    for filename, rule_data in rules.items():
        parsed = rule_data.get("parsed") or {}
        title = parsed.get("title", filename) if isinstance(parsed, dict) else filename
        level = (parsed.get("level", "unknown") if isinstance(parsed, dict) else "unknown").upper()
        level_color = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(level, "⚪")

        with st.expander(f"{level_color} [{level}] {title}"):
            if isinstance(parsed, dict):
                col1, col2 = st.columns(2)
                col1.write(f"**Status:** {parsed.get('status', 'N/A')}")
                col2.write(f"**Author:** {parsed.get('author', 'N/A')}")
                st.write(f"**Description:** {parsed.get('description', 'N/A')}")

                tags = parsed.get("tags", [])
                if tags:
                    st.write("**MITRE ATT&CK Tags:** " + ", ".join(f"`{t}`" for t in tags))

            st.code(rule_data["content"], language="yaml")


def page_sigma_editor() -> None:
    st.header("✏️ Sigma Rule Editor")
    st.info("Write new Sigma rules and save them to the rules directory.")

    rule_template = """\
title: New Detection Rule
id: 00000000-0000-0000-0000-000000000000
status: experimental
description: Describe what this rule detects
author: Your Name
date: {date}
logsource:
    product: linux
    category: process_creation
detection:
    selection:
        Image|endswith:
            - '/bash'
            - '/sh'
    condition: selection
falsepositives:
    - Legitimate admin tasks
level: medium
tags:
    - attack.execution
    - attack.t1059.004
""".format(date=datetime.utcnow().strftime("%Y/%m/%d"))

    filename = st.text_input("Rule filename (without .yml)", "new_rule")
    content = st.text_area("Rule YAML", value=rule_template, height=400)

    col1, col2 = st.columns(2)
    with col1:
        if st.button("Validate YAML"):
            try:
                parsed = yaml.safe_load(content)
                required = ["title", "id", "status", "logsource", "detection", "condition"]
                missing = [f for f in ["title", "id", "status", "logsource", "detection"] if f not in parsed]
                if missing:
                    st.warning(f"Missing recommended fields: {', '.join(missing)}")
                else:
                    st.success("Valid YAML with all required fields present.")
            except yaml.YAMLError as exc:
                st.error(f"YAML parse error: {exc}")

    with col2:
        if st.button("Save Rule"):
            if not filename.replace("_", "").replace("-", "").isalnum():
                st.error("Filename must be alphanumeric (underscores and hyphens allowed).")
            else:
                out_path = os.path.join(SIGMA_RULES_DIR, f"{filename}.yml")
                try:
                    yaml.safe_load(content)  # validate before saving
                    with open(out_path, "w") as fh:
                        fh.write(content)
                    st.success(f"Saved to {out_path}")
                except yaml.YAMLError as exc:
                    st.error(f"Cannot save — YAML error: {exc}")
                except PermissionError:
                    st.error(f"Permission denied writing to {out_path}. Check volume mount.")


def page_sample_webshells() -> None:
    st.header("🔬 Sample Webshell Analysis")
    st.info("These are reference samples for developing detection signatures — do NOT deploy on production systems.")
    shells = load_sample_webshells()

    if not shells:
        st.warning(f"No sample webshells found in `{SAMPLES_DIR}`.")
        return

    for shell in shells:
        with st.expander(f"📄 {shell['name']}"):
            st.code(shell["content"], language="php")


def page_raw_logs() -> None:
    st.header("📜 Raw System Logs")
    log_choice = st.selectbox("Select log source", [
        "Honeypot Upload Log (JSON)",
        "Host Audit Log (auditd)",
        "Host Syslog",
    ])

    line_count = st.slider("Lines to show", 50, 500, 100, step=50)

    if log_choice == "Honeypot Upload Log (JSON)":
        content = tail_log(UPLOAD_LOG, line_count)
    elif log_choice == "Host Audit Log (auditd)":
        content = tail_log(HOST_AUDIT_LOG, line_count)
    else:
        content = tail_log(HOST_SYSLOG, line_count)

    st.text_area("Log output", value=content, height=500)


# ---------------------------------------------------------------------------
# Main app
# ---------------------------------------------------------------------------

def main() -> None:
    if not check_password():
        return

    st.set_page_config(
        page_title="Sigma Detection Lab",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="expanded",
    )

    # Sidebar navigation
    st.sidebar.title("🛡️ Sigma Detection Lab")
    st.sidebar.caption("Webshell Honeypot Dashboard")

    page = st.sidebar.radio("Navigate", [
        "📊 Overview",
        "📋 Upload Log",
        "📂 Captured Files",
        "📏 Sigma Rules",
        "✏️ Rule Editor",
        "🔬 Sample Webshells",
        "📜 Raw Logs",
    ])

    st.sidebar.divider()
    st.sidebar.caption(f"Dashboard v1.0 | {datetime.utcnow().strftime('%Y-%m-%d %H:%M')} UTC")

    if st.sidebar.button("Logout"):
        st.session_state["authenticated"] = False
        st.rerun()

    # Load data used by multiple pages
    df = load_upload_logs()

    # Route to the selected page
    if page == "📊 Overview":
        page_overview(df)
    elif page == "📋 Upload Log":
        page_upload_log(df)
    elif page == "📂 Captured Files":
        page_uploaded_files()
    elif page == "📏 Sigma Rules":
        page_sigma_rules()
    elif page == "✏️ Rule Editor":
        page_sigma_editor()
    elif page == "🔬 Sample Webshells":
        page_sample_webshells()
    elif page == "📜 Raw Logs":
        page_raw_logs()


if __name__ == "__main__":
    main()
