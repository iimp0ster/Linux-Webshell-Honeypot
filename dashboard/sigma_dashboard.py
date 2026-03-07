"""
Sigma Detection Lab Dashboard
Streamlit application for analyzing webshell honeypot telemetry and managing Sigma rules.
"""

import os
import re
import json
import hashlib
import time
import glob
import fnmatch
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Optional

import requests
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
UPLOADS_DIR = "/captures"
HOST_AUDIT_LOG = "/host_audit/audit.log"
HOST_SYSLOG = "/host_syslog"

DASHBOARD_PASSWORD = os.environ.get("DASHBOARD_PASSWORD", "ChangeMe123!")

# IP enrichment: use ip-api.com (free, no key required, 45 req/min limit)
IP_API_URL = "http://ip-api.com/json/{ip}?fields=status,country,countryCode,region,regionName,city,org,as,query"

# ---------------------------------------------------------------------------
# Webshell Classification
# ---------------------------------------------------------------------------

# Ordered from most-specific to least-specific so the first match wins.
WEBSHELL_SIGNATURES: list[tuple[str, list[str]]] = [
    # China Chopper — tiny eval stager, very common in APT campaigns
    ("China Chopper", [r"assert\s*\(\s*\$_POST", r"eval\s*\(\s*\$_POST"]),
    # WSO (Web Shell by Orb) — feature-rich PHP shell with auth
    ("WSO Shell", [r"\$auth_pass\s*=", r"wso_version", r"WSO\s+\d"]),
    # b374k — PHP shell with blowfish-encrypted payload; characteristic nested decode
    ("b374k Shell", [r"b374k", r"Dx\s*\(", r"gzinflate\s*\(\s*base64_decode"]),
    # c99 / r57 — classic full-featured shells
    ("c99 Shell", [r"c99_", r"\$c99_name"]),
    ("r57 Shell", [r"r57_", r"\$r57_name"]),
    # Weevely — steganographic stager
    ("Weevely", [r"\$k\s*=\s*['\"][0-9a-f]{32}['\"]", r"str_replace.*\$k"]),
    # Reverse shell indicators
    ("Reverse Shell", [
        r"fsockopen\s*\(", r"socket_create\s*\(", r"stream_socket_client\s*\(",
        r"/dev/tcp/", r"bash\s+-i\s+>&",
    ]),
    # Simple eval-based one-liners / droppers
    ("Eval/Base64 Dropper", [
        r"eval\s*\(\s*base64_decode",
        r"eval\s*\(\s*gzinflate",
        r"eval\s*\(\s*str_rot13",
        r"eval\s*\(\s*gzuncompress",
        r"preg_replace\s*\(.*\/e",
    ]),
    # Generic command execution functions present
    ("Generic Command Shell", [
        r"\bsystem\s*\(", r"\bexec\s*\(", r"\bpassthru\s*\(",
        r"\bshell_exec\s*\(", r"\bpopen\s*\(",
    ]),
]


def classify_webshell(content: str) -> dict:
    """
    Classify uploaded file content against known webshell family signatures.
    Returns a dict with 'family', 'confidence', and 'matched_indicators'.
    """
    if not content:
        return {"family": "Unknown", "confidence": "none", "matched_indicators": []}

    matched_indicators = []
    family = "Unknown"

    for family_name, patterns in WEBSHELL_SIGNATURES:
        hits = []
        for pat in patterns:
            if re.search(pat, content, re.IGNORECASE | re.DOTALL):
                hits.append(pat)
        if hits:
            family = family_name
            matched_indicators = hits
            break  # first-match wins (most specific)

    if family == "Unknown" and matched_indicators == []:
        confidence = "none"
    elif len(matched_indicators) >= 2:
        confidence = "high"
    else:
        confidence = "medium"

    return {
        "family": family,
        "confidence": confidence,
        "matched_indicators": matched_indicators,
    }


# ---------------------------------------------------------------------------
# Sigma Rule Evaluation Engine
# ---------------------------------------------------------------------------

def _eval_field_match(record_val: str, match_val: str, modifier: str) -> bool:
    """Apply a single Sigma field condition with the given modifier."""
    rv = str(record_val).lower()
    mv = str(match_val).lower()
    if modifier == "contains":
        return mv in rv
    if modifier == "startswith":
        return rv.startswith(mv)
    if modifier == "endswith":
        return rv.endswith(mv)
    if modifier == "re":
        return bool(re.search(match_val, record_val, re.IGNORECASE))
    # no modifier — exact match
    return rv == mv


def _lookup_record_field(record: dict, field: str) -> Optional[str]:
    """Case-insensitive field lookup; returns None if missing."""
    for k, v in record.items():
        if k.lower() == field.lower():
            return str(v)
    return None


def _eval_selection(selection_val, record: dict) -> bool:
    """
    Evaluate one Sigma selection block against a record.

    selection_val may be:
      - list  → keyword search; any value must appear in ANY record field (OR)
      - dict  → field conditions; ALL fields must match (AND), values are OR lists
    """
    if isinstance(selection_val, list):
        # Keyword mode: search each value across all record fields
        record_text = " ".join(str(v) for v in record.values()).lower()
        return any(str(kw).lower() in record_text for kw in selection_val)

    if isinstance(selection_val, dict):
        for raw_field, match_val in selection_val.items():
            # Parse field|modifier syntax
            parts = raw_field.split("|")
            field = parts[0]
            modifier = parts[1] if len(parts) > 1 else ""

            record_val = _lookup_record_field(record, field)
            if record_val is None:
                return False  # field not present → selection fails

            # Normalise match_val to a list for uniform OR handling
            values = match_val if isinstance(match_val, list) else [match_val]
            if not any(_eval_field_match(record_val, mv, modifier) for mv in values):
                return False
        return True

    return False


def _eval_condition(condition: str, sel_results: dict[str, bool],
                    all_names: list[str]) -> bool:
    """
    Evaluate a Sigma condition string against pre-computed selection results.

    Handles:
      - bare selection name            e.g. "selection"
      - "all of them"
      - "1 of <pattern>"              e.g. "1 of selection_*"
      - "all of <pattern>"
      - "sel_a and sel_b"
      - "sel_a or sel_b"
      - "not sel_a"
      - parentheses for grouping
    """
    cond = condition.strip()

    # "all of them"
    if cond == "all of them":
        return all(sel_results.values())

    # "1 of <pattern>" / "all of <pattern>"
    m = re.match(r'^(1|all) of (\S+)$', cond)
    if m:
        quantifier, pattern = m.group(1), m.group(2)
        matched_names = [n for n in all_names if fnmatch.fnmatch(n, pattern)]
        if quantifier == "1":
            return any(sel_results.get(n, False) for n in matched_names)
        return all(sel_results.get(n, False) for n in matched_names)

    # Recursive descent for AND / OR / NOT / parentheses
    # Tokenise into: identifiers, 'and', 'or', 'not', '(', ')'
    tokens = re.findall(
        r'\(|\)|not\b|and\b|or\b|[\w\*]+',
        cond, re.IGNORECASE
    )

    pos = [0]  # mutable index

    def peek():
        return tokens[pos[0]] if pos[0] < len(tokens) else None

    def consume():
        t = tokens[pos[0]]
        pos[0] += 1
        return t

    def parse_primary():
        t = peek()
        if t is None:
            return False
        if t == '(':
            consume()
            val = parse_or()
            if peek() == ')':
                consume()
            return val
        if t.lower() == 'not':
            consume()
            return not parse_primary()
        # selection name or wildcard
        consume()
        # Expand wildcard patterns like "selection_*"
        if '*' in t:
            names = [n for n in all_names if fnmatch.fnmatch(n, t)]
            return any(sel_results.get(n, False) for n in names)
        return sel_results.get(t, False)

    def parse_and():
        left = parse_primary()
        while peek() and peek().lower() == 'and':
            consume()
            right = parse_primary()
            left = left and right
        return left

    def parse_or():
        left = parse_and()
        while peek() and peek().lower() == 'or':
            consume()
            right = parse_and()
            left = left or right
        return left

    try:
        return parse_or()
    except Exception:
        return False


def evaluate_sigma_detection(detection: dict,
                              record: dict) -> tuple[bool, dict[str, bool]]:
    """
    Evaluate a parsed Sigma detection block against a flat record dict.

    Returns:
        (overall_match: bool, sel_results: dict[selection_name -> bool])
    """
    if not detection or not isinstance(detection, dict):
        return False, {}

    condition = str(detection.get("condition", "")).strip()
    if not condition:
        return False, {}

    # Evaluate every named selection / filter block
    sel_results: dict[str, bool] = {}
    for key, val in detection.items():
        if key == "condition":
            continue
        sel_results[key] = _eval_selection(val, record)

    all_names = list(sel_results.keys())
    overall = _eval_condition(condition, sel_results, all_names)
    return overall, sel_results


# ---------------------------------------------------------------------------
# Auditd log parsing — command execution telemetry
# ---------------------------------------------------------------------------

# UIDs that correspond to web server processes on Debian/Ubuntu/CentOS
WEB_SERVER_UIDS = {"33", "48", "99"}  # www-data=33, apache=48, nginx/nobody=99

# Per-field patterns for auditd SYSCALL lines.
# Using individual re.search calls avoids order-dependency bugs
# (auditd emits ppid= before pid=, which breaks chained .*? patterns).
_AUD_TS_EVID = re.compile(r"msg=audit\(([\d.]+):(\d+)\)")
_AUD_FIELD   = {
    "syscall": re.compile(r"\bsyscall=(\d+)\b"),
    "ppid":    re.compile(r"\bppid=(\d+)\b"),
    "pid":     re.compile(r"\bpid=(\d+)\b"),
    "uid":     re.compile(r"\buid=(\d+)\b"),
}


def _decode_auditd_arg(raw: str) -> str:
    """Decode an auditd argument — either a quoted string or a hex-encoded value."""
    raw = raw.strip()
    if raw.startswith('"') and raw.endswith('"'):
        return raw[1:-1]
    # Hex-encoded value (even-length hex string)
    if re.fullmatch(r"[0-9A-Fa-f]+", raw) and len(raw) % 2 == 0:
        try:
            return bytes.fromhex(raw).decode("utf-8", errors="replace")
        except ValueError:
            pass
    return raw


def load_command_logs() -> pd.DataFrame:
    """
    Parse the host auditd log for EXECVE events spawned by web server UIDs.

    Auditd emits multi-record events keyed by a shared event ID
    (the number after 'audit(' in each line).  We group SYSCALL + EXECVE
    records and reconstruct the full command line for any event where the
    SYSCALL record shows uid=<web_server_uid>.

    Returns a DataFrame with columns:
        event_id, timestamp, uid, pid, ppid, command, binary
    """
    if not os.path.exists(HOST_AUDIT_LOG):
        return pd.DataFrame()

    # Group raw lines by event ID
    events: dict[str, dict] = defaultdict(lambda: {"syscall": None, "execve": None})

    execve_pattern = re.compile(
        r"type=EXECVE msg=audit\([\d.]+:(?P<evid>\d+)\):\s+argc=\d+\s+(?P<args>.+)"
    )
    arg_kv_pattern = re.compile(r'a\d+=("(?:[^"\\]|\\.)*"|[0-9A-Fa-f]+)')

    try:
        with open(HOST_AUDIT_LOG, "r", errors="replace") as fh:
            for line in fh:
                if "type=SYSCALL" in line:
                    ts_m = _AUD_TS_EVID.search(line)
                    if not ts_m:
                        continue
                    ev = ts_m.group(2)
                    field_vals = {}
                    for name, pat in _AUD_FIELD.items():
                        m = pat.search(line)
                        field_vals[name] = m.group(1) if m else None
                    if all(v is not None for v in field_vals.values()):
                        events[ev]["syscall"] = {
                            "ts": float(ts_m.group(1)),
                            "pid": field_vals["pid"],
                            "ppid": field_vals["ppid"],
                            "uid": field_vals["uid"],
                            "syscall": field_vals["syscall"],
                        }
                    continue

                ex_m = execve_pattern.search(line)
                if ex_m:
                    ev = ex_m.group("evid")
                    raw_args = arg_kv_pattern.findall(ex_m.group("args"))
                    argv = [_decode_auditd_arg(a) for a in raw_args]
                    events[ev]["execve"] = {"argv": argv}
    except PermissionError:
        return pd.DataFrame()

    rows = []
    for ev_id, ev in events.items():
        sc = ev.get("syscall")
        ex = ev.get("execve")
        if sc is None or ex is None:
            continue
        if sc["uid"] not in WEB_SERVER_UIDS:
            continue
        argv = ex["argv"]
        command = " ".join(argv) if argv else ""
        rows.append({
            "event_id": ev_id,
            "timestamp": datetime.utcfromtimestamp(sc["ts"]),
            "uid": sc["uid"],
            "pid": sc["pid"],
            "ppid": sc["ppid"],
            "command": command,
            "binary": argv[0] if argv else "",
            "argv": argv,
        })

    if not rows:
        return pd.DataFrame()

    df = pd.DataFrame(rows)
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    df.sort_values("timestamp", inplace=True)
    df.reset_index(drop=True, inplace=True)
    return df


# ---------------------------------------------------------------------------
# IP Geolocation enrichment (cached per session)
# ---------------------------------------------------------------------------

@st.cache_data(ttl=3600, show_spinner=False)
def enrich_ip(ip: str) -> dict:
    """
    Look up country, region, city, org, and ASN for a single IP via ip-api.com.
    Returns empty dict on failure (private IPs, rate limits, network errors).
    """
    if not ip or ip in ("unknown", "127.0.0.1", "::1"):
        return {}
    # Skip RFC-1918 / link-local ranges — ip-api rejects them
    private = re.compile(
        r"^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.|169\.254\.|::1)"
    )
    if private.match(ip):
        return {}
    try:
        resp = requests.get(IP_API_URL.format(ip=ip), timeout=3)
        data = resp.json()
        if data.get("status") == "success":
            return {
                "country": data.get("country", ""),
                "country_code": data.get("countryCode", ""),
                "region": data.get("regionName", ""),
                "city": data.get("city", ""),
                "org": data.get("org", ""),
                "asn": data.get("as", ""),
            }
    except Exception:
        pass
    return {}


def enrich_ip_dataframe(df: pd.DataFrame, ip_col: str = "ip") -> pd.DataFrame:
    """Add country, org, and ASN columns to a DataFrame by enriching the IP column."""
    if ip_col not in df.columns or df.empty:
        return df
    unique_ips = df[ip_col].dropna().unique()
    enriched = {}
    for ip in unique_ips:
        enriched[ip] = enrich_ip(str(ip))
    df = df.copy()
    df["country"] = df[ip_col].map(lambda ip: enriched.get(str(ip), {}).get("country", ""))
    df["country_code"] = df[ip_col].map(lambda ip: enriched.get(str(ip), {}).get("country_code", ""))
    df["org"] = df[ip_col].map(lambda ip: enriched.get(str(ip), {}).get("org", ""))
    df["asn"] = df[ip_col].map(lambda ip: enriched.get(str(ip), {}).get("asn", ""))
    return df


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
                pass

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
                raw = fh.read()
            rules[path.name] = {
                "path": str(path),
                "content": raw,
                "parsed": yaml.safe_load(raw or ""),
            }
        except Exception as exc:
            rules[path.name] = {
                "path": str(path),
                "content": f"# Error reading file: {exc}",
                "parsed": None,
            }
    return rules


def load_uploaded_files() -> list:
    """List files in the uploads directory with webshell classification."""
    if not os.path.isdir(UPLOADS_DIR):
        return []
    entries = []
    for p in sorted(Path(UPLOADS_DIR).iterdir()):
        if not p.is_file():
            continue
        stat = p.stat()
        try:
            content = p.read_text(errors="replace")
        except Exception:
            content = ""
        classification = classify_webshell(content)
        entries.append({
            "name": p.name,
            "size": stat.st_size,
            "modified": datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S"),
            "extension": p.suffix.lower(),
            "family": classification["family"],
            "confidence": classification["confidence"],
        })
    return entries


def load_sample_webshells() -> list:
    """Load sample webshell source code for educational display."""
    shells = []
    if not os.path.isdir(SAMPLES_DIR):
        return shells
    for p in sorted(Path(SAMPLES_DIR).glob("*.php")):
        try:
            content = p.read_text(errors="replace")
            classification = classify_webshell(content)
            shells.append({
                "name": p.name,
                "content": content,
                "family": classification["family"],
                "confidence": classification["confidence"],
            })
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

def page_overview(df: pd.DataFrame, df_cmds: pd.DataFrame) -> None:
    st.header("Attack Overview")

    total_uploads = len(df)
    unique_ips = df["ip"].nunique() if "ip" in df.columns and total_uploads else 0
    php_uploads = (
        df[df["filename"].str.lower().str.endswith(".php")].shape[0]
        if "filename" in df.columns and total_uploads else 0
    )
    today_uploads = (
        df[df["timestamp"].dt.date == datetime.utcnow().date()].shape[0]
        if "timestamp" in df.columns and total_uploads else 0
    )
    total_cmds = len(df_cmds)

    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("Total Uploads", total_uploads)
    c2.metric("Unique Attacker IPs", unique_ips)
    c3.metric("PHP Files Uploaded", php_uploads)
    c4.metric("Uploads Today", today_uploads)
    c5.metric("Commands Captured", total_cmds)

    if df.empty:
        st.info("No upload telemetry yet. The honeypot is waiting for attackers.")
        return

    st.divider()

    # Upload timeline
    if "timestamp" in df.columns:
        st.subheader("Upload Timeline")
        timeline = df.dropna(subset=["timestamp"]).set_index("timestamp").resample("1h").size().reset_index()
        timeline.columns = ["hour", "count"]
        fig = px.bar(
            timeline, x="hour", y="count",
            title="Uploads per Hour",
            labels={"count": "Uploads", "hour": "Time"},
        )
        st.plotly_chart(fig, use_container_width=True)

    col_a, col_b = st.columns(2)

    # Top IPs
    if "ip" in df.columns:
        with col_a:
            st.subheader("Top Attacker IPs")
            top_ips = df["ip"].value_counts().head(10).reset_index()
            top_ips.columns = ["IP Address", "Count"]
            fig2 = px.bar(
                top_ips, x="Count", y="IP Address",
                orientation="h", title="Top 10 Source IPs",
            )
            fig2.update_layout(yaxis={"categoryorder": "total ascending"})
            st.plotly_chart(fig2, use_container_width=True)

    # File extensions
    if "filename" in df.columns:
        with col_b:
            st.subheader("File Extensions")
            exts = (
                df["filename"]
                .apply(lambda f: Path(str(f)).suffix.lower() or "(none)")
                .value_counts()
                .head(10)
                .reset_index()
            )
            exts.columns = ["Extension", "Count"]
            fig3 = px.pie(exts, names="Extension", values="Count", title="File Types Uploaded")
            st.plotly_chart(fig3, use_container_width=True)

    st.divider()
    col_c, col_d = st.columns(2)

    # Webshell family distribution (from captured files on disk)
    files = load_uploaded_files()
    if files:
        with col_c:
            st.subheader("Webshell Family Breakdown")
            families = pd.DataFrame(files)["family"].value_counts().reset_index()
            families.columns = ["Family", "Count"]
            fig4 = px.pie(families, names="Family", values="Count", title="Webshell Families Detected")
            st.plotly_chart(fig4, use_container_width=True)

    # Top commands
    if not df_cmds.empty and "binary" in df_cmds.columns:
        with col_d:
            st.subheader("Top Binaries Executed by Webshells")
            top_bins = df_cmds["binary"].value_counts().head(10).reset_index()
            top_bins.columns = ["Binary", "Count"]
            fig5 = px.bar(
                top_bins, x="Count", y="Binary",
                orientation="h", title="Most-Used Binaries",
            )
            fig5.update_layout(yaxis={"categoryorder": "total ascending"})
            st.plotly_chart(fig5, use_container_width=True)

    # User-agent breakdown
    if "user_agent" in df.columns:
        st.subheader("Top User-Agents")
        ua_counts = df["user_agent"].fillna("(empty)").value_counts().head(10).reset_index()
        ua_counts.columns = ["User-Agent", "Count"]
        st.dataframe(ua_counts, use_container_width=True)


def page_upload_log(df: pd.DataFrame) -> None:
    st.header("Upload Log")

    if df.empty:
        st.info("No uploads recorded yet.")
        return

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
    display_cols = [
        c for c in [
            "timestamp", "ip", "filename", "size", "reported_type",
            "user_agent", "x_forwarded_for", "referer", "accept_language",
        ]
        if c in filtered.columns
    ]
    st.dataframe(
        filtered[display_cols].sort_values("timestamp", ascending=False)
        if "timestamp" in display_cols else filtered[display_cols],
        use_container_width=True,
    )


def page_uploaded_files() -> None:
    st.header("Captured Webshells")
    files = load_uploaded_files()

    if not files:
        st.info("No files in the uploads directory yet.")
        return

    df_files = pd.DataFrame(files)
    php_count = df_files[df_files["extension"] == ".php"].shape[0]
    unknown_count = df_files[df_files["family"] == "Unknown"].shape[0]
    classified_count = len(files) - unknown_count

    c1, c2, c3 = st.columns(3)
    c1.metric("Total Captured Files", len(files), f"{php_count} PHP files")
    c2.metric("Classified Webshells", classified_count)
    c3.metric("Unclassified Files", unknown_count)

    # Colour confidence column
    def _confidence_badge(val: str) -> str:
        colors = {"high": "background-color:#ff4b4b;color:white",
                  "medium": "background-color:#ffa500;color:white",
                  "none": ""}
        return colors.get(val, "")

    st.dataframe(
        df_files.style.map(_confidence_badge, subset=["confidence"]),
        use_container_width=True,
    )

    # Inspect file content + show classification detail
    selected = st.selectbox("Inspect file content", ["(select a file)"] + [f["name"] for f in files])
    if selected != "(select a file)":
        file_path = os.path.join(UPLOADS_DIR, selected)
        try:
            content = Path(file_path).read_text(errors="replace")
            cls = classify_webshell(content)

            st.subheader(f"Classification: {cls['family']}")
            col_a, col_b = st.columns(2)
            col_a.write(f"**Family:** `{cls['family']}`")
            col_b.write(f"**Confidence:** `{cls['confidence']}`")
            if cls["matched_indicators"]:
                st.write("**Matched patterns:**")
                for pat in cls["matched_indicators"]:
                    st.code(pat, language="regex")

            st.subheader(f"Source of {selected}")
            ext = Path(selected).suffix.lower()
            lang = "php" if ext == ".php" else "text"
            st.code(content, language=lang)
        except Exception as exc:
            st.error(f"Cannot read file: {exc}")


def page_command_telemetry(df_cmds: pd.DataFrame) -> None:
    st.header("Command Execution Telemetry")
    st.caption(
        "Commands parsed from auditd EXECVE records where the caller UID matches "
        "a web server account (www-data=33, apache=48, nginx/nobody=99)."
    )

    if df_cmds.empty:
        st.warning(
            "No command telemetry found. "
            "Ensure `auditd` is running on the host and the audit log is mounted at "
            "`/host_audit/audit.log`. "
            "Add the following auditd rule to capture web process executions:\n\n"
            "```\n-a always,exit -F arch=b64 -S execve -F uid=33 -k webshell_exec\n```"
        )
        return

    total = len(df_cmds)
    unique_bins = df_cmds["binary"].nunique() if "binary" in df_cmds.columns else 0
    st.metric("Total Commands Captured", total, f"{unique_bins} distinct binaries")

    st.divider()

    col_a, col_b = st.columns(2)

    # Top binaries
    if "binary" in df_cmds.columns:
        with col_a:
            st.subheader("Top Binaries Executed")
            top_bins = df_cmds["binary"].value_counts().head(15).reset_index()
            top_bins.columns = ["Binary", "Count"]
            fig = px.bar(
                top_bins, x="Count", y="Binary",
                orientation="h", title="Most-Used Binaries",
            )
            fig.update_layout(yaxis={"categoryorder": "total ascending"})
            st.plotly_chart(fig, use_container_width=True)

    # Command execution timeline
    if "timestamp" in df_cmds.columns:
        with col_b:
            st.subheader("Command Execution Timeline")
            tl = df_cmds.set_index("timestamp").resample("1h").size().reset_index()
            tl.columns = ["hour", "count"]
            fig2 = px.bar(tl, x="hour", y="count",
                          title="Commands per Hour",
                          labels={"count": "Commands", "hour": "Time"})
            st.plotly_chart(fig2, use_container_width=True)

    st.divider()

    # Classify command intent
    st.subheader("Command Intent Categorisation")

    INTENT_PATTERNS = {
        "Recon / System Info": [
            r"\b(id|whoami|uname|hostname|env|printenv|pwd|ls|find|locate|which|ps|netstat|ss|ip\s+addr|ifconfig)\b"
        ],
        "Credential Access": [
            r"\b(cat|head|tail|grep)\b.*(passwd|shadow|\.ssh|id_rsa|\.bash_history|\.env|wp-config)",
            r"\b(hashcat|john|hydra|medusa)\b",
        ],
        "Lateral Movement / Network": [
            r"\b(ssh|scp|rsync|nc|ncat|netcat|curl|wget|ftp|telnet)\b",
            r"\b(nmap|masscan|ping|traceroute)\b",
        ],
        "Persistence": [
            r"\b(crontab|at\b|systemctl|service|rc\.local|\.bashrc|\.profile|authorized_keys)\b",
        ],
        "Exfiltration / C2": [
            r"\b(curl|wget|nc|ncat)\b.*(http|ftp|tcp)://",
            r"(base64\s+-d|base64\s+--decode)",
        ],
        "Privilege Escalation": [
            r"\b(sudo|su\b|chmod\s+[0-9]*[67][0-9]*\s+/|chown\s+root|suid|sgid)\b",
        ],
        "Anti-Forensics": [
            r"\b(history\s+-c|shred|rm\s+-[rf]|unset\s+HISTFILE|export\s+HISTSIZE=0)\b",
        ],
    }

    intent_counts = {k: 0 for k in INTENT_PATTERNS}
    intent_map = []
    for _, row in df_cmds.iterrows():
        cmd = row.get("command", "")
        matched = "Other"
        for intent, patterns in INTENT_PATTERNS.items():
            if any(re.search(p, cmd, re.IGNORECASE) for p in patterns):
                matched = intent
                intent_counts[intent] += 1
                break
        intent_map.append(matched)

    df_cmds = df_cmds.copy()
    df_cmds["intent"] = intent_map

    intent_df = pd.DataFrame(
        [(k, v) for k, v in intent_counts.items() if v > 0],
        columns=["Intent", "Count"],
    ).sort_values("Count", ascending=False)

    if not intent_df.empty:
        fig3 = px.bar(
            intent_df, x="Intent", y="Count",
            title="Command Intent Distribution",
            color="Count",
            color_continuous_scale="Reds",
        )
        st.plotly_chart(fig3, use_container_width=True)

    st.divider()

    # Searchable raw command table
    st.subheader("Command Log")
    search_term = st.text_input("Search commands", "")
    display_df = df_cmds.copy()
    if search_term:
        display_df = display_df[display_df["command"].str.contains(search_term, case=False, na=False)]

    display_cols = [c for c in ["timestamp", "pid", "ppid", "uid", "binary", "command", "intent"] if c in display_df.columns]
    st.write(f"Showing {len(display_df):,} records")
    st.dataframe(
        display_df[display_cols].sort_values("timestamp", ascending=False)
        if "timestamp" in display_cols else display_df[display_cols],
        use_container_width=True,
    )


def page_ip_intelligence(df: pd.DataFrame) -> None:
    st.header("IP Threat Intelligence")
    st.caption(
        "Source IPs enriched with country, ASN, and org via ip-api.com. "
        "Results are cached for 1 hour. Private/RFC-1918 IPs are skipped."
    )

    if df.empty or "ip" not in df.columns:
        st.info("No upload telemetry with IP data yet.")
        return

    unique_ips = df["ip"].dropna().unique().tolist()
    st.write(f"Enriching **{len(unique_ips)}** unique IPs...")

    with st.spinner("Fetching geolocation data (may take a few seconds for large sets)..."):
        df_enriched = enrich_ip_dataframe(df)

    # Metrics
    countries = df_enriched["country"].nunique() if "country" in df_enriched.columns else 0
    c1, c2, c3 = st.columns(3)
    c1.metric("Unique Attacker IPs", len(unique_ips))
    c2.metric("Countries Represented", countries)
    c3.metric("Total Upload Events", len(df_enriched))

    st.divider()

    col_a, col_b = st.columns(2)

    # Attacks by country
    if "country" in df_enriched.columns:
        with col_a:
            st.subheader("Attacks by Country")
            country_counts = (
                df_enriched[df_enriched["country"] != ""]
                ["country"].value_counts().head(15).reset_index()
            )
            country_counts.columns = ["Country", "Count"]
            fig = px.bar(
                country_counts, x="Count", y="Country",
                orientation="h", title="Top Source Countries",
            )
            fig.update_layout(yaxis={"categoryorder": "total ascending"})
            st.plotly_chart(fig, use_container_width=True)

    # Attacks by ASN / Org
    if "org" in df_enriched.columns:
        with col_b:
            st.subheader("Attacks by ASN / Org")
            org_counts = (
                df_enriched[df_enriched["org"] != ""]
                ["org"].value_counts().head(10).reset_index()
            )
            org_counts.columns = ["Organisation", "Count"]
            fig2 = px.bar(
                org_counts, x="Count", y="Organisation",
                orientation="h", title="Top Source Organisations",
            )
            fig2.update_layout(yaxis={"categoryorder": "total ascending"})
            st.plotly_chart(fig2, use_container_width=True)

    # World choropleth map
    if "country_code" in df_enriched.columns:
        st.subheader("Global Attacker Origin Map")
        map_data = (
            df_enriched[df_enriched["country_code"] != ""]
            .groupby(["country_code", "country"])
            .size()
            .reset_index(name="count")
        )
        if not map_data.empty:
            fig_map = px.choropleth(
                map_data,
                locations="country_code",
                color="count",
                hover_name="country",
                color_continuous_scale="Reds",
                title="Upload Events by Country",
                labels={"count": "Uploads"},
            )
            fig_map.update_layout(margin={"r": 0, "t": 40, "l": 0, "b": 0})
            st.plotly_chart(fig_map, use_container_width=True)

    st.divider()

    # Per-IP enrichment table
    st.subheader("IP Enrichment Table")
    ip_table = (
        df_enriched.groupby("ip")
        .agg(
            uploads=("ip", "count"),
            country=("country", "first"),
            org=("org", "first"),
            asn=("asn", "first"),
        )
        .reset_index()
        .sort_values("uploads", ascending=False)
    )
    ip_filter = st.text_input("Filter by IP or country", "")
    if ip_filter:
        mask = (
            ip_table["ip"].str.contains(ip_filter, case=False, na=False)
            | ip_table["country"].str.contains(ip_filter, case=False, na=False)
        )
        ip_table = ip_table[mask]
    st.dataframe(ip_table, use_container_width=True)

    # Export as IOC list
    st.subheader("IOC Export")
    ioc_lines = "\n".join(
        f"{row['ip']}  # {row.get('country', '')} | {row.get('org', '')} | {row['uploads']} uploads"
        for _, row in ip_table.iterrows()
    )
    st.download_button(
        label="Download IP IOC list (.txt)",
        data=ioc_lines,
        file_name=f"attacker_ips_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.txt",
        mime="text/plain",
    )


def page_sigma_rules() -> None:
    st.header("Sigma Detection Rules")
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
    st.header("Sigma Rule Editor")
    st.info("Write new Sigma rules and save them to the rules directory.")

    _process_template = """\
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

    template_choice = st.radio(
        "Start from template",
        ["Process creation", "Upload event", "File content"],
        horizontal=True,
        key="editor_template_choice",
    )

    if template_choice == "Process creation":
        default_yaml = _process_template
    elif template_choice == "Upload event":
        default_yaml = _UPLOAD_EVENT_TEMPLATE
    else:
        default_yaml = _FILE_CONTENT_TEMPLATE

    filename = st.text_input("Rule filename (without .yml)", "new_rule")
    content = st.text_area("Rule YAML", value=default_yaml, height=400)

    col1, col2, col3 = st.columns(3)
    with col1:
        if st.button("Validate YAML"):
            try:
                parsed = yaml.safe_load(content)
                missing = [
                    f for f in ["title", "id", "status", "logsource", "detection"]
                    if f not in parsed
                ]
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
                    yaml.safe_load(content)
                    with open(out_path, "w") as fh:
                        fh.write(content)
                    st.success(f"Saved to {out_path}")
                except yaml.YAMLError as exc:
                    st.error(f"Cannot save — YAML error: {exc}")
                except PermissionError:
                    st.error(f"Permission denied writing to {out_path}. Check volume mount.")

    with col3:
        if st.button("Send to Rule Tester"):
            try:
                yaml.safe_load(content)
                st.session_state["tester_yaml"] = content
                st.success("Rule queued — navigate to 🧪 Rule Tester to run it.")
            except yaml.YAMLError as exc:
                st.error(f"Fix YAML error before testing: {exc}")


def page_sample_webshells() -> None:
    st.header("Sample Webshell Analysis")
    st.info(
        "Reference samples for developing detection signatures. "
        "Each sample is classified against the built-in signature engine."
    )
    shells = load_sample_webshells()

    if not shells:
        st.warning(f"No sample webshells found in `{SAMPLES_DIR}`.")
        return

    for shell in shells:
        family = shell.get("family", "Unknown")
        conf = shell.get("confidence", "none")
        badge = {"high": "🔴", "medium": "🟠", "none": "⚪"}.get(conf, "⚪")
        with st.expander(f"{badge} {shell['name']} — {family} ({conf} confidence)"):
            st.code(shell["content"], language="php")


def page_raw_logs() -> None:
    st.header("Raw System Logs")
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
        if (
            hashlib.sha256(password.encode()).hexdigest()
            == hashlib.sha256(DASHBOARD_PASSWORD.encode()).hexdigest()
        ):
            st.session_state["authenticated"] = True
            st.rerun()
        else:
            st.error("Incorrect password.")
    return False


# ---------------------------------------------------------------------------
# Rule Tester
# ---------------------------------------------------------------------------

# Field reference shown to the user so they know what field names to use.
_UPLOAD_EVENT_FIELDS = [
    ("filename",        "Uploaded filename, e.g. shell.php"),
    ("size",            "File size in bytes (integer)"),
    ("reported_type",   "MIME type reported by browser"),
    ("ip",              "Source IP address"),
    ("x_forwarded_for", "X-Forwarded-For header value"),
    ("user_agent",      "HTTP User-Agent string"),
    ("referer",         "HTTP Referer header"),
    ("accept_language", "Accept-Language header"),
    ("method",          "HTTP method (POST)"),
    ("request_uri",     "Request URI path"),
]

_FILE_CONTENT_FIELDS = [
    ("filename",  "Captured filename, e.g. shell.php"),
    ("extension", "File extension, e.g. .php"),
    ("size",      "File size in bytes (integer)"),
    ("content",   "Full raw text of the file"),
]

_UPLOAD_EVENT_TEMPLATE = """\
title: Suspicious PHP Upload
id: 00000000-0000-0000-0000-000000000001
status: experimental
description: Detects PHP file uploads to the honeypot
author: Your Name
date: {date}
logsource:
    product: linux
    category: webshell_upload
detection:
    selection:
        filename|endswith:
            - '.php'
            - '.phtml'
            - '.phar'
    condition: selection
falsepositives:
    - Legitimate PHP deployments
level: high
tags:
    - attack.persistence
    - attack.t1505.003
""".format(date=datetime.utcnow().strftime("%Y/%m/%d"))

_FILE_CONTENT_TEMPLATE = """\
title: Eval-Based Webshell Content
id: 00000000-0000-0000-0000-000000000002
status: experimental
description: Detects eval() obfuscation patterns inside uploaded files
author: Your Name
date: {date}
logsource:
    product: linux
    category: webshell_file
detection:
    selection:
        content|contains:
            - 'eval('
            - 'base64_decode'
            - 'shell_exec'
    condition: selection
falsepositives:
    - Minified JavaScript frameworks
level: high
tags:
    - attack.persistence
    - attack.t1505.003
""".format(date=datetime.utcnow().strftime("%Y/%m/%d"))


def page_rule_tester() -> None:
    st.header("🧪 Sigma Rule Tester")
    st.info(
        "Evaluate a Sigma rule against real honeypot data. "
        "Write a rule in **✏️ Rule Editor** and click *Send to Rule Tester*, "
        "or select a library rule below."
    )

    rules = load_sigma_rules()
    prefill_yaml = st.session_state.pop("tester_yaml", None)

    left, right = st.columns([2, 3], gap="large")

    with left:
        st.subheader("Rule")

        rule_source = st.radio(
            "Rule source",
            ["Library rule", "Paste YAML"],
            horizontal=True,
            key="tester_rule_source",
        )

        detection_block = None
        rule_yaml_text = ""

        if rule_source == "Library rule":
            if not rules:
                st.warning("No rules found in /sigma_rules. Save a rule first.")
                return
            selected_name = st.selectbox("Select rule", list(rules.keys()))
            rule_data = rules[selected_name]
            rule_yaml_text = rule_data["content"]
            st.code(rule_yaml_text, language="yaml")
            parsed = rule_data.get("parsed") or {}
            detection_block = parsed.get("detection")
        else:
            default = prefill_yaml if prefill_yaml else ""
            rule_yaml_text = st.text_area(
                "Rule YAML",
                value=default,
                height=300,
                key="tester_paste_yaml",
            )
            if rule_yaml_text.strip():
                try:
                    parsed = yaml.safe_load(rule_yaml_text) or {}
                    detection_block = parsed.get("detection")
                    if not detection_block:
                        st.warning("No `detection:` block found in the YAML.")
                except yaml.YAMLError as exc:
                    st.error(f"YAML parse error: {exc}")

        st.divider()
        st.subheader("Data source")

        mode = st.radio(
            "Test against",
            ["Upload log events", "File content"],
            key="tester_mode",
        )

        with st.expander("📋 Available field names", expanded=False):
            if mode == "Upload log events":
                st.caption("Use these field names in your Sigma `detection:` block:")
                st.table(
                    pd.DataFrame(_UPLOAD_EVENT_FIELDS, columns=["Field", "Description"])
                )
            else:
                st.caption("Use these field names when writing file-content rules:")
                st.table(
                    pd.DataFrame(_FILE_CONTENT_FIELDS, columns=["Field", "Description"])
                )

        run = st.button("▶ Run Test", type="primary", disabled=detection_block is None)

    with right:
        st.subheader("Results")

        if not run or detection_block is None:
            st.caption("Configure a rule and click **Run Test** to see results.")
            return

        # ── Build records to test ──────────────────────────────────────────
        if mode == "Upload log events":
            df = load_upload_logs()
            if df.empty:
                st.warning("No upload log events found. Upload a file to the honeypot first.")
                return
            records = df.to_dict(orient="records")
        else:
            files = []
            if os.path.isdir(UPLOADS_DIR):
                for p in sorted(Path(UPLOADS_DIR).iterdir()):
                    if not p.is_file():
                        continue
                    try:
                        content = p.read_text(errors="replace")
                    except Exception:
                        content = ""
                    stat = p.stat()
                    files.append({
                        "filename":  p.name,
                        "extension": p.suffix.lower(),
                        "size":      stat.st_size,
                        "content":   content,
                    })
            if not files:
                st.warning("No captured files found in /captures. Upload a file to the honeypot first.")
                return
            records = files

        # ── Evaluate ───────────────────────────────────────────────────────
        total = len(records)
        matched_records = []
        all_sel_breakdowns: dict[str, int] = defaultdict(int)

        for rec in records:
            overall, sel_results = evaluate_sigma_detection(detection_block, rec)
            if overall:
                matched_records.append(rec)
            for sel_name, matched in sel_results.items():
                if matched:
                    all_sel_breakdowns[sel_name] += 1

        match_count = len(matched_records)
        ratio = match_count / total if total else 0.0

        # ── Summary metrics ────────────────────────────────────────────────
        col_a, col_b, col_c = st.columns(3)
        col_a.metric("Matched", match_count)
        col_b.metric("Total", total)
        col_c.metric("Match rate", f"{ratio:.1%}")
        st.progress(ratio)

        if match_count == 0:
            st.warning(
                "No records matched. Check that your field names match the **Available field names** "
                "reference in the left panel, and verify your condition logic."
            )
        else:
            # Matched records table
            st.subheader(f"Matched records ({match_count})")
            display_cols = (
                ["timestamp", "filename", "ip", "user_agent", "size"]
                if mode == "Upload log events"
                else ["filename", "extension", "size"]
            )
            display_cols = [c for c in display_cols if c in matched_records[0]]
            st.dataframe(
                pd.DataFrame(matched_records)[display_cols],
                use_container_width=True,
            )

        # ── Per-selection breakdown ────────────────────────────────────────
        if all_sel_breakdowns:
            st.subheader("Selection breakdown")
            breakdown_df = pd.DataFrame([
                {"Selection": k, "Matched": v, "Of total": f"{v}/{total}"}
                for k, v in sorted(all_sel_breakdowns.items())
            ])
            fig = px.bar(
                breakdown_df,
                x="Selection",
                y="Matched",
                text="Of total",
                color_discrete_sequence=["#0082c9"],
            )
            fig.update_layout(
                margin=dict(t=20, b=20),
                yaxis_title="Records matched",
                xaxis_title="",
                showlegend=False,
            )
            st.plotly_chart(fig, use_container_width=True)


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

    st.sidebar.title("🛡️ Sigma Detection Lab")
    st.sidebar.caption("Webshell Honeypot Dashboard")

    page = st.sidebar.radio("Navigate", [
        "📊 Overview",
        "📋 Upload Log",
        "📂 Captured Files",
        "💻 Command Telemetry",
        "🌍 IP Intelligence",
        "📏 Sigma Rules",
        "✏️ Rule Editor",
        "🧪 Rule Tester",
        "🔬 Sample Webshells",
        "📜 Raw Logs",
    ])

    st.sidebar.divider()
    st.sidebar.caption(f"Dashboard v2.0 | {datetime.utcnow().strftime('%Y-%m-%d %H:%M')} UTC")

    if st.sidebar.button("Logout"):
        st.session_state["authenticated"] = False
        st.rerun()

    # Load shared data
    df = load_upload_logs()
    df_cmds = load_command_logs()

    if page == "📊 Overview":
        page_overview(df, df_cmds)
    elif page == "📋 Upload Log":
        page_upload_log(df)
    elif page == "📂 Captured Files":
        page_uploaded_files()
    elif page == "💻 Command Telemetry":
        page_command_telemetry(df_cmds)
    elif page == "🌍 IP Intelligence":
        page_ip_intelligence(df)
    elif page == "📏 Sigma Rules":
        page_sigma_rules()
    elif page == "✏️ Rule Editor":
        page_sigma_editor()
    elif page == "🧪 Rule Tester":
        page_rule_tester()
    elif page == "🔬 Sample Webshells":
        page_sample_webshells()
    elif page == "📜 Raw Logs":
        page_raw_logs()


if __name__ == "__main__":
    main()
