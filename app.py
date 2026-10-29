from __future__ import annotations
from typing import Any
import hashlib
import io
import json
import sqlite3
import tempfile
from datetime import datetime
from pathlib import Path
from streamlit_option_menu import option_menu
import pandas as pd
import plotly.express as px
import streamlit as st

from modules.scanner import scan_localhost
from modules.network_analysis import analyze_pcap


# -------------------------------------------------------------------
# App configuration and paths
# -------------------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent
DATABASE_DIR = BASE_DIR / "database"
DATABASE_DIR.mkdir(parents=True, exist_ok=True)
DB_PATH = DATABASE_DIR / "cyberscope.db"

st.set_page_config(
    page_title="CyberScope | Security Assessment",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


# -------------------------------------------------------------------
# Database: preserve existing data and add missing columns safely
# -------------------------------------------------------------------
def get_connection() -> sqlite3.Connection:
    connection = sqlite3.connect(DB_PATH, timeout=15)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def init_db() -> None:
    with get_connection() as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                source TEXT NOT NULL DEFAULT 'Manual Review',
                severity TEXT NOT NULL DEFAULT 'Informational',
                recommendation TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS scan_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_type TEXT NOT NULL,
                target TEXT NOT NULL,
                result_count INTEGER NOT NULL DEFAULT 0,
                status TEXT NOT NULL DEFAULT 'Completed',
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )
            """
        )

        # Safe migrations for databases created by earlier versions.
        finding_columns = {
            row["name"]
            for row in connection.execute("PRAGMA table_info(findings)").fetchall()
        }
        migrations = {
            "evidence": "ALTER TABLE findings ADD COLUMN evidence TEXT NOT NULL DEFAULT ''",
            "fingerprint": "ALTER TABLE findings ADD COLUMN fingerprint TEXT",
            "status": "ALTER TABLE findings ADD COLUMN status TEXT NOT NULL DEFAULT 'Open'",
        }
        for column, statement in migrations.items():
            if column not in finding_columns:
                connection.execute(statement)

        # Safely add missing columns to existing scan_history table
        scan_columns = {
            row["name"]
            for row in connection.execute(
                "PRAGMA table_info(scan_history)"
            ).fetchall()
        }

        scan_migrations = {
            "scan_type": "TEXT NOT NULL DEFAULT 'Unknown'",
            "target": "TEXT NOT NULL DEFAULT 'Unknown'",
            "result_count": "INTEGER NOT NULL DEFAULT 0",
            "status": "TEXT NOT NULL DEFAULT 'Completed'",
            "details": "TEXT NOT NULL DEFAULT ''",
            "created_at": "TEXT NOT NULL DEFAULT ''",
        }

        for column, definition in scan_migrations.items():
            if column not in scan_columns:
                connection.execute(
                    f"ALTER TABLE scan_history ADD COLUMN {column} {definition}"
                )

        # A unique index works for both new and migrated databases.
        connection.execute(
            """
            CREATE UNIQUE INDEX IF NOT EXISTS idx_findings_fingerprint
            ON findings(fingerprint)
            WHERE fingerprint IS NOT NULL AND fingerprint != ''
            """
        )


def save_finding(
    title: str,
    source: str,
    severity: str,
    recommendation: str,
    evidence: str = "",
    fingerprint: str | None = None,
    status: str = "Open",
) -> None:
    with get_connection() as connection:
        connection.execute(
            """
            INSERT OR IGNORE INTO findings
                (title, source, severity, recommendation, evidence,
                 fingerprint, status, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                title,
                source,
                severity,
                recommendation,
                evidence,
                fingerprint,
                status,
                datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            ),
        )


def save_scan_history(
    scan_type: str,
    target: str,
    result_count: int,
    status: str = "Completed",
    details: str = "",
) -> None:
    with get_connection() as connection:
        connection.execute(
            """
            INSERT INTO scan_history
                (scan_type, target, result_count, status, details, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                scan_type,
                target,
                int(result_count),
                status,
                details,
                datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            ),
        )


def load_findings() -> pd.DataFrame:
    with get_connection() as connection:
        return pd.read_sql_query(
            """
            SELECT id, title, source, severity, status, evidence,
                   recommendation, created_at
            FROM findings
            ORDER BY id DESC
            """,
            connection,
        )


def load_scan_history(limit: int | None = None) -> pd.DataFrame:
    query = """
        SELECT id, scan_type, target, result_count, status, details, created_at
        FROM scan_history
        ORDER BY id DESC
    """
    if limit is not None:
        query += " LIMIT ?"
        params = (int(limit),)
    else:
        params = ()
    with get_connection() as connection:
        return pd.read_sql_query(query, connection, params=params)


init_db()


# -------------------------------------------------------------------
# Styling
# -------------------------------------------------------------------
st.markdown(
    """
    <style>
    @import url('https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700&family=Space+Grotesk:wght@500;600;700&display=swap');

    :root { color-scheme: dark; }
    .stApp {
        background:
          radial-gradient(ellipse at 15% 0%, rgba(0, 210, 190, 0.08), transparent 34%),
          linear-gradient(145deg, #07111f 0%, #0a1424 48%, #0b1020 100%);
        color: #e7edf7;
        font-family: 'DM Sans', sans-serif;
    }
    h1, h2, h3 { font-family: 'Space Grotesk', sans-serif !important; letter-spacing: -0.025em; }
    [data-testid="stSidebar"] {
        background: #080f1c;
        border-right: 1px solid rgba(148, 163, 184, 0.15);
    }
    
/* Sidebar shell */
[data-testid="stSidebar"] {
    background: #080f1c;
    border-right: 1px solid #1c2b3d;
}

[data-testid="stSidebar"] > div:first-child {
    padding-top: 1.5rem;
}

/* Sidebar typography */
[data-testid="stSidebar"] h1,
[data-testid="stSidebar"] h2,
[data-testid="stSidebar"] h3 {
    color: #f4f8ff;
    font-family: "Space Grotesk", sans-serif;
}

[data-testid="stSidebar"] [data-testid="stCaptionContainer"] {
    color: #8fa2b9;
}

/* Navigation labels */
[data-testid="stSidebar"] [data-testid="stRadio"] > label {
    color: #8fa2b9;
    font-size: 0.76rem;
    font-weight: 700;
    letter-spacing: 0.09em;
    margin-bottom: 0.8rem;
}

/* Remove default radio circles */
[data-testid="stSidebar"] [data-testid="stRadio"] label > div:first-child {
    display: none;
}

/* Navigation item spacing and shape */
[data-testid="stSidebar"] [data-testid="stRadio"] div[role="radiogroup"] {
    gap: 0.35rem;
}

[data-testid="stSidebar"] [data-testid="stRadio"] div[role="radiogroup"] label {
    display: flex;
    align-items: center;
    padding: 0.72rem 0.8rem;
    border: 1px solid transparent;
    border-radius: 10px;
    background: transparent;
    transition: background 0.18s ease, border-color 0.18s ease;
    letter-spacing: 0;
    margin: 0;
    cursor: pointer;
}

[data-testid="stSidebar"] [data-testid="stRadio"] div[role="radiogroup"] label p {
    color: #aebed0;
    font-size: 0.88rem;
    font-weight: 500;
    margin: 0;
}

/* Hover state */
[data-testid="stSidebar"] [data-testid="stRadio"] div[role="radiogroup"] label:hover {
    background: #101e2e;
    border-color: #24394b;
}

[data-testid="stSidebar"] [data-testid="stRadio"] div[role="radiogroup"] label:hover p {
    color: #e7f2ff;
}

/* Selected item: relies on Streamlit's checked input */
[data-testid="stSidebar"] [data-testid="stRadio"] div[role="radiogroup"] label:has(input:checked) {
    background: #103331;
    border-color: #205b55;
}

[data-testid="stSidebar"] [data-testid="stRadio"] div[role="radiogroup"] label:has(input:checked) p {
    color: #5eead4;
    font-weight: 700;
}

/* Sidebar separators */
[data-testid="stSidebar"] hr {
    border-color: #1e2c3e;
    margin-top: 1.4rem;
    margin-bottom: 1.4rem;
}

    .hero {
        padding: 1.35rem 1.5rem;
        border: 1px solid rgba(94, 234, 212, 0.22);
        border-radius: 18px;
        background: linear-gradient(120deg, rgba(15, 35, 55, .96), rgba(10, 26, 39, .8));
        margin-bottom: 1.2rem;
        box-shadow: 0 12px 40px rgba(0, 0, 0, .16);
    }
    .eyebrow { color: #5eead4; font-size: .76rem; font-weight: 700; letter-spacing: .14em; text-transform: uppercase; }
    .hero h1 { margin: .35rem 0 .35rem 0; font-size: 2.15rem; color: #f8fbff; }
    .hero p { color: #a9b8cc; margin: 0; max-width: 800px; }
    .metric-card {
        padding: 1rem 1.05rem;
        min-height: 116px;
        border: 1px solid rgba(148, 163, 184, .17);
        border-radius: 15px;
        background: linear-gradient(145deg, rgba(19, 34, 54, .94), rgba(12, 24, 40, .94));
    }
    .metric-label { color: #a4b3c8; font-size: .82rem; margin-bottom: .55rem; }
    .metric-value { color: #f5f8ff; font-family: 'Space Grotesk', sans-serif; font-size: 1.8rem; font-weight: 700; line-height: 1.1; }
    .metric-note { color: #7dd3c7; font-size: .76rem; margin-top: .45rem; }
    .section-heading { color: #e9f1fb; font-size: 1.12rem; font-weight: 700; margin: .5rem 0 .75rem 0; }
    .small-muted { color: #98a9bf; font-size: .88rem; }
    .status-pill {
        display: inline-block; padding: .24rem .58rem; border-radius: 999px;
        background: rgba(45, 212, 191, .12); border: 1px solid rgba(45, 212, 191, .25);
        color: #5eead4; font-size: .76rem; font-weight: 600;
    }
    div[data-testid="stMetric"] {
        background: rgba(15, 30, 48, .75); padding: 13px 15px;
        border: 1px solid rgba(148, 163, 184, .16); border-radius: 14px;
    }
    div[data-testid="stMetricLabel"] { color: #a4b3c8; }
    div[data-testid="stMetricValue"] { color: #f8fbff; }
    .stButton > button, .stDownloadButton > button {
        border-radius: 10px; border: 1px solid rgba(94, 234, 212, .38);
        background: linear-gradient(90deg, #0f766e, #0d9488); color: white;
        font-weight: 600; min-height: 2.55rem;
    }
    .stButton > button:hover, .stDownloadButton > button:hover {
        border-color: #5eead4; color: white; background: #115e59;
    }
    div[data-testid="stDataFrame"] { border: 1px solid rgba(148, 163, 184, .15); border-radius: 12px; overflow: hidden; }
    hr { border-color: rgba(148, 163, 184, .16); }
    </style>
    """,
    unsafe_allow_html=True,
)


# -------------------------------------------------------------------
# Helpers
# -------------------------------------------------------------------
def render_hero(title: str, subtitle: str, eyebrow: str = "CYBERSCOPE / SECURITY OPERATIONS") -> None:
    st.markdown(
        f"""
        <div class="hero">
          <div class="eyebrow">{eyebrow}</div>
          <h1>{title}</h1>
          <p>{subtitle}</p>
        </div>
        """,
        unsafe_allow_html=True,
    )


def metric_card(label: str, value: str | int, note: str) -> None:
    st.markdown(
        f"""
        <div class="metric-card">
          <div class="metric-label">{label}</div>
          <div class="metric-value">{value}</div>
          <div class="metric-note">{note}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def make_fingerprint(*parts: str) -> str:
    raw = "|".join(str(part or "").strip() for part in parts)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def normalize_scan_results(results) -> pd.DataFrame:
    """Convert the existing scanner output to a DataFrame without changing scanner.py."""
    if isinstance(results, pd.DataFrame):
        return results.copy()
    if isinstance(results, dict):
        # Support either a single result or a dict containing a results list.
        nested = results.get("results") or results.get("ports") or results.get("open_ports")
        if isinstance(nested, list):
            return pd.DataFrame(nested)
        return pd.DataFrame([results])
    if isinstance(results, list):
        return pd.DataFrame(results)
    return pd.DataFrame()


def severity_color(severity: str) -> str:
    return {
        "Critical": "#fb7185",
        "High": "#f97316",
        "Medium": "#facc15",
        "Low": "#4ade80",
        "Informational": "#60a5fa",
    }.get(str(severity), "#94a3b8")


def generate_pdf(findings_df: pd.DataFrame, history_df: pd.DataFrame) -> bytes:
    from reportlab.lib import colors
    from reportlab.lib.enums import TA_LEFT
    from reportlab.lib.pagesizes import A4, landscape
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
    )

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=landscape(A4),
        rightMargin=12 * mm,
        leftMargin=12 * mm,
        topMargin=14 * mm,
        bottomMargin=14 * mm,
        title="CyberScope Security Assessment Report",
        author="CyberScope",
    )
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(
        name="CyberTitle", parent=styles["Title"], fontName="Helvetica-Bold",
        fontSize=22, leading=26, textColor=colors.HexColor("#0f766e"),
        alignment=TA_LEFT, spaceAfter=5
    ))
    styles.add(ParagraphStyle(
        name="CyberSmall", parent=styles["BodyText"], fontSize=7.5,
        leading=9, wordWrap="CJK"
    ))
    styles.add(ParagraphStyle(
        name="CyberCell", parent=styles["BodyText"], fontSize=8,
        leading=10, wordWrap="CJK"
    ))

    story = [
        Paragraph("CyberScope Security Assessment Report", styles["CyberTitle"]),
        Paragraph(
            f"Generated: {datetime.now().strftime('%d %B %Y, %H:%M')} | "
            "Scope: local/authorized security assessment",
            styles["Normal"],
        ),
        Spacer(1, 10),
    ]

    total = len(findings_df)
    counts = (
        findings_df["severity"].value_counts().to_dict()
        if not findings_df.empty and "severity" in findings_df.columns else {}
    )
    summary_data = [
        ["Total findings", "Critical", "High", "Medium", "Low", "Informational"],
        [
            str(total), str(counts.get("Critical", 0)), str(counts.get("High", 0)),
            str(counts.get("Medium", 0)), str(counts.get("Low", 0)),
            str(counts.get("Informational", 0)),
        ],
    ]
    summary = Table(summary_data, colWidths=[38 * mm] * 6)
    summary.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#102a3a")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#edf7f6")),
        ("TEXTCOLOR", (0, 1), (-1, -1), colors.HexColor("#102a3a")),
        ("GRID", (0, 0), (-1, -1), .4, colors.HexColor("#cbd5e1")),
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("TOPPADDING", (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
    ]))
    story.extend([summary, Spacer(1, 14), Paragraph("Findings and Remediation", styles["Heading2"])])

    finding_cols = [
        "title", "severity", "status",
        "source", "evidence", "recommendation"
    ]

    available_cols = [
        col for col in finding_cols
        if col in findings_df.columns
    ]

    # Explicitly allow ReportLab Paragraphs and other table-cell values
    table_data: list[list[Any]] = [
        [
            Paragraph(
                col.replace("_", " ").title(),
                styles["CyberCell"]
            )
            for col in available_cols
        ]
    ]

    for _, row in findings_df.iterrows():
        table_data.append([
            Paragraph(
                (
                    str(row.get(col, "") or "")
                    .replace("&", "&amp;")
                    .replace("<", "&lt;")
                    .replace(">", "&gt;")
                ),
                styles["CyberCell"]
            )
            for col in available_cols
        ])

    if len(table_data) == 1:
        table_data.append([
            Paragraph(
                "No findings recorded." if index == 0 else "",
                styles["CyberCell"]
            )
            for index, _ in enumerate(available_cols)
        ])

    widths_by_col = {
        "title": 42 * mm,
        "severity": 22 * mm,
        "status": 24 * mm,
        "source": 30 * mm,
        "evidence": 65 * mm,
        "recommendation": 65 * mm,
    }

    finding_table = Table(
        table_data,
        colWidths=[
            widths_by_col.get(col, 30 * mm)
            for col in available_cols
        ],
        repeatRows=1,
    )

    finding_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#102a3a")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#cbd5e1")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 5),
        ("RIGHTPADDING", (0, 0), (-1, -1), 5),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        (
            "ROWBACKGROUNDS",
            (0, 1),
            (-1, -1),
            [colors.white, colors.HexColor("#f3f7fa")]
        ),
    ]))

    story.append(finding_table)

    story.extend([
        Spacer(1, 14),
        Paragraph("Scan History", styles["Heading2"])
    ])
    history_cols = ["created_at", "scan_type", "target", "result_count", "status"]
    available_history = [col for col in history_cols if col in history_df.columns]
    history_data = [[Paragraph(col.replace("_", " ").title(), styles["CyberCell"]) for col in available_history]]
    for _, row in history_df.iterrows():
        history_data.append([Paragraph(str(row.get(col, "") or ""), styles["CyberCell"]) for col in available_history])
    if len(history_data) == 1:
        history_data.append([
            Paragraph(
                "No scans recorded." if index == 0 else "",
                styles["CyberCell"],
            )
            for index, _ in enumerate(available_history)
        ])
    history_table = Table(history_data, repeatRows=1)
    history_table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#102a3a")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), .35, colors.HexColor("#cbd5e1")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f3f7fa")]),
    ]))
    story.append(history_table)

    def footer(canvas, document):
        canvas.saveState()
        canvas.setFont("Helvetica", 8)
        canvas.setFillColor(colors.HexColor("#64748b"))
        canvas.drawString(12 * mm, 7 * mm, "CyberScope • For authorized security assessment use")
        canvas.drawRightString(landscape(A4)[0] - 12 * mm, 7 * mm, f"Page {document.page}")
        canvas.restoreState()

    doc.build(story, onFirstPage=footer, onLaterPages=footer)
    return buffer.getvalue()


# -------------------------------------------------------------------
# Sidebar navigation
# -------------------------------------------------------------------


with st.sidebar:
    # Branding
    st.markdown(
        """
        <div style="display:flex;align-items:center;gap:12px;
                    margin:8px 0 28px 0;">
            <div style="background:#103331;border:1px solid #205b55;
                        border-radius:12px;padding:10px;
                        display:flex;align-items:center;
                        justify-content:center;">
                <span style="font-size:25px;">🛡️</span>
            </div>
            <div>
                <div style="font-size:22px;font-weight:700;
                            color:#f4f8ff;letter-spacing:-0.6px;">
                    CyberScope
                </div>
                <div style="font-size:10px;letter-spacing:1.5px;
                            color:#8fa2b9;margin-top:3px;">
                    SECURITY OPERATIONS
                </div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    # Menu heading
    st.markdown(
        """
        <div style="color:#8fa2b9;font-size:13px;
                    font-weight:600;margin-bottom:12px;">
            WORKSPACE MENU
        </div>
        """,
        unsafe_allow_html=True,
    )

    # Icon-based navigation
    page = option_menu(
        menu_title=None,
        options=[
            "Dashboard",
            "Information Gathering",
            "Network Analysis",
            "Findings & Remediation",
            "Reports",
        ],
        icons=[
            "grid",
            "bullseye",
            "diagram-3",
            "clipboard-check",
            "file-earmark-bar-graph",
        ],
        default_index=0,
        orientation="vertical",
        styles={
            "container": {
                "padding": "0!important",
                "background-color": "#080f1c",
            },
            "icon": {
                "color": "#91a4bb",
                "font-size": "18px",
                "margin-right": "12px",
            },
            "nav-link": {
                "font-size": "15px",
                "font-weight": "500",
                "text-align": "left",
                "margin": "5px 0",
                "padding": "14px 12px",
                "border-radius": "12px",
                "color": "#b9c7d8",
                "background-color": "transparent",
                "--hover-color": "#101e2e",
            },
            "nav-link-selected": {
                "background-color": "#123b3b",
                "color": "#e8fffc",
                "font-weight": "700",
                "border": "1px solid #205b55",
            },
        },
        key="cyberscope_navigation",
    )

    # Safety information
    st.divider()

    st.caption("AUTHORIZED TESTING ONLY")
    st.caption("Network scans are restricted to localhost.")
    st.caption(f"Database: {DB_PATH.name}")

# -------------------------------------------------------------------
# Dashboard
# -------------------------------------------------------------------
if page == "Dashboard":
    render_hero(
        "Security Overview",
        "A consolidated view of your local scans, recorded findings, and packet-capture analysis.",
    )

    findings = load_findings()
    history = load_scan_history()
    total_findings = len(findings)
    open_findings = int((findings["status"] != "Resolved").sum()) if not findings.empty else 0
    high_risk = int(findings["severity"].isin(["Critical", "High"]).sum()) if not findings.empty else 0
    total_scans = len(history)
    recent_scan = history.iloc[0]["created_at"] if not history.empty else "No scans yet"

    cols = st.columns(4, gap="medium")
    with cols[0]:
        metric_card("TOTAL SCANS", total_scans, "Recorded scan sessions")
    with cols[1]:
        metric_card("TOTAL FINDINGS", total_findings, "Saved security observations")
    with cols[2]:
        metric_card("OPEN FINDINGS", open_findings, "Not marked resolved")
    with cols[3]:
        metric_card("HIGH-RISK FINDINGS", high_risk, "Critical + High severity")

    st.write("")
    left, right = st.columns([1.2, 1], gap="large")
    with left:
        st.markdown('<div class="section-heading">Finding severity distribution</div>', unsafe_allow_html=True)
        if not findings.empty:
            severity_order = ["Critical", "High", "Medium", "Low", "Informational"]
            severity_df = (
                findings["severity"].value_counts()
                .reindex(severity_order, fill_value=0)
                .rename_axis("Severity").reset_index(name="Count")
            )
            fig = px.bar(
                severity_df, x="Severity", y="Count", color="Severity",
                category_orders={"Severity": severity_order},
                color_discrete_map={
                    "Critical": "#fb7185", "High": "#f97316", "Medium": "#facc15",
                    "Low": "#4ade80", "Informational": "#60a5fa",
                },
            )
            fig.update_layout(
                template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)", margin=dict(l=8, r=8, t=15, b=8),
                showlegend=False, xaxis_title="", yaxis_title="Findings",
            )
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("No findings yet. Add a manual finding or analyze a sample PCAP to populate this chart.")

    with right:
        st.markdown('<div class="section-heading">Recent activity</div>', unsafe_allow_html=True)
        if history.empty:
            st.info("Your scan activity will appear here after the first scan.")
        else:
            display_cols = ["created_at", "scan_type", "target", "result_count", "status"]
            st.dataframe(history[display_cols].head(6), use_container_width=True, hide_index=True)
        st.markdown(f'<p class="small-muted">Most recent scan: {recent_scan}</p>', unsafe_allow_html=True)

    st.markdown('<div class="section-heading">Latest findings</div>', unsafe_allow_html=True)
    if findings.empty:
        st.info("No saved findings. Use Network Analysis or Findings & Remediation to get started.")
    else:
        st.dataframe(
            findings[["title", "severity", "status", "source", "created_at"]].head(8),
            use_container_width=True,
            hide_index=True,
        )

    st.caption("CyberScope is an educational assessment dashboard. Findings are indicators for review, not proof of exploitability.")


# -------------------------------------------------------------------
# Information gathering / localhost scan
# -------------------------------------------------------------------
elif page == "Information Gathering":
    render_hero(
        "Information Gathering",
        "Inventory listening ports and detected services on your own machine.",
        "CYBERSCOPE / LOCALHOST SCAN",
    )
    st.warning("This page scans localhost only. Use the results to understand your own machine's exposed services.")

    if st.button("▶ Start Localhost Scan", type="primary"):
        with st.spinner("Running Nmap against 127.0.0.1..."):
            try:
                scan_results = scan_localhost()
                scan_df = normalize_scan_results(scan_results)
                save_scan_history(
                    "Nmap Localhost Scan",
                    "127.0.0.1",
                    len(scan_df),
                    "Completed",
                    f"{len(scan_df)} result rows",
                )
                st.session_state["last_scan_df"] = scan_df
                st.session_state["last_scan_time"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                st.success(f"Scan completed. {len(scan_df)} result row(s) returned.")
            except Exception as exc:
                save_scan_history("Nmap Localhost Scan", "127.0.0.1", 0, "Failed", str(exc))
                st.error(f"Scan failed: {exc}")

    scan_df = st.session_state.get("last_scan_df")
    if scan_df is not None:
        if scan_df.empty:
            st.info("The scanner returned no rows. This can mean no matching ports were found, or the result format needs adjustment.")
        else:
            st.markdown('<div class="section-heading">Scan results</div>', unsafe_allow_html=True)
            st.dataframe(scan_df, use_container_width=True, hide_index=True)
            st.download_button(
                "Download scan results (CSV)",
                scan_df.to_csv(index=False).encode("utf-8"),
                file_name="cyberscope_localhost_scan.csv",
                mime="text/csv",
            )
        st.caption(f"Last scan: {st.session_state.get('last_scan_time', 'Unknown')}")

    st.caption("An open port is not automatically a vulnerability. Verify whether the service is needed and configured securely.")


# -------------------------------------------------------------------
# Network analysis / PCAP
# -------------------------------------------------------------------
elif page == "Network Analysis":
    render_hero(
        "Network Traffic Analysis",
        "Analyze a packet-capture file for protocol distribution and heuristic traffic indicators.",
        "CYBERSCOPE / PCAP ANALYSIS",
    )
    st.info("Use a capture you own or are authorized to analyze. For a safe first test, use the supplied synthetic sample PCAP.")

    uploaded_file = st.file_uploader("Upload a PCAP or PCAPNG file", type=["pcap", "pcapng"])
    if uploaded_file is not None:
        st.caption(f"Selected file: {uploaded_file.name} • {uploaded_file.size:,} bytes")
        if st.button("Analyze Capture", type="primary"):
            temp_path = None
            try:
                suffix = Path(uploaded_file.name).suffix or ".pcap"
                with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as temp_file:
                    temp_file.write(uploaded_file.getvalue())
                    temp_path = temp_file.name

                with st.spinner("Analyzing packets..."):
                    result = analyze_pcap(temp_path)

                packet_count = int(result.get("packet_count", 0))
                protocol_summary = pd.DataFrame(result.get("protocol_summary", []))
                findings_list = result.get("findings", [])

                st.session_state["last_pcap_name"] = uploaded_file.name
                st.session_state["last_pcap_packets"] = packet_count
                st.session_state["last_protocol_summary"] = protocol_summary
                st.session_state["last_pcap_findings"] = findings_list

                for finding in findings_list:
                    title = str(finding.get("Finding", "Network traffic indicator"))
                    source = str(finding.get("Source", "Network Analysis"))
                    severity = str(finding.get("Severity", "Informational"))
                    evidence = str(finding.get("Evidence", ""))
                    recommendation = str(finding.get("Recommendation", "Review the traffic and validate the indicator."))
                    fingerprint = make_fingerprint(
                        "Network Analysis", uploaded_file.name, title, source, evidence
                    )
                    save_finding(title, source, severity, recommendation, evidence, fingerprint)

                save_scan_history(
                    "PCAP Analysis",
                    uploaded_file.name,
                    len(findings_list),
                    "Completed",
                    f"{packet_count} packets; {len(findings_list)} indicators",
                )
                st.success(f"Analysis complete: {packet_count} packets reviewed.")
            except Exception as exc:
                save_scan_history("PCAP Analysis", uploaded_file.name, 0, "Failed", str(exc))
                st.error(f"Could not analyze this capture: {exc}")
            finally:
                if temp_path:
                    try:
                        Path(temp_path).unlink(missing_ok=True)
                    except OSError:
                        pass

    if "last_pcap_packets" in st.session_state:
        st.write("")
        cols = st.columns(3)
        with cols[0]:
            metric_card("PACKETS ANALYZED", st.session_state["last_pcap_packets"], "Packets in selected capture")
        with cols[1]:
            metric_card("PROTOCOLS", len(st.session_state.get("last_protocol_summary", [])), "Protocol categories observed")
        with cols[2]:
            metric_card("INDICATORS", len(st.session_state.get("last_pcap_findings", [])), "Heuristic findings saved")

        protocol_df = st.session_state.get("last_protocol_summary", pd.DataFrame())
        if not protocol_df.empty:
            st.markdown('<div class="section-heading">Protocol distribution</div>', unsafe_allow_html=True)
            st.dataframe(protocol_df, use_container_width=True, hide_index=True)
            if {"Protocol", "Packet Count"}.issubset(protocol_df.columns):
                fig = px.pie(
                    protocol_df, names="Protocol", values="Packet Count", hole=0.55,
                    color_discrete_sequence=["#2dd4bf", "#60a5fa", "#fbbf24", "#c084fc", "#fb7185"],
                )
                fig.update_layout(
                    template="plotly_dark", paper_bgcolor="rgba(0,0,0,0)",
                    plot_bgcolor="rgba(0,0,0,0)", margin=dict(l=5, r=5, t=10, b=5),
                )
                st.plotly_chart(fig, use_container_width=True)

        pcap_findings = st.session_state.get("last_pcap_findings", [])
        st.markdown('<div class="section-heading">Traffic indicators</div>', unsafe_allow_html=True)
        if pcap_findings:
            pcap_df = pd.DataFrame(pcap_findings)
            st.dataframe(pcap_df, use_container_width=True, hide_index=True)
            st.download_button(
                "Download analysis findings (CSV)",
                pcap_df.to_csv(index=False).encode("utf-8"),
                file_name="cyberscope_pcap_findings.csv",
                mime="text/csv",
            )
        else:
            st.success("No heuristic indicators were triggered by the current analysis rules.")

        st.caption("Heuristic indicators can produce false positives and should be validated before taking action.")


# -------------------------------------------------------------------
# Findings and remediation
# -------------------------------------------------------------------
elif page == "Findings & Remediation":
    render_hero(
        "Findings & Remediation",
        "Record, prioritize, filter, and track security observations through remediation.",
        "CYBERSCOPE / FINDINGS REGISTER",
    )
    
    with st.expander("＋ Add a finding", expanded=False):
        with st.form("add_finding_form", clear_on_submit=True):
            title = st.text_input("Finding title *", placeholder="Example: Unnecessary service exposed")
            source = st.selectbox("Source", ["Manual Review", "Nmap Localhost Scan", "Network Analysis", "Configuration Review", "Other"])
            severity = st.selectbox("Severity", ["Critical", "High", "Medium", "Low", "Informational"], index=2)
            evidence = st.text_area("Evidence", placeholder="What did you observe? Include relevant port, service, or packet evidence.")
            recommendation = st.text_area("Recommendation *", placeholder="Describe the recommended defensive action.")
            submitted = st.form_submit_button("Save Finding", type="primary")
            if submitted:
                if not title.strip() or not recommendation.strip():
                    st.error("Finding title and recommendation are required.")
                else:
                    save_finding(
                        title.strip(), source, severity, recommendation.strip(),
                        evidence.strip(), None, "Open",
                    )
                    st.success("Finding saved.")
                    st.rerun()

    findings = load_findings()
    if findings.empty:
        st.info("No findings recorded yet. Add one manually or analyze a PCAP file.")
    else:
        f1, f2, f3 = st.columns(3)
        with f1:
            severity_filter = st.multiselect(
                "Filter by severity",
                ["Critical", "High", "Medium", "Low", "Informational"],
                default=["Critical", "High", "Medium", "Low", "Informational"],
            )
        with f2:
            status_filter = st.multiselect(
                "Filter by status",
                ["Open", "In Progress", "Resolved"],
                default=["Open", "In Progress", "Resolved"],
            )
        with f3:
            search_text = st.text_input("Search findings", placeholder="Title, source, evidence...")

        filtered = findings[
            findings["severity"].isin(severity_filter)
            & findings["status"].isin(status_filter)
        ].copy()
        if search_text.strip():
            searchable = (
                filtered["title"].fillna("") + " " +
                filtered["source"].fillna("") + " " +
                filtered["evidence"].fillna("") + " " +
                filtered["recommendation"].fillna("")
            )
            query = search_text.strip().casefold()
            filtered = filtered[
                searchable.map(lambda value: query in str(value).casefold())
            ]

        st.markdown(f'<div class="section-heading">Findings register · {len(filtered)} result(s)</div>', unsafe_allow_html=True)
        show_cols = ["id", "title", "severity", "status", "source", "created_at"]
        st.dataframe(filtered[show_cols], use_container_width=True, hide_index=True)

        st.download_button(
            "Export filtered findings (CSV)",
            filtered.to_csv(index=False).encode("utf-8"),
            file_name="cyberscope_findings.csv",
            mime="text/csv",
        )

        st.markdown('<div class="section-heading">Update or delete a finding</div>', unsafe_allow_html=True)
        options = {
            f'#{int(row["id"])} — {str(row["title"])[:70]}': int(row["id"])
            for _, row in findings.iterrows()
        }
        selected_label = st.selectbox("Select a finding", list(options.keys()))
        selected_id = options[selected_label]
        selected_row = findings[findings["id"] == selected_id].iloc[0]

        with st.form("update_finding_form"):
            new_status = st.selectbox(
                "Status",
                ["Open", "In Progress", "Resolved"],
                index=["Open", "In Progress", "Resolved"].index(
                    selected_row["status"] if selected_row["status"] in ["Open", "In Progress", "Resolved"] else "Open"
                ),
            )
            update_clicked = st.form_submit_button("Update Status")
            if update_clicked:
                with get_connection() as connection:
                    connection.execute(
                        "UPDATE findings SET status = ? WHERE id = ?",
                        (new_status, int(selected_id)),
                    )
                st.success("Finding status updated.")
                st.rerun()

        if st.button("Delete Selected Finding"):
            if selected_id is None:
                st.warning("Please select a finding to delete.")
            else:
                with get_connection() as connection:
                    connection.execute("DELETE FROM findings WHERE id = ?", (int(selected_id),))
                st.success("Finding deleted.")
                st.rerun()

        with st.expander("View selected finding details"):
            st.write("**Evidence**")
            st.write(selected_row["evidence"] or "No evidence recorded.")
            st.write("**Recommendation**")
            st.write(selected_row["recommendation"] or "No recommendation recorded.")


# -------------------------------------------------------------------
# Reports
# -------------------------------------------------------------------
elif page == "Reports":
    render_hero(
        "Reports & Export",
        "Generate a shareable PDF report from your saved findings and scan history.",
        "CYBERSCOPE / REPORT CENTER",
    )

    findings = load_findings()
    history = load_scan_history()
    c1, c2, c3 = st.columns(3)
    with c1:
        metric_card("FINDINGS", len(findings), "Included in report")
    with c2:
        metric_card("SCAN RECORDS", len(history), "Saved activity history")
    with c3:
        metric_card("RESOLVED", int((findings["status"] == "Resolved").sum()) if not findings.empty else 0, "Marked resolved")

    st.markdown('<div class="section-heading">Report preview</div>', unsafe_allow_html=True)
    if findings.empty:
        st.info("No findings have been saved yet. You can still generate a report containing scan history.")
    else:
        st.dataframe(
            findings[["title", "severity", "status", "source", "created_at"]],
            use_container_width=True,
            hide_index=True,
        )

    if st.button("Generate PDF Report", type="primary"):
        try:
            pdf_bytes = generate_pdf(findings, history)
            st.session_state["cyberscope_pdf"] = pdf_bytes
            st.success("PDF report generated.")
        except Exception as exc:
            st.error(f"Could not generate the PDF: {exc}")

    if "cyberscope_pdf" in st.session_state:
        st.download_button(
            "Download CyberScope PDF Report",
            data=st.session_state["cyberscope_pdf"],
            file_name=f"CyberScope_Report_{datetime.now().strftime('%Y%m%d_%H%M')}.pdf",
            mime="application/pdf",
        )

    st.download_button(
        "Export all findings (CSV)",
        findings.to_csv(index=False).encode("utf-8"),
        file_name="cyberscope_all_findings.csv",
        mime="text/csv",
    )
    st.download_button(
        "Export scan history (CSV)",
        history.to_csv(index=False).encode("utf-8"),
        file_name="cyberscope_scan_history.csv",
        mime="text/csv",
    )


# -------------------------------------------------------------------
# Footer
# -------------------------------------------------------------------
st.divider()
st.caption(
    "CyberScope • Educational security assessment dashboard • "
    "Only assess systems you own or have explicit permission to test."
)
