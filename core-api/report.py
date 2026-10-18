import json
import datetime
import os
from fpdf import FPDF
from database import AttackSession, Event

def generate_pdf_report(session: AttackSession, events: list[Event], output_path: str, techniques: list[dict] = None, narrative: str = None):
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    pdf = FPDF()
    pdf.add_page()

    # Logo Header
    logo_path = os.path.join(os.path.dirname(__file__), "assets", "logo.png")
    if os.path.exists(logo_path):
        try:
            pdf.image(logo_path, x=95, y=10, w=20)
            pdf.ln(18)
        except Exception:
            pass

    # Title
    pdf.set_font("Helvetica", "B", 16)
    pdf.cell(0, 10, f"Incident Report: Session {session.id[:8]}", new_x="LMARGIN", new_y="NEXT", align='C')
    pdf.ln(10)

    # Session Details
    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 10, "Session Overview", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 10)
    pdf.cell(0, 8, f"Session ID: {session.id}", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 8, f"Source IP: {session.src_ip}", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 8, f"Start Time: {session.start_time}", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 8, f"End Time: {session.end_time}", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 8, f"Severity Score: {session.severity_score}", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 8, f"Honeypot: {session.honeypot or 'unknown'}", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(5)

    # AI Summary
    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 10, "AI Executive Summary", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 10)
    if session.ai_summary:
        pdf.multi_cell(0, 8, session.ai_summary, new_x="LMARGIN", new_y="NEXT")
    else:
        pdf.multi_cell(0, 8, "No AI summary available.", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(5)

    # Narrative (new)
    if narrative:
        pdf.set_font("Helvetica", "B", 12)
        pdf.cell(0, 10, "Incident Narrative", new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("Helvetica", "", 10)
        pdf.multi_cell(0, 8, narrative, new_x="LMARGIN", new_y="NEXT")
        pdf.ln(5)

    # MITRE Techniques
    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 10, "Identified MITRE ATT&CK Techniques", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 10)
    if techniques is None:
        techniques = [
            {"technique": e.mitre_technique, "source": "rule"}
            for e in events
            if e.mitre_technique
        ]
    if techniques:
        for t in techniques:
            label = t["technique"]
            source = t.get("source", "rule")
            if source == "semantic":
                label = f"{label}  [semantic]"
            elif source == "rule":
                label = f"{label}  [rule-based]"
            pdf.cell(0, 8, f"- {label}", new_x="LMARGIN", new_y="NEXT")
    else:
        pdf.cell(0, 8, "No known techniques identified.", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(5)

    # Event Log
    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 10, "Event Timeline", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 9)
    for e in events:
        time_str = e.timestamp.strftime("%Y-%m-%d %H:%M:%S")
        pdf.multi_cell(0, 6, f"[{time_str}] {e.event_type.upper()}: {e.message}", new_x="LMARGIN", new_y="NEXT")
        if e.mitre_technique:
            pdf.set_text_color(200, 0, 0)
            pdf.cell(0, 6, f"    TAG: {e.mitre_technique}", new_x="LMARGIN", new_y="NEXT")
            pdf.set_text_color(0, 0, 0)

    pdf.output(output_path)
    return output_path