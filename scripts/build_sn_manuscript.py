"""Script to build the DeceptionNet manuscript strictly adhering to the Springer SN Computer Science
template, incorporating all sections, tables, objectives, comparative analyses, and declarations
present in the reference papers (Guardian Eye and Beyond Task Count from SVERI's College of Engineering).

All claims remain 100% grounded in the committed Claim Ledger (docs/CLAIM_LEDGER.md).
"""
import os
import json
import docx
from docx import Document
from docx.shared import Inches, Pt, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.oxml import OxmlElement
from docx.oxml.ns import qn


def set_cell_background(cell, fill_hex):
    tcPr = cell._tc.get_or_add_tcPr()
    shd = OxmlElement('w:shd')
    shd.set(qn('w:val'), 'clear')
    shd.set(qn('w:color'), 'auto')
    shd.set(qn('w:fill'), fill_hex)
    tcPr.append(shd)


def set_cell_margins(cell, top=100, bottom=100, left=140, right=140):
    tcPr = cell._tc.get_or_add_tcPr()
    tcMar = OxmlElement('w:tcMar')
    for m, val in [('w:top', top), ('w:bottom', bottom), ('w:left', left), ('w:right', right)]:
        node = OxmlElement(m)
        node.set(qn('w:w'), str(val))
        node.set(qn('w:type'), 'dxa')
        tcMar.append(node)
    tcPr.append(tcMar)


def generate_sn_manuscript(output_path):
    doc = Document()

    # Page Margins: 1 inch everywhere
    for section in doc.sections:
        section.top_margin = Inches(1.0)
        section.bottom_margin = Inches(1.0)
        section.left_margin = Inches(1.0)
        section.right_margin = Inches(1.0)

        # Header: SN Computer Science
        header = section.header
        p_hdr = header.paragraphs[0]
        p_hdr.text = "SN Computer Science"
        p_hdr.alignment = WD_ALIGN_PARAGRAPH.RIGHT
        p_hdr.runs[0].font.name = 'Times New Roman'
        p_hdr.runs[0].font.size = Pt(9)
        p_hdr.runs[0].font.color.rgb = RGBColor(0x77, 0x77, 0x77)

    # Styles
    styles = doc.styles
    normal_style = styles['Normal']
    normal_style.font.name = 'Times New Roman'
    normal_style.font.size = Pt(11)
    normal_style.font.color.rgb = RGBColor(0x11, 0x11, 0x11)
    normal_style.paragraph_format.line_spacing = 1.15
    normal_style.paragraph_format.space_after = Pt(5)

    # Journal Label on Page 1 Top
    p_jrn = doc.add_paragraph()
    r_jrn = p_jrn.add_run("SN Computer Science")
    r_jrn.font.size = Pt(10)
    r_jrn.italic = True
    r_jrn.font.color.rgb = RGBColor(0x55, 0x55, 0x55)
    p_jrn.paragraph_format.space_after = Pt(8)

    # Title
    p_title = doc.add_paragraph()
    r_title = p_title.add_run("DeceptionNet: An Architectural Framework for Multi-Honeypot Active Defense, Deterministic ATT&CK Attribution, and Decoupled Threat Intelligence")
    r_title.bold = True
    r_title.font.size = Pt(17)
    r_title.font.color.rgb = RGBColor(0x1B, 0x36, 0x5D)
    p_title.paragraph_format.space_after = Pt(10)

    # Authors
    p_auth = doc.add_paragraph()
    r_auth = p_auth.add_run("[NEED FROM AUTHOR: Project Supervisor¹], Piyush Madan Shinde²*, Shivani Danwe³, [NEED FROM AUTHOR: Co-Author 3⁴], [NEED FROM AUTHOR: Co-Author 4⁵]")
    r_auth.bold = True
    r_auth.font.size = Pt(11)
    p_auth.paragraph_format.space_after = Pt(3)

    # Affiliations
    p_aff = doc.add_paragraph()
    r_aff = p_aff.add_run(
        "²⁻⁵ Department of Computer Science and Engineering, SVERI's College of Engineering, Pandharpur, Maharashtra, India\n"
        "¹ Assistant Professor, Department of Computer Science and Engineering, SVERI's College of Engineering, Pandharpur, Maharashtra, India\n"
        "*Corresponding Author: Piyush Madan Shinde ([NEED FROM AUTHOR: Author email])\n"
        "Repository: https://github.com/Pi25sh/DeceptionNet (pinned commit 0d4111142f4970e83bb8eeede43a5a1b08486214)"
    )
    r_aff.italic = True
    r_aff.font.size = Pt(9.5)
    r_aff.font.color.rgb = RGBColor(0x44, 0x44, 0x44)
    p_aff.paragraph_format.space_after = Pt(14)

    # Abstract
    p_absh = doc.add_paragraph()
    r_absh = p_absh.add_run("Abstract")
    r_absh.bold = True
    r_absh.font.size = Pt(11.5)
    p_absh.paragraph_format.space_after = Pt(2)

    p_abs = doc.add_paragraph()
    abstract_text = (
        "Modern enterprise cyber defense increasingly incorporates deception technology to lure, observe, and delay adversaries "
        "before they compromise production assets. However, standalone honeypots often present operational challenges: telemetry "
        "remains fragmented across heterogeneous daemon formats, manual threat mapping introduces operational latency, and recent "
        "proposals to embed generative Large Language Models directly into interactive shell execution introduce prompt injection "
        "risks and hallucinated outputs. This paper presents DeceptionNet, an open-source active defense platform built on isolated "
        "Docker microservices. DeceptionNet integrates multi-service honeypot decoys (Cowrie SSH/Telnet, Dionaea multi-protocol, and "
        "a vulnerable Flask web application) with an asynchronous log forwarder, a deterministic 34-rule MITRE ATT&CK mapping engine "
        "spanning 22 distinct techniques, monotonic additive severity scoring, and a sliding-window session correlation engine. "
        "Crucially, DeceptionNet strictly decouples the LLM from interactive decoy emulation: generative models serve exclusively "
        "as post-capture incident summarizers for operators. Platform logic is verified through an 84-test automated pytest suite "
        "validating rule boundaries, correlation invariants, and concurrent database savepoints. System operation is demonstrated "
        "through a live Docker harness execution across container bridge networks, recording 14 ingested events across 6 distinct "
        "sessions, including a persistent authenticated attack campaign of 9 events achieving a cumulative severity score of 26.0."
    )
    r_abst = p_abs.add_run(abstract_text)
    r_abst.font.size = Pt(10)
    p_abs.paragraph_format.space_after = Pt(6)

    # Keywords
    p_kw = doc.add_paragraph()
    r_kwh = p_kw.add_run("Keywords: ")
    r_kwh.bold = True
    r_kwh.font.size = Pt(9.5)
    r_kwt = p_kw.add_run("honeypots, active cyber defense, MITRE ATT&CK, telemetry normalization, cross-honeypot correlation, decoupled LLM summarization, reproducible systems.")
    r_kwt.italic = True
    r_kwt.font.size = Pt(9.5)
    p_kw.paragraph_format.space_after = Pt(14)

    def add_h1(text):
        h = doc.add_paragraph()
        r = h.add_run(text)
        r.bold = True
        r.font.size = Pt(12.5)
        r.font.color.rgb = RGBColor(0x1B, 0x36, 0x5D)
        h.paragraph_format.space_before = Pt(12)
        h.paragraph_format.space_after = Pt(3)
        return h

    def add_h2(text):
        h = doc.add_paragraph()
        r = h.add_run(text)
        r.bold = True
        r.font.size = Pt(11)
        r.font.color.rgb = RGBColor(0x2E, 0x5B, 0x88)
        h.paragraph_format.space_before = Pt(8)
        h.paragraph_format.space_after = Pt(2)
        return h

    # I. Introduction
    add_h1("I. Introduction")
    doc.add_paragraph(
        "Public and enterprise network infrastructures face relentless reconnaissance and automated exploitation attempts by external "
        "adversaries. Traditional perimeter defenses, such as network intrusion detection systems and stateful firewalls, struggle "
        "under high alert volumes and elevated false-alarm rates when processing legitimate production traffic. Active cyber defense "
        "inverts this asymmetry by deploying honeypots—decoy computational systems that emulate genuine operational services but possess "
        "no legitimate business function [1], [2]. Because benign enterprise users have no operational cause to interact with these decoys, "
        "any interaction with a honeypot is inherently anomalous, yielding high-confidence detection signals with minimal false positives [3]."
    )
    doc.add_paragraph(
        "Despite their strategic efficacy, operating multi-honeypot infrastructures in educational, research, and resource-constrained "
        "enterprise environments exposes three critical architectural hurdles:"
    )
    p_gaps = doc.add_paragraph()
    p_gaps.add_run("1. Telemetry Fragmentation: ").bold = True
    p_gaps.add_run(
        "Standard honeypots (e.g., Cowrie [4] for SSH/Telnet and Dionaea [5] for binary malware capture) emit events in disparate, "
        "proprietary JSON and binary log formats. Security operators cannot readily query or aggregate cross-honeypot telemetry "
        "without developing custom translation middleware.\n"
    )
    p_gaps.add_run("2. Semantic Attribution Overhead: ").bold = True
    p_gaps.add_run(
        "Translating raw shell commands, HTTP payloads, and connection probes into standardized threat intelligence (such as the "
        "MITRE ATT&CK enterprise matrix [6], Version 14.1 [23]) often relies on manual post-hoc analyst triage, creating an operational "
        "bottleneck during high-volume automated attacks.\n"
    )
    p_gaps.add_run("3. Risks of Direct LLM Shell Emulation: ").bold = True
    p_gaps.add_run(
        "Recent research has explored inserting Large Language Models directly into the terminal execution loop to generate dynamic, "
        "deceptive shell responses [7], [8]. While interactive LLM honeypots achieve conversational realism, they introduce severe "
        "vulnerabilities: adversaries can exploit indirect prompt injection [9] to alter system state, induce ungrounded hallucinations [10], "
        "or execute denial-of-wallet attacks through unbounded token consumption [11]. Importantly, while removing generative models from "
        "interactive terminal sockets prevents live hijacking, any post-capture summarizer that processes attacker-controlled logs remains "
        "exposed to passive prompt injection and context contamination [22]."
    )
    doc.add_paragraph(
        "To resolve these challenges without incurring the hazards of interactive generative execution, this work presents "
        "DeceptionNet, an open-source active defense platform built on containerized microservices. DeceptionNet decouples "
        "deception execution from artificial intelligence: low-latency deterministic rules handle telemetry normalization, "
        "MITRE ATT&CK mapping, and threat severity scoring, while LLMs operate strictly post-capture as asynchronous narrative "
        "summarizers. This paper makes three primary contributions:"
    )
    p_contrib = doc.add_paragraph()
    p_contrib.add_run("• Architectural Decoupling: ").bold = True
    p_contrib.add_run(
        "We implement an isolated active defense framework where decoys run within a restricted honeypot network, log forwarders "
        "bridge events into a centralized ingestion API, and generative models are strictly barred from the live network interaction loop.\n"
    )
    p_contrib.add_run("• Deterministic MITRE Attribution & Scoring: ").bold = True
    p_contrib.add_run(
        "We define a rule engine containing 34 specifications (16 command keyword rules spanning 49 signatures and 18 event-type "
        "normalization rules) mapping decoy interactions to 22 distinct MITRE ATT&CK techniques with monotonic additive severity scoring.\n"
    )
    p_contrib.add_run("• Reproducible Evaluation & Case Study: ").bold = True
    p_contrib.add_run(
        "We provide an 84-test automated pytest verification suite covering correlation invariants, database concurrency savepoints, "
        "and rule boundaries, alongside an end-to-end multi-stage attack case study executed across the live Docker compose network "
        "capturing 14 events across 6 sessions (campaign severity 26.0), backed by the committed Claim Ledger."
    )

    # II. Literature Review
    add_h1("II. Literature Review")
    doc.add_paragraph(
        "The conceptual foundations of computational deception were articulated by Cohen [12], [13] and operationalized by "
        "Spitzner [1] and Provos [14]. Low-interaction honeypots emulate network daemon banners and basic protocol handshakes with "
        "minimal resource overhead, while high-interaction honeypots expose real operating systems to capture novel exploits at the risk "
        "of host compromise [15]. Specialized medium-interaction honeypots like Cowrie [4] and Dionaea [5] strike an effective operational "
        "compromise. Multi-honeypot appliances like T-Pot [16] integrate diverse daemons but rely on heavyweight ELK stacks that lack native, "
        "weighted ATT&CK technique mapping. Alert correlation methodologies formalized by Valeur et al. [17], Ning et al. [18], and "
        "Sadoddin and Ghorbani [19] provide foundational principles for sliding-window temporal aggregation and scenario reconstruction."
    )
    doc.add_paragraph(
        "Recent investigations into LLM-driven deception, exemplified by HoneyGPT [7], Otal and Canbaz [8], and systematized by "
        "Bridges et al. [20], demonstrate the promise of dynamic terminal generation. However, fundamental security liabilities identified "
        "by Greshake et al. [9], Kang et al. [11], and Ji et al. [10] highlight how direct generative loops expose decoys to prompt injection, "
        "hallucination, and runaway costs. Furthermore, Karanjai et al. [22] recently demonstrated that even offline security log analysis "
        "is susceptible to context contamination via passive prompt injection. Table 1 summarizes the recent literature."
    )

    # Table 1: Comparative Analysis of Recent Studies
    p_t1 = doc.add_paragraph()
    r_t1 = p_t1.add_run("Table 1. Comparative Analysis of Recent Studies")
    r_t1.bold = True
    p_t1.paragraph_format.space_after = Pt(3)

    t1_table = doc.add_table(rows=9, cols=5)
    t1_table.alignment = WD_TABLE_ALIGNMENT.CENTER
    t1_hdrs = ["#", "Study", "Year", "Method / Focus", "Key Result / Operational Limitation"]
    for i, h in enumerate(t1_hdrs):
        cell = t1_table.rows[0].cells[i]
        cell.text = h
        cell.paragraphs[0].runs[0].bold = True
        set_cell_background(cell, "1B365D")
        cell.paragraphs[0].runs[0].font.color.rgb = RGBColor(0xFF, 0xFF, 0xFF)
        cell.paragraphs[0].runs[0].font.size = Pt(8.5)

    t1_data = [
        ("1", "Provos (Honeyd) [14]", "2004", "Virtual low-interaction daemon emulation", "Scalable network decoys; lack application-level shell interactivity"),
        ("2", "T-Pot Platform [16]", "2015–24", "Multi-honeypot containerized appliance", "Aggregates diverse daemons; heavyweight ELK stack; no native ATT&CK weights"),
        ("3", "Valeur et al. [17]", "2004", "Comprehensive intrusion alert correlation", "Establishes sliding-window heuristics; does not target honeypot session binding"),
        ("4", "Sadoddin & Ghorbani [19]", "2006", "Alert correlation survey & framework", "Surveys structural and statistical correlation; identifies multi-source fusion gaps"),
        ("5", "HoneyGPT (Wang et al.) [7]", "2024", "Chain-of-thought terminal shell LLM", "High conversational realism; vulnerable to indirect prompt injection and cost spikes"),
        ("6", "Otal & Canbaz [8]", "2024", "Fine-tuned open-source LLM honeypot", "Autonomous shell generation; susceptible to ungrounded hallucinated commands"),
        ("7", "Greshake et al. [9]", "2023", "Indirect prompt injection analysis", "Proves attackers can manipulate LLM behavior through untrusted data ingestion"),
        ("8", "Karanjai et al. [22]", "2026", "Passive prompt injection in SOC logs", "Demonstrates context contamination when LLMs summarize untrusted network telemetry")
    ]
    for row_idx, data in enumerate(t1_data, start=1):
        for col_idx, text in enumerate(data):
            c = t1_table.rows[row_idx].cells[col_idx]
            c.text = text
            set_cell_margins(c, top=60, bottom=60, left=90, right=90)
            if row_idx % 2 == 1:
                set_cell_background(c, "F9FAFC")
            c.paragraphs[0].runs[0].font.size = Pt(8)

    doc.add_paragraph().paragraph_format.space_after = Pt(6)

    # Research Gap
    p_rg_h = doc.add_paragraph()
    p_rg_h.add_run("Research Gap").bold = True
    p_rg_h.paragraph_format.space_after = Pt(2)

    p_rg = doc.add_paragraph()
    p_rg.add_run("• Most honeypot deployments operate as isolated silos, lacking unified normalization and cross-protocol correlation.\n")
    p_rg.add_run("• Existing multi-honeypot architectures rely on generic SIEMs that do not natively execute deterministic ATT&CK mapping with monotonic severity scoring.\n")
    p_rg.add_run("• Emerging interactive LLM honeypots expose live network sockets to prompt injection, hallucinations, and unbounded token costs.\n")
    p_rg.add_run("• Academic deception prototypes frequently lack automated unit-test verification, reproducible Docker testbeds, and committed raw execution evidence.")

    # III. Problem Statement
    add_h1("III. Problem Statement")
    doc.add_paragraph(
        "Modern enterprise perimeter defense requires rapid, automated detection and attribution of multi-stage network intrusions. "
        "While honeypots offer high-fidelity signals by penalizing unauthorized decoy interaction, enterprise deployments face severe "
        "telemetry fragmentation across heterogeneous daemons, operational triage latency, and high false-alarm overhead. Furthermore, "
        "recent efforts to embed generative LLMs into interactive shell emulation introduce critical vulnerabilities—including prompt "
        "injection, non-deterministic hallucinations, and token exhaustion. DeceptionNet resolves this challenge by providing an open-source, "
        "containerized active defense framework that pairs multi-service honeypot decoys with deterministic sub-millisecond MITRE ATT&CK "
        "attribution, monotonic severity scoring, and a sliding-window correlation engine, while restricting generative LLMs exclusively "
        "to post-capture incident reporting."
    )

    # IV. Objectives
    add_h1("IV. Objectives")
    doc.add_paragraph(
        "To address these operational challenges, DeceptionNet is engineered around ten concrete, testable objectives outlined in Table 2:"
    )

    p_t2 = doc.add_paragraph()
    r_t2 = p_t2.add_run("Table 2. Platform Objectives and Implementation Reality")
    r_t2.bold = True
    p_t2.paragraph_format.space_after = Pt(3)

    t2_table = doc.add_table(rows=11, cols=2)
    t2_table.alignment = WD_TABLE_ALIGNMENT.CENTER
    t2_hdrs = ["Objective", "What it means in practice"]
    for i, h in enumerate(t2_hdrs):
        cell = t2_table.rows[0].cells[i]
        cell.text = h
        cell.paragraphs[0].runs[0].bold = True
        set_cell_background(cell, "1B365D")
        cell.paragraphs[0].runs[0].font.color.rgb = RGBColor(0xFF, 0xFF, 0xFF)
        cell.paragraphs[0].runs[0].font.size = Pt(8.5)

    t2_data = [
        ("1. Multi-Honeypot Decoy Orchestration", "Deploy Cowrie (SSH/Telnet), Dionaea (SMB/FTP/HTTP), Custom Decoy, and Flask web app in isolated Docker networks."),
        ("2. Asynchronous Telemetry Ingestion", "Tail heterogeneous decoy logs in real time, normalize into a uniform JSON schema, and forward via HTTP to core-api."),
        ("3. Deterministic MITRE ATT&CK Attribution", "Map shell commands and protocol actions through a 34-rule hierarchy to 22 distinct ATT&CK techniques with zero LLM hallucinations."),
        ("4. Monotonic Additive Severity Scoring", "Increment session threat severity additively upon verified techniques, classifying incidents into Low, Elevated, High, and Critical tiers."),
        ("5. Sliding-Window Cross-Honeypot Correlation", "Isolate concurrent sessions within the same honeypot while fusing cross-honeypot events sharing an IP within a 5-minute window."),
        ("6. Decoupled AI Threat Intelligence", "Bar generative models from live socket emulation; invoke Gemini/Claude strictly post-capture for narrative incident synthesis."),
        ("7. Lexical Grounding Verification", "Enforce that semantic ATT&CK recommendations contain tokens (> 3 characters) present in raw event logs before PDF inclusion."),
        ("8. Operator Web Monitoring Dashboard", "Provide a responsive React 18 single-page dashboard streaming live WebSockets, timelines, and downloadable incident reports."),
        ("9. Comprehensive Automated Verification", "Execute an 84-test pytest suite validating rule boundaries, correlation invariants, and concurrent database savepoints."),
        ("10. Empirical Benchmarking & Reproducibility", "Benchmark rule engine lookup latency with hardware performance counters and execute a multi-stage live Docker attack harness.")
    ]
    for row_idx, data in enumerate(t2_data, start=1):
        for col_idx, text in enumerate(data):
            c = t2_table.rows[row_idx].cells[col_idx]
            c.text = text
            set_cell_margins(c, top=60, bottom=60, left=90, right=90)
            if row_idx % 2 == 1:
                set_cell_background(c, "F9FAFC")
            c.paragraphs[0].runs[0].font.size = Pt(8)

    doc.add_paragraph().paragraph_format.space_after = Pt(6)

    # V. Methodology
    add_h1("V. Methodology")
    doc.add_paragraph(
        "DeceptionNet processes decoy interactions through a pipeline that ingests, normalizes, attributes, scores, and correlates "
        "events into actionable threat intelligence. The core methodology encompasses three algorithmic subsystems:"
    )

    add_h2("5.1 Deterministic MITRE ATT&CK Mapping Engine")
    doc.add_paragraph(
        "To ensure predictable attribution latency and eliminate non-deterministic hallucinations during active attacks, "
        "core-api/mitre.py evaluates incoming telemetry against a deterministic two-tier rule hierarchy:"
    )
    p_rules = doc.add_paragraph()
    p_rules.add_run("• Command Keyword Rules (16 rules, 49 signatures): ").bold = True
    p_rules.add_run(
        "Evaluates shell commands using regex word-boundary matching (\\b) to avoid sub-token false positives (e.g., ensuring 'id' "
        "matches user discovery without falsely triggering on 'rapid'). Specific rules take precedence over general ones: reading "
        "'/etc/passwd' or '/etc/shadow' maps to T1003.008 (weight 5.0) before generic password manipulation maps to T1098 (weight 3.0). "
        "System enumeration commands are strictly differentiated: 'whoami' and 'id' map to T1033 (weight 1.0), whereas 'uname' maps "
        "to T1082 (weight 1.0).\n"
    )
    p_rules.add_run("• Event-Type Normalization Rules (18 rules): ").bold = True
    p_rules.add_run(
        "Evaluates normalized protocol actions directly. Rules are evaluated in specific-to-general order: 'login_failed' maps to "
        "T1110 (Brute Force, weight 0.5) and takes precedence over generic 'login' which maps to T1078 (Valid Accounts, weight 1.0). "
        "Application exploits map to high-severity techniques, including 'sqli' -> T1190 (weight 4.0), 'file_upload' -> T1505.003 "
        "(weight 3.0), and 'shellcode' -> T1210 (weight 5.0)."
    )

    add_h2("5.2 Monotonic Additive Severity Scoring")
    doc.add_paragraph(
        "Session threat severity is computed as an incremental additive function over positively identified technique weights:\n"
        "   Severity_new = round(Severity_current + w_i, 2)  for w_i > 0\n"
        "Unmapped commands or background noise contribute weight 0.0, leaving the cumulative score unchanged. As defined in dashboard/src/utils.js, "
        "severity scores map into four operational tiers: Low (< 1.0), Elevated (1.0–2.4), High (2.5–3.9), and Critical (≥ 4.0). "
        "Because the severity score is monotonically non-decreasing, once an attacker executes an exploitation step, the session permanently "
        "retains its elevated triage priority."
    )

    add_h2("5.3 Sliding-Window Session Correlation")
    doc.add_paragraph(
        "Session correlation is governed by get_or_create_session in core-api/main.py. The engine enforces two strict invariants:\n"
        "1. Intra-Honeypot Session Isolation: When an event arrives with an unseen session ID from a honeypot that already has an active "
        "session from that IP (e.g., a second Cowrie connection), the system creates a fresh session record. This prevents merging "
        "independent brute-force connections into a single synthetic session.\n"
        "2. Cross-Honeypot Campaign Fusion: When an event arrives from a different honeypot (e.g., Dionaea) sharing the same source IP "
        "within the correlation window (default: SESSION_CORRELATION_WINDOW_MINUTES = 5 minutes), the engine attaches the event to the "
        "most recent session, reconstructing the cross-protocol attack sequence."
    )

    add_h2("5.4 Decoupled AI Threat Intelligence & Reporting")
    doc.add_paragraph(
        "Generative AI capabilities (Google Gemini 2.5 Flash and Anthropic Claude 3 Haiku) are decoupled from interactive execution and "
        "invoked strictly on demand by SOC analysts. When requested, ai-service/main.py synthesizes committed session events into an "
        "executive incident narrative. An auxiliary semantic embedding service (using sentence-transformers all-MiniLM-L6-v2 across a "
        "384-dimensional FAISS index) suggests candidate ATT&CK techniques, which are subjected to a lexical grounding check verifying "
        "that technique terms appear in raw event logs before inclusion in final ReportLab PDF incident reports."
    )

    # VI. Implementation
    add_h1("VI. Implementation")
    doc.add_paragraph(
        "DeceptionNet is implemented as five containerized microservices orchestrated via Docker Compose:\n"
        "• Decoy Honeypot Subsystem (honeypot_net): Cowrie, Dionaea, Custom Decoy (ports 16379, 2525), and Attack-Target (Flask 3.1.3 on port 9090).\n"
        "• Asynchronous Telemetry Forwarders: Python forwarder daemons tailing decoy logs in real time and dispatching normalized HTTP POSTs.\n"
        "• Central Security Engine (core-api): FastAPI 0.109.2, SQLAlchemy 2.0.25, PostgreSQL 16 / SQLite 3, Uvicorn 0.27.1, OAuth2 JWT RBAC.\n"
        "• Decoupled AI Threat Intelligence Service (ai-service): Gemini/Claude summarizer, all-MiniLM-L6-v2 (384-dim), FAISS-CPU 1.8+.\n"
        "• Operator Web Dashboard (dashboard): React 18.2.0, Vite 5.1.0, Lucide-React 0.330.0, Recharts 2.15.4, Vanilla CSS.\n\n"
        "Pipeline Architecture Flow:\n"
        "Attacker Probe → Decoy Container (honeypot_net) → Shared Volume Log → Forwarder Daemon → JSON Normalization → "
        "Central Ingestion API (deceptionnet network) → Deterministic Rule Engine → Additive Scoring & Correlation → "
        "PostgreSQL Storage → Live WebSocket Broadcast → Operator Dashboard & Post-Capture AI Incident Report (PDF)."
    )

    add_h2("6.1 Sample System Output and Live Demo Trace")
    doc.add_paragraph(
        "The figures below present authentic operational outputs captured during live execution of the DeceptionNet active defense "
        "pipeline across the Docker Compose testbed. They demonstrate end-to-end execution: from adversary attack script initiation, "
        "through real-time telemetry streaming and threat scoring on the operator dashboard, to automated post-capture incident report synthesis."
    )

    # Figure 1: Attack Harness Terminal Execution
    fig1_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "results", "live_attack_terminal.png"))
    if os.path.exists(fig1_path):
        p_f1 = doc.add_paragraph()
        p_f1.alignment = WD_ALIGN_PARAGRAPH.CENTER
        doc.add_picture(fig1_path, width=Inches(5.8))
        p_f1_cap = doc.add_paragraph()
        p_f1_cap.alignment = WD_ALIGN_PARAGRAPH.CENTER
        r_f1_cap = p_f1_cap.add_run(
            "Fig. 1: Live multi-stage attack simulation execution — Automated attack script (attacker/scripts/full-attack.sh) "
            "executing inside the containerized attacker environment (172.21.0.5), chaining SQLi authentication bypass, brute-force "
            "credential guessing, command injection, path traversal, reflected XSS, and web shell upload."
        )
        r_f1_cap.italic = True
        r_f1_cap.font.size = Pt(8.5)
        p_f1_cap.paragraph_format.space_after = Pt(6)

    doc.add_paragraph(
        "Figure 1 illustrates the live execution of the multi-stage attack harness within the attacker container (172.21.0.5). "
        "The harness executes six sequential attack stages against the vulnerable web decoy (attack-target:9090). In Stage 1, an SQL "
        "injection payload (admin'--) bypasses authentication, and curl stores the resulting session cookie into a local cookie-jar. "
        "In Stage 2, five unauthenticated credential-guessing attempts are launched without cookies; each generates an independent "
        "session logged at severity 0.5. In Stages 3 through 6, post-exploitation payloads present the stored session cookie, enabling "
        "DeceptionNet to bind all subsequent exploitation events—including system reconnaissance (whoami, uname), credential dumping "
        "(/etc/passwd), file retrieval, reflected XSS, and PHP web shell upload—into a single persistent campaign session."
    )

    # Figure 2: Live Operator Dashboard
    fig2_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "data", "shots", "dashboard-main.png"))
    if os.path.exists(fig2_path):
        p_f2 = doc.add_paragraph()
        p_f2.alignment = WD_ALIGN_PARAGRAPH.CENTER
        doc.add_picture(fig2_path, width=Inches(5.8))
        p_f2_cap = doc.add_paragraph()
        p_f2_cap.alignment = WD_ALIGN_PARAGRAPH.CENTER
        r_f2_cap = p_f2_cap.add_run(
            "Fig. 2: DeceptionNet live operator dashboard — Real-time telemetry feed displaying isolated and correlated decoy sessions, "
            "source IP attribution, monotonic additive threat severity scores (Critical tier: 26.0), and automated MITRE ATT&CK technique tags."
        )
        r_f2_cap.italic = True
        r_f2_cap.font.size = Pt(8.5)
        p_f2_cap.paragraph_format.space_after = Pt(6)

    doc.add_paragraph(
        "Figure 2 displays the operator web dashboard streaming live telemetry over WebSockets. Each incoming decoy event is evaluated "
        "by the deterministic MITRE ATT&CK rule engine in under 0.06 ms. As the adversary progresses through the attack chain, the session "
        "card dynamically updates: positively identified techniques (e.g., T1003.008, T1078, T1505.003) appear as color-coded badges, and "
        "the cumulative severity score increases monotonically. The primary campaign session escalates from 4.0 (Elevated) to 26.0 (Critical), "
        "triggering prominent visual alerts for security operations staff, while unauthenticated brute-force probes remain isolated in the Low tier."
    )

    # Figure 3: Generated Incident Report
    fig3_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "results", "incident_report_preview.png"))
    if os.path.exists(fig3_path):
        p_f3 = doc.add_paragraph()
        p_f3.alignment = WD_ALIGN_PARAGRAPH.CENTER
        doc.add_picture(fig3_path, width=Inches(5.8))
        p_f3_cap = doc.add_paragraph()
        p_f3_cap.alignment = WD_ALIGN_PARAGRAPH.CENTER
        r_f3_cap = p_f3_cap.add_run(
            "Fig. 3: Decoupled AI threat intelligence and automated incident report — Generated post-capture incident summary compiling "
            "chronological session events, verified ATT&CK techniques, and operator triage recommendations without exposing generative "
            "models to the live execution loop."
        )
        r_f3_cap.italic = True
        r_f3_cap.font.size = Pt(8.5)
        p_f3_cap.paragraph_format.space_after = Pt(6)

    doc.add_paragraph(
        "Figure 3 demonstrates the output of the decoupled AI reporting service (ai-service). Once a session is concluded or flagged "
        "for analysis, an analyst can trigger automated PDF report generation. The AI engine synthesizes committed events into an "
        "executive incident summary, details session timelines and metadata, and tabulates verified ATT&CK techniques. To guarantee "
        "fidelity, every semantic recommendation is passed through a lexical grounding filter, verifying that technique keywords "
        "(> 3 characters) appear in raw event logs before inclusion in the final report."
    )

    # VII. Comparative Analysis
    add_h1("VII. Comparative Analysis")
    doc.add_paragraph(
        "Table 3 contrasts DeceptionNet's architectural properties against traditional standalone honeypots, integrated multi-honeypot "
        "distributions, and emerging interactive LLM honeypots:"
    )

    p_t3 = doc.add_paragraph()
    r_t3 = p_t3.add_run("Table 3. Comparative Architectural Analysis across Deception Paradigms")
    r_t3.bold = True
    p_t3.paragraph_format.space_after = Pt(3)

    t3_table = doc.add_table(rows=8, cols=5)
    t3_table.alignment = WD_TABLE_ALIGNMENT.CENTER
    t3_hdrs = ["Capability / Dimension", "Standalone Honeypots", "T-Pot Distribution", "Interactive LLM Decoys", "DeceptionNet (Proposed)"]
    for i, h in enumerate(t3_hdrs):
        cell = t3_table.rows[0].cells[i]
        cell.text = h
        cell.paragraphs[0].runs[0].bold = True
        set_cell_background(cell, "1B365D")
        cell.paragraphs[0].runs[0].font.color.rgb = RGBColor(0xFF, 0xFF, 0xFF)
        cell.paragraphs[0].runs[0].font.size = Pt(8.5)

    t3_data = [
        ("Telemetry Unification", "Isolated log files", "Centralized ELK stack", "Application terminal logs", "Unified JSON forwarder pipeline"),
        ("MITRE ATT&CK Attribution", "Manual analyst triage", "Generic search queries", "Non-deterministic LLM output", "Deterministic 34-rule hierarchy (22 techniques)"),
        ("Attribution Latency", "Hours / Days (post-hoc)", "Seconds (ELK index)", "1–5 seconds per command", "Sub-millisecond (mean: 10.56 µs microbenchmark)"),
        ("Threat Severity Tiering", "None (binary alert)", "Static dashboard counts", "Subjective LLM assessment", "Monotonic additive scoring (4 operational tiers)"),
        ("Prompt Injection Surface", "None (daemon emulators)", "None (daemon emulators)", "Severe (direct terminal loop)", "Eliminated from socket loop; residual in post-capture"),
        ("Automated Test Suite", "Rare / Manual", "Service healthchecks", "Empirical prompt benchmarks", "84-test automated pytest suite (100% pass)"),
        ("Deployment Overhead", "Low (single container)", "Heavyweight (>16 GB RAM)", "Moderate (GPU / Cloud API)", "Lightweight Docker microservices (~8 GB RAM)")
    ]
    for row_idx, data in enumerate(t3_data, start=1):
        for col_idx, text in enumerate(data):
            c = t3_table.rows[row_idx].cells[col_idx]
            c.text = text
            set_cell_margins(c, top=60, bottom=60, left=90, right=90)
            if row_idx % 2 == 1:
                set_cell_background(c, "F9FAFC")
            c.paragraphs[0].runs[0].font.size = Pt(8)

    doc.add_paragraph().paragraph_format.space_after = Pt(6)

    # VIII. Advantages of System
    add_h1("VIII. Advantages of System")
    p_adv = doc.add_paragraph()
    p_adv.add_run("• Deterministic Sub-Millisecond Speed: ").bold = True
    p_adv.add_run("Executes ATT&CK attribution via in-memory regex and dictionary lookups, achieving a mean evaluation latency of 10.56 µs (0.011 ms) without LLM latency penalties.\n")
    p_adv.add_run("• Decoupled AI Safety Architecture: ").bold = True
    p_adv.add_run("Excludes generative models from live socket loops, neutralizing interactive terminal hijacking while leveraging LLMs safely for post-capture incident reports.\n")
    p_adv.add_run("• Cross-Protocol Multi-Honeypot Correlation: ").bold = True
    p_adv.add_run("Fuses events across Cowrie, Dionaea, and custom decoys into unified multi-stage campaigns using a 5-minute temporal window while isolating concurrent brute-force sessions.\n")
    p_adv.add_run("• Monotonic Additive Scoring: ").bold = True
    p_adv.add_run("Accumulates positive technique weights into monotonically non-decreasing session scores, guaranteeing permanent critical visibility for exploited decoys.\n")
    p_adv.add_run("• 100% Automated Test Verification: ").bold = True
    p_adv.add_run("All architectural invariants are backed by an 84-test automated pytest suite executed with zero failures.\n")
    p_adv.add_run("• Lightweight Containerized Deployment: ").bold = True
    p_adv.add_run("Orchestrated via standard Docker Compose, enabling rapid replication across educational testbeds and enterprise perimeters on standard commodity hardware.")

    # IX. Evaluation & Results
    add_h1("IX. Evaluation & Results")
    doc.add_paragraph(
        "In accordance with strict empirical integrity, we evaluate DeceptionNet exclusively against executed unit-test suites, "
        "a live Docker network case study, and an in-memory rule table microbenchmark. We make no claims of field deployment, "
        "detection accuracy over wild attackers, or superior detection performance relative to external commercial tools."
    )

    add_h2("9.1 Automated Unit-Test Suite")
    doc.add_paragraph(
        "Platform logic is verified by an 84-test automated pytest suite in core-api/tests. All 84 tests pass with zero failures. "
        "The per-file test breakdown is summarized in Table 4:"
    )

    p_t4 = doc.add_paragraph()
    r_t4 = p_t4.add_run("Table 4. Unit-Test Verification Suite Breakdown")
    r_t4.bold = True
    p_t4.paragraph_format.space_after = Pt(3)

    t4_table = doc.add_table(rows=6, cols=3)
    t4_table.alignment = WD_TABLE_ALIGNMENT.CENTER
    t4_hdrs = ["Test Module", "Focus / Verified Behavioral Invariants", "Pass Count"]
    for i, h in enumerate(t4_hdrs):
        cell = t4_table.rows[0].cells[i]
        cell.text = h
        cell.paragraphs[0].runs[0].bold = True
        set_cell_background(cell, "1B365D")
        cell.paragraphs[0].runs[0].font.color.rgb = RGBColor(0xFF, 0xFF, 0xFF)
        cell.paragraphs[0].runs[0].font.size = Pt(8.5)

    t4_data = [
        ("core-api/tests/test_mitre.py", "Rule table dimensions, ATT&CK ID formats, keyword word-boundaries, event-type precedence", "61 passed"),
        ("core-api/tests/test_correlation.py", "Sliding-window bounds, cross-honeypot fusion, intra-honeypot isolation, concurrent savepoints", "12 passed"),
        ("core-api/tests/test_scoring.py", "Monotonic severity accumulation, noise filtering, incremental vs bulk score equivalence", "9 passed"),
        ("core-api/tests/test_evaluation_benchmark.py", "Benchmark schema validation, representative attack sequence mapping, NAT isolation", "2 passed"),
        ("Total Verification Suite", "Comprehensive verification across all core-api platform subsystems", "84 passed (100%)")
    ]
    for row_idx, data in enumerate(t4_data, start=1):
        for col_idx, text in enumerate(data):
            c = t4_table.rows[row_idx].cells[col_idx]
            c.text = text
            set_cell_margins(c, top=60, bottom=60, left=90, right=90)
            if row_idx == 5:
                c.paragraphs[0].runs[0].bold = True
                set_cell_background(c, "E8EEF5")
            elif row_idx % 2 == 1:
                set_cell_background(c, "F9FAFC")
            c.paragraphs[0].runs[0].font.size = Pt(8)

    doc.add_paragraph().paragraph_format.space_after = Pt(6)

    add_h2("9.2 Illustrative Case Study: Live Docker Network Harness Execution")
    doc.add_paragraph(
        "Provenance: The case study results presented herein were produced via a REAL_RUN execution of the automated multi-stage attack "
        "harness (attacker/scripts/full-attack.sh) inside the running Docker Compose environment. Real network traffic was transmitted "
        "from the attacker container (172.21.0.5) across honeypot_net to the attack-target container (port 9090). Interaction logs were "
        "written to a shared volume, tailed in real time by log-forwarder-target, shipped over HTTP across the deceptionnet bridge network "
        "to core-api (port 8000), and committed into PostgreSQL. The raw evidence artifacts—including the full container log stream "
        "(results/docker_compose_logs.txt), raw PostgreSQL database dump (results/postgres_dump.sql), SQLite export (results/case_study.db), "
        "and normalized JSON export (results/case_study_raw.json)—are committed directly to the repository and documented in the "
        "supplementary Claim Ledger (docs/CLAIM_LEDGER.md)."
    )
    doc.add_paragraph(
        "Session Binding & Campaign Mechanics: During Stage 1 (SQL injection login bypass), curl stores the signed Flask session cookie "
        "(session['sid']) using a cookie jar (-c $COOKIE_JAR). Subsequent post-exploitation requests in Stages 3 through 6 present this "
        "cookie (-b $COOKIE_JAR), allowing attack-target/app.py:current_sid to bind all 9 authenticated requests to the single session ID "
        "'web-172.21.0.5-364304df'. In contrast, the 5 credential stuffing attempts in Stage 2 carry no session cookie; each unauthenticated "
        "request is assigned a distinct random session ID. The complete live execution produced exactly 14 ingested events across 6 distinct "
        "sessions. The 5 credential stuffing sessions were scored at severity 0.5 each (Low tier). The primary campaign session accumulated "
        "a final severity score of 26.0 (Critical tier) across 9 stages, summarized in Table 5."
    )

    # Table 5: Case Study Steps
    p_t5 = doc.add_paragraph()
    r_t5 = p_t5.add_run("Table 5. Step-by-Step Live Attack Campaign Progression")
    r_t5.bold = True
    p_t5.paragraph_format.space_after = Pt(3)

    cs_table = doc.add_table(rows=10, cols=7)
    cs_table.alignment = WD_TABLE_ALIGNMENT.CENTER
    cs_hdrs = ["Step", "Stage", "Payload / Action", "Event", "ATT&CK Technique", "Weight", "Score"]
    for i, h in enumerate(cs_hdrs):
        cell = cs_table.rows[0].cells[i]
        cell.text = h
        cell.paragraphs[0].runs[0].bold = True
        set_cell_background(cell, "1B365D")
        cell.paragraphs[0].runs[0].font.color.rgb = RGBColor(0xFF, 0xFF, 0xFF)
        cell.paragraphs[0].runs[0].font.size = Pt(8.5)

    steps_data = [
        ("1", "1. SQLi Login Bypass", "admin'-- on /login", "sqli", "T1190 Exploit Public-Facing App", "4.0", "4.0"),
        ("2", "3. Command Injection", "ping -c 1 127.0.0.1; whoami", "command", "T1033 System Owner/User Discovery", "1.0", "5.0"),
        ("3", "3. Command Injection", "ping -c 1 127.0.0.1; uname -a", "command", "T1082 System Information Discovery", "1.0", "6.0"),
        ("4", "3. Command Injection", "ping -c 1 127.0.0.1; cat /etc/passwd", "command", "T1003.008 OS Credential Dumping", "5.0", "11.0"),
        ("5", "3. Command Injection", "ping ...; wget http://evil.example/malware.sh", "command", "T1105 Ingress Tool Transfer", "3.0", "14.0"),
        ("6", "4. Path Traversal", "cat /etc/passwd via /read", "command", "T1003.008 OS Credential Dumping", "5.0", "19.0"),
        ("7", "4. Path Traversal", "cat /var/etc/portal.conf via /read", "command", "Unmapped (Background Noise)", "0.0", "19.0"),
        ("8", "5. Reflected XSS", "/search?q=<script>alert(1)</script>", "http", "T1190 Exploit Public-Facing App", "4.0", "23.0"),
        ("9", "6. Web Shell Upload", "shell.php (29 bytes) via /upload", "file_upload", "T1505.003 Web Shell", "3.0", "26.0"),
    ]
    for row_idx, data in enumerate(steps_data, start=1):
        for col_idx, text in enumerate(data):
            c = cs_table.rows[row_idx].cells[col_idx]
            c.text = text
            set_cell_margins(c, top=60, bottom=60, left=80, right=80)
            if row_idx % 2 == 1:
                set_cell_background(c, "F9FAFC")
            c.paragraphs[0].runs[0].font.size = Pt(8)

    doc.add_paragraph().paragraph_format.space_after = Pt(6)

    add_h2("9.3 Rule Table Evaluation Latency Microbenchmark")
    doc.add_paragraph(
        "Scope & Testbed Specification: To establish empirical timing boundaries for the deterministic rule engine, an automated "
        "microbenchmark script (scripts/benchmark_rule_latency.py) was executed. This is an in-memory microbenchmark measuring pure "
        "table and regex lookup execution via Python's high-resolution performance counter (time.perf_counter_ns); it explicitly "
        "excludes network transmission and database I/O latency. The microbenchmark was executed on a dedicated testbed host equipped "
        "with an 11th Gen Intel(R) Core(TM) i5-11320H processor @ 3.20GHz (4 physical cores, 8 logical threads), 8 GB RAM, running "
        "Microsoft Windows 11 (Build 26300) and Python 3.14.6 (64-bit)."
    )
    doc.add_paragraph(
        "Microbenchmark Results: The evaluation executed 10,000 iterations across a representative corpus of 14 items comprising shell "
        "attack payloads, protocol actions, and unmapped background noise (140,000 total evaluations). The rule engine achieved a mean "
        "evaluation latency of 10.56 µs (0.01056 ms) with a standard deviation of 20.80 µs. The median latency was 2.50 µs, the 95th "
        "percentile was 34.10 µs, and the 99th percentile was 58.10 µs (0.0581 ms). Minimum observed latency was 0.20 µs, and maximum "
        "latency was 2,170.20 µs (2.17 ms). The full statistical breakdown is committed under results/rule_latency_benchmark.json."
    )

    # X. Limitations and Threats to Validity
    add_h1("X. Limitations and Threats to Validity")
    doc.add_paragraph(
        "A rigorous engineering evaluation requires candid disclosure of system boundaries and known failure modes:"
    )
    p_lim = doc.add_paragraph()
    p_lim.add_run("1. Cross-Honeypot-Only Session Merging: ").bold = True
    p_lim.add_run(
        "The sliding-window correlation engine intentionally isolates intra-honeypot connections. While this prevents collapsing "
        "independent brute-force probes from the same IP into one session, it also prevents grouping multiple distinct SSH connections "
        "executed by the same attacker over time into a unified persistent identity unless they interact with a secondary decoy.\n"
    )
    p_lim.add_run("2. NAT IP Merging: ").bold = True
    p_lim.add_run(
        "Because correlation relies on source IPv4 addresses, multiple distinct hosts behind a shared enterprise NAT or public proxy "
        "will be aggregated into a single campaign session if their activity falls within the 5-minute correlation window.\n"
    )
    p_lim.add_run("3. Command Obfuscation Vulnerability: ").bold = True
    p_lim.add_run(
        "The 16 keyword rules evaluate explicit character sequences. Sophisticated attackers employing shell variable substitution "
        "(e.g., c$u\\a\\t /e't'c/pass'w'd), base64 decoding pipes, or wildcard path expansion bypass the keyword matcher, registering "
        "weight 0.0 (Unmapped).\n"
    )
    p_lim.add_run("4. Gameable Lexical Grounding Filter: ").bold = True
    p_lim.add_run(
        "The post-capture hallucination filter in ai-service checks whether candidate technique terms (> 3 characters) appear in raw logs. "
        "An adversary who intentionally places words such as 'credential' or 'discovery' into HTTP query strings can manipulate the "
        "grounding check into certifying hallucinated semantic suggestions as verified.\n"
    )
    p_lim.add_run("5. Lab-Only Evaluation & Lack of Baseline Comparison: ").bold = True
    p_lim.add_run(
        "The platform was evaluated exclusively against scripted attack harness workflows in a local Docker testbed. The system has "
        "not been subjected to unconstrained wild internet traffic, and no empirical throughput or accuracy comparisons were conducted "
        "against commercial SIEM platforms under enterprise production loads.\n"
    )
    p_lim.add_run("6. Residual Passive Prompt Injection in Offline Summarization: ").bold = True
    p_lim.add_run(
        "Decoupling the LLM from interactive sockets prevents interactive session hijacking and runaway generation. However, because "
        "the offline summarization engine ingests attacker-controlled strings (e.g., HTTP user agents and shell parameters), the system "
        "remains susceptible to passive prompt injection and context contamination [9], [22] unless strict delimiter sanitization is applied."
    )

    # XI. Conclusion
    add_h1("XI. Conclusion")
    doc.add_paragraph(
        "DeceptionNet demonstrates an open-source, reproducible architecture for active cyber defense that harmonizes multi-honeypot "
        "orchestration, deterministic ATT&CK mapping, and decoupled generative threat summarization. By strictly excluding LLMs from "
        "the live execution loop, DeceptionNet mitigates live prompt injection risks and interactive hallucinations while preserving "
        "deterministic attribution speed (microbenchmark mean: 10.56 µs). The platform's internal consistency is validated by an "
        "84-test automated pytest suite, and its operational flow is demonstrated through a verified live Docker harness run capturing "
        "14 events across 6 sessions (cumulative campaign severity: 26.0)."
    )

    # XII. Future Research Directions
    add_h1("XII. Future Research Directions")
    doc.add_paragraph(
        "1. Automated Shell De-obfuscation Pipelines: Train and integrate lightweight normalizers to unroll variable substitutions "
        "and base64 encodings prior to deterministic rule matching.\n"
        "2. Multi-Subnet & IPv6 Correlation Expansion: Extend sliding-window grouping to accommodate enterprise autonomous system boundaries "
        "and IPv6 /64 prefix aggregation.\n"
        "3. Delimiter-Hardened Post-Capture Log Sanitization: Investigate structured prompt sandboxing and template miners to immunize "
        "offline LLM summarizers against passive prompt injection."
    )

    # Declarations
    add_h1("Declarations")
    p_dec = doc.add_paragraph()
    p_dec.add_run("Competing Interests: ").bold = True
    p_dec.add_run("The authors declare that they have no competing interests.\n")
    p_dec.add_run("Funding Information: ").bold = True
    p_dec.add_run("[NEED FROM AUTHOR: Funding sources or state 'Not Applicable']\n")
    p_dec.add_run("Author Contribution: ").bold = True
    p_dec.add_run(
        "P.M. Shinde: conceptualization, methodology, software, and writing – original draft. "
        "S. Danwe, [Co-Author 3], [Co-Author 4]: system design, literature review, evaluation, and writing – review and editing. "
        "[Project Supervisor]: supervision, validation, review and editing.\n"
    )
    p_dec.add_run("Data Availability Statement: ").bold = True
    p_dec.add_run(
        "All source code, Docker configurations, test suites, raw database dumps, and container execution logs are publicly available in the GitHub "
        "repository: https://github.com/Pi25sh/DeceptionNet (pinned commit 0d4111142f4970e83bb8eeede43a5a1b08486214). "
        "A formal supplementary Claim Ledger is committed at docs/CLAIM_LEDGER.md.\n"
    )
    p_dec.add_run("Research Involving Human and/or Animals: ").bold = True
    p_dec.add_run("Not Applicable.\n")
    p_dec.add_run("Informed Consent: ").bold = True
    p_dec.add_run("Not Applicable.")

    # XIII. References
    add_h1("XIII. References")
    references = [
        "1. Spitzner, L. (2002). Honeypots: Tracking Hackers. Addison-Wesley Professional. ISBN: 0-321-10895-7.",
        "2. Provos, N., & Holz, T. (2007). Virtual Honeypots: From Botnet Tracking to Intrusion Detection. Addison-Wesley Professional. ISBN: 978-0-321-33632-3.",
        "3. Fraunholz, D., Anton, S. D., Lipps, C., Reti, D., Krohmer, D., Pohl, F., Tammen, M., & Schotten, H. D. (2018). Demystifying deception technology: A survey. arXiv preprint arXiv:1804.06196. https://arxiv.org/abs/1804.06196",
        "4. Oosterhof, M. (2024). Cowrie: An SSH and Telnet honeypot designed to log brute force attacks and shell interaction. GitHub repository. https://github.com/cowrie/cowrie",
        "5. Baecher, P., Bächer, M., & Holz, T. (2024). Dionaea: Catching malware with low-interaction honeypots. DinoTools repository. https://github.com/DinoTools/dionaea",
        "6. Strom, B. E., Applebaum, A., Miller, D. P., Nickels, K. C., Pennington, A. G., & Thomas, C. B. (2018). MITRE ATT&CK: Design and philosophy. The MITRE Corporation, Tech. Rep. MTR180175. https://www.mitre.org/news-insights/publication-library/mitre-attck-design-and-philosophy",
        "7. Wang, Z., Ding, Z., Qin, X., Fan, Y., Sun, L., & Fan, M. (2024). HoneyGPT: Breaking the trilemma in terminal honeypots with large language models. arXiv preprint arXiv:2406.01882. https://arxiv.org/abs/2406.01882",
        "8. Otal, H. T., & Canbaz, M. A. (2024). LLM Honeypot: Leveraging large language models as advanced interactive honeypot systems. arXiv preprint arXiv:2409.08234. https://arxiv.org/abs/2409.08234",
        "9. Greshake, K., Abdelnabi, S., Mishra, S., Endres, C., Holz, T., & Fritz, M. (2023). Not what you've signed up for: Compromising real-world LLM-integrated applications with indirect prompt injection. In Proceedings of the 16th ACM Workshop on Artificial Intelligence and Security (AISEC '23) (pp. 79–90). https://doi.org/10.1145/3605764.3623985",
        "10. Ji, Z., Lee, N., Frieske, R., Yu, T., Su, D., Xu, Y., Ishii, E., Bang, Y. J., Madotto, A., & Fung, P. (2023). Survey of hallucination in natural language generation. ACM Computing Surveys, 55(12), 1–38. https://doi.org/10.1145/3571730",
        "11. Kang, D., Li, X., Stoica, I., Guestrin, C., Zaharia, M., & Hashimoto, T. (2024). Exploiting programmatic behavior of LLMs: Dual-use through standard security attacks. In Proceedings of the IEEE Security and Privacy Workshops (SPW '24) (pp. 132–143). https://doi.org/10.1109/SPW63631.2024.00018",
        "12. Cohen, F. (1998). A note on the role of deception in information protection. Computers & Security, 17(6), 483–506. https://doi.org/10.1016/S0167-4048(98)80071-0",
        "13. Cohen, F. (2000). A mathematical structure of simple defensive network deceptions. Computers & Security, 19(6), 520–528. http://all.net/journal/deception/mathdeception/mathdeception.html",
        "14. Provos, N. (2004). A virtual honeypot framework. In Proceedings of the 13th USENIX Security Symposium (pp. 1–14). https://www.usenix.org/legacy/event/sec04/tech/provos.html",
        "15. Holz, T., & Raynal, F. (2005). Detecting honeypots and other suspicious environments. In Proceedings of the 6th IEEE Information Assurance Workshop (IAW '05) (pp. 29–36). https://doi.org/10.1109/IAW.2005.1495930",
        "16. Telekom Security. (2024). T-Pot: The all-in-one multi-honeypot platform. Deutsche Telekom AG. https://github.com/telekom-security/tpotce",
        "17. Valeur, F., Vigna, G., Kruegel, C., & Kemmerer, R. A. (2004). A comprehensive approach to intrusion detection alert correlation. IEEE Transactions on Dependable and Secure Computing, 1(3), 146–169. https://doi.org/10.1109/TDSC.2004.21",
        "18. Ning, P., Cui, Y., & Reeves, D. S. (2002). Constructing attack scenarios through correlation of intrusion alerts. In Proceedings of the 9th ACM Conference on Computer and Communications Security (CCS '02) (pp. 245–254). https://doi.org/10.1145/586110.586144",
        "19. Sadoddin, R., & Ghorbani, A. A. (2006). Alert correlation survey: Framework and techniques. In Proceedings of the 2006 International Conference on Privacy, Security and Trust (PST '06) (Article 37, pp. 1–12). https://doi.org/10.1145/1501434.1501479",
        "20. Bridges, R. A., Mitchell, T. R., Muñoz, M., & Henriksson, T. (2025). SoK: Honeypots & LLMs, more than the sum of their parts? arXiv preprint arXiv:2510.25939. https://arxiv.org/abs/2510.25939",
        "21. Lewis, P., Perez, E., Piktus, A., Petroni, F., Karpukhin, V., Goyal, N., Küttler, H., Lewis, M., Yih, W., Rocktäschel, T., Riedel, S., & Kiela, D. (2020). Retrieval-augmented generation for knowledge-intensive NLP tasks. In Advances in Neural Information Processing Systems (NeurIPS 2020) (Vol. 33, pp. 9459–9474).",
        "22. Karanjai, R., Lu, Y., Madhavarao, H. H., Xu, L., & Shi, W. (2026). Context contamination in LLM analysis of network security logs: Poison with passive prompt injection and mitigation evaluation. arXiv preprint arXiv:2607.14493. https://arxiv.org/abs/2607.14493",
        "23. The MITRE Corporation. (2023). MITRE ATT&CK Enterprise Matrix (Version 14.1). https://attack.mitre.org/"
    ]
    for ref in references:
        p_ref = doc.add_paragraph(ref)
        p_ref.paragraph_format.left_indent = Inches(0.3)
        p_ref.paragraph_format.first_line_indent = Inches(-0.3)
        p_ref.paragraph_format.space_after = Pt(3)
        p_ref.runs[0].font.size = Pt(9)

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    try:
        doc.save(output_path)
        print(f"SN Computer Science manuscript generated successfully at: {output_path}")
    except PermissionError:
        alt_path = os.path.join(os.path.dirname(output_path), "DeceptionNet_SN_Computer_Science_Manuscript.docx")
        doc.save(alt_path)
        print(f"Warning: {output_path} is locked by another process (e.g. Word). Saved to: {alt_path}")

    words = abstract_text.split()
    print(f"Abstract word count: {len(words)} words (Requirement: 150-200 words)")
    assert 150 <= len(words) <= 200, f"Abstract word count {len(words)} is out of range!"


if __name__ == "__main__":
    out_file = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "docs", "DeceptionNet_SN_Computer_Science_Manuscript.docx"))
    generate_sn_manuscript(out_file)

    # Also attempt updating Submission Manuscript if not locked
    sub_file = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "docs", "DeceptionNet_Submission_Manuscript.docx"))
    try:
        import shutil
        shutil.copyfile(out_file, sub_file)
        print(f"Also synchronized: {sub_file}")
    except Exception as e:
        print(f"Note: Could not copy to {sub_file} ({e}).")

