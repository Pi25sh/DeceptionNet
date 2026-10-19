import os
import io
import base64
from docx import Document
from docx.shared import Inches, Pt, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.oxml import OxmlElement, parse_xml
from docx.oxml.ns import nsdecls, qn

def set_cell_margins(cell, top=80, bottom=80, left=110, right=110):
    tcPr = cell._tc.get_or_add_tcPr()
    tcMar = OxmlElement('w:tcMar')
    for m, val in [('w:top', top), ('w:bottom', bottom), ('w:left', left), ('w:right', right)]:
        node = OxmlElement(m)
        node.set(qn('w:w'), str(val))
        node.set(qn('w:type'), 'dxa')
        tcMar.append(node)
    tcPr.append(tcMar)

def set_cell_shading(cell, color_hex):
    shading_xml = f'<w:shd {nsdecls("w")} w:val="clear" w:color="auto" w:fill="{color_hex}"/>'
    cell._tc.get_or_add_tcPr().append(parse_xml(shading_xml))

def set_table_borders(table, color="CBD5E1"):
    tblPr = table._tbl.tblPr
    borders_xml = f'''
    <w:tblBorders {nsdecls("w")}>
        <w:top w:val="single" w:sz="4" w:space="0" w:color="{color}"/>
        <w:bottom w:val="single" w:sz="4" w:space="0" w:color="{color}"/>
        <w:insideH w:val="single" w:sz="4" w:space="0" w:color="{color}"/>
        <w:insideV w:val="none"/><w:left w:val="none"/><w:right w:val="none"/>
    </w:tblBorders>
    '''
    tblPr.append(parse_xml(borders_xml))

def add_figure_block(doc, fig_label, fig_title, fig_desc, img_filename=None):
    p_img = doc.add_paragraph()
    p_img.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p_img.paragraph_format.space_before = Pt(14)
    p_img.paragraph_format.space_after = Pt(4)
    
    loaded = False
    candidates = [
        img_filename,
        os.path.join(os.path.dirname(__file__), img_filename) if img_filename else None,
        os.path.join(os.path.dirname(__file__), "..", img_filename) if img_filename else None,
        os.path.join(os.path.dirname(__file__), "..", "results", img_filename) if img_filename else None,
    ]
    target_img = next((c for c in candidates if c and os.path.exists(c)), None)
    if target_img:
        try:
            p_img.add_run().add_picture(target_img, width=Inches(6.2))
            loaded = True
        except Exception:
            loaded = False

    if not loaded:
        tbl = doc.add_table(rows=1, cols=1)
        tbl.alignment = WD_TABLE_ALIGNMENT.CENTER
        cell = tbl.cell(0, 0)
        set_cell_margins(cell, top=160, bottom=160, left=200, right=200)
        set_cell_shading(cell, "0F172A")
        p_box = cell.paragraphs[0]
        p_box.alignment = WD_ALIGN_PARAGRAPH.CENTER
        r1 = p_box.add_run(f"[{fig_label.upper()} SCREENSHOT CAPTURE]\n")
        r1.font.bold = True
        r1.font.size = Pt(10)
        r1.font.color.rgb = RGBColor(56, 189, 248)
        r2 = p_box.add_run(f"Target: {fig_title}\n(Right-click this box in Word -> Change Picture -> choose your screenshot image)")
        r2.font.size = Pt(8.5)
        r2.font.color.rgb = RGBColor(148, 163, 184)
    
    p_cap = doc.add_paragraph()
    p_cap.paragraph_format.space_before = Pt(4)
    p_cap.paragraph_format.space_after = Pt(12)
    p_cap.paragraph_format.line_spacing = 1.15
    p_cap.paragraph_format.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
    
    r_cap_b = p_cap.add_run(f"{fig_label}: {fig_title} — ")
    r_cap_b.font.bold = True
    r_cap_b.font.size = Pt(9.5)
    r_cap_b.font.color.rgb = RGBColor(15, 23, 42)
    
    r_cap_t = p_cap.add_run(fig_desc)
    r_cap_t.font.size = Pt(9.0)
    r_cap_t.font.color.rgb = RGBColor(71, 85, 105)

doc = Document()

# Academic Standard Margins
for s in doc.sections:
    s.top_margin = s.bottom_margin = s.left_margin = s.right_margin = Inches(1.0)

doc.styles['Normal'].font.name = 'Times New Roman'
doc.styles['Normal'].font.size = Pt(10.5)

# Journal Tag
p_meta = doc.add_paragraph()
r_meta = p_meta.add_run("SN Computer Science (Springer Nature) — Research Article Manuscript")
r_meta.font.size = Pt(9)
r_meta.font.bold = True
r_meta.font.color.rgb = RGBColor(100, 100, 100)
p_meta.paragraph_format.space_after = Pt(8)

# Title
p_title = doc.add_paragraph()
r_title = p_title.add_run("DeceptionNet: A Containerized Architecture for Multi-Honeypot Telemetry Normalization, Deterministic ATT&CK Attribution, and Offline Threat Summarization")
r_title.font.size = Pt(16.5)
r_title.font.bold = True
r_title.font.color.rgb = RGBColor(15, 23, 42)
p_title.paragraph_format.space_after = Pt(6)

# Authors
p_auth = doc.add_paragraph()
p_auth.add_run("[NEED FROM AUTHOR: Project Supervisor¹], Piyush Madan Shinde²*, Shivani Danwe³, [NEED FROM AUTHOR: Co-Author 3⁴], [NEED FROM AUTHOR: Co-Author 4⁵]").font.bold = True
p_auth.paragraph_format.space_after = Pt(4)

# Affiliations
p_aff = doc.add_paragraph()
r_aff = p_aff.add_run(
    "¹ Assistant Professor, Department of Computer Science and Engineering, SVERI's College of Engineering, Pandharpur, Maharashtra, India\n"
    "²⁻⁵ Department of Computer Science and Engineering, SVERI's College of Engineering, Pandharpur, Maharashtra, India\n"
    "*Corresponding Author: Piyush Madan Shinde ([NEED FROM AUTHOR: Author email])\n"
    "Repository: https://github.com/Pi25sh/DeceptionNet (pinned commit 0d4111142f4970e83bb8eeede43a5a1b08486214)"
)
r_aff.font.size = Pt(8.5)
r_aff.font.italic = True
r_aff.font.color.rgb = RGBColor(71, 85, 105)
p_aff.paragraph_format.space_after = Pt(12)

# Abstract Box
abs_table = doc.add_table(rows=1, cols=1)
abs_table.alignment = WD_TABLE_ALIGNMENT.CENTER
abs_cell = abs_table.cell(0, 0)
set_cell_margins(abs_cell, top=140, bottom=140, left=180, right=180)
set_cell_shading(abs_cell, "F8FAFC")

p_abs = abs_cell.paragraphs[0]
p_abs.paragraph_format.line_spacing = 1.15
p_abs.paragraph_format.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
r_abs_h = p_abs.add_run("Abstract—")
r_abs_h.bold = True
p_abs.add_run(
    "Enterprise network defenders frequently deploy decoy services to detect, delay, and study unauthorized intrusion attempts before production systems are affected. In practice, however, running standalone honeypots introduces significant engineering overhead: log schemas vary widely across daemon implementations, mapping raw attacker commands to standardized threat frameworks requires manual analyst review, and recent proposals that wire Large Language Models (LLMs) directly into interactive shell sockets expose systems to prompt injection and fabricated command outputs. We present DeceptionNet, an open-source deception platform built on isolated Docker microservices. The architecture combines multiple decoy services—Cowrie for SSH and Telnet, Dionaea for multi-protocol binary capture, a custom service listener, and an intentionally vulnerable Flask web application—with an asynchronous log ingestion pipeline, a deterministic 34-rule MITRE ATT&CK attribution engine covering 22 techniques, an additive session scoring mechanism, and a 5-minute sliding-window correlation engine. Rather than placing generative models inside the live network path, DeceptionNet restricts LLMs to offline, post-capture incident reporting. Core platform logic is validated through an 84-test pytest suite covering regex boundary conditions, session correlation rules, and database concurrency savepoints. We demonstrate end-to-end operation through a live multi-stage attack execution across Docker bridge networks, capturing 14 events distributed across 6 sessions, highlighted by a 9-event authenticated exploitation sequence that reaches a cumulative severity score of 26.0.\n\n"
)
r_kw = p_abs.add_run("Keywords: ")
r_kw.bold = True
p_abs.add_run("Honeypots, Active Cyber Defense, MITRE ATT&CK Attribution, Log Normalization, Cross-Honeypot Correlation, Offline LLM Summarization, Reproducible Security Systems.")

doc.add_paragraph().paragraph_format.space_after = Pt(8)

def add_h(title):
    p = doc.add_paragraph()
    p.paragraph_format.space_before = Pt(14)
    p.paragraph_format.space_after = Pt(4)
    p.paragraph_format.keep_with_next = True
    r = p.add_run(title)
    r.font.size = Pt(12)
    r.font.bold = True
    r.font.color.rgb = RGBColor(15, 23, 42)

def add_subh(title):
    p = doc.add_paragraph()
    p.paragraph_format.space_before = Pt(8)
    p.paragraph_format.space_after = Pt(2)
    p.paragraph_format.keep_with_next = True
    r = p.add_run(title)
    r.font.size = Pt(11)
    r.font.bold = True
    r.font.italic = True
    r.font.color.rgb = RGBColor(30, 41, 59)

def add_p(text):
    p = doc.add_paragraph()
    p.paragraph_format.space_after = Pt(6)
    p.paragraph_format.line_spacing = 1.15
    p.paragraph_format.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
    p.add_run(text)

def add_b(prefix, text):
    p = doc.add_paragraph(style='List Bullet')
    p.paragraph_format.space_after = Pt(3)
    p.paragraph_format.line_spacing = 1.15
    p.paragraph_format.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
    r_b = p.add_run(prefix)
    r_b.bold = True
    p.add_run(text)

# Content Sections
add_h("I. Introduction")
add_p("Production networks connected to the public internet face continuous automated scanning, credential stuffing, and application-layer exploitation. Conventional perimeter controls, including stateful firewalls and signature-based intrusion detection systems (IDS), must inspect high volumes of benign traffic, which frequently produces alert fatigue and false positives. Honeypots reverse this operational burden. Because decoy systems serve no legitimate user traffic and hold no production value, any network connection or command execution observed on a honeypot represents unauthorized activity by definition, providing low-noise detection signals [1–3].")
add_p("When security teams move from single-daemon tests to multi-honeypot deployments across campus networks or small-to-medium enterprise environments, three engineering problems emerge:")
add_b("1. Incompatible Log Formats: ", "Established honeypot daemons such as Cowrie [4] (SSH/Telnet) and Dionaea [5] (SMB/HTTP/FTP malware capture) write telemetry in incompatible JSON structures and binary dumps. Aggregating events across protocols requires custom parsing pipelines before analysts can run unified queries.")
add_b("2. Manual Threat Attribution Delays: ", "Converting captured shell strings, HTTP query parameters, and socket probes into structured adversary behaviors—specifically the MITRE ATT&CK enterprise matrix [6] (Version 14.1 [23])—typically depends on post-hoc analyst inspection or heavy SIEM correlation rules, slowing down incident triage during automated campaigns.")
add_b("3. Vulnerabilities in Live LLM Shell Emulation: ", "Recent work has placed generative LLMs directly inside the honeypot command loop to synthesize realistic terminal outputs on the fly [7, 8]. Although dynamic text generation keeps human attackers engaged longer, wiring an LLM directly to an untrusted network socket creates a severe attack surface. Attackers can craft indirect prompt injections [9] via command arguments or HTTP headers to alter prompt instructions, trigger ungrounded model hallucinations [10], or force excessive API token usage (denial-of-wallet attacks) [11]. Even when generative models are moved out of the live execution path, any offline reporting tool that parses raw attacker strings remains vulnerable to passive prompt injection and context poisoning if inputs are not strictly validated [22].")
add_p("To address log fragmentation and attribution latency without exposing live network sockets to generative models, we designed DeceptionNet, a containerized active defense platform. In DeceptionNet, fast deterministic lookup tables handle real-time log normalization, MITRE ATT&CK attribution, and severity scoring, whereas cloud or local LLMs are called strictly on demand after session capture to draft analyst summaries. The primary contributions of this work are:")
add_b("Air-Gapped AI Decoupling: ", "We separate decoy execution from generative analysis. Decoy containers operate inside a restricted Docker bridge network (honeypot_net), lightweight Python forwarders ship normalized JSON events to a central FastAPI backend, and LLM APIs are never exposed to live attacker sockets.")
add_b("Deterministic Attribution and Monotonic Scoring: ", "We implement a two-tier rule engine comprising 34 rule definitions (16 command-matching rules covering 49 regex keyword signatures, plus 18 protocol event-type rules) that map incoming telemetry to 22 MITRE ATT&CK techniques and update session threat scores additively.")
add_b("Verified Reproducibility and Live Testbed Evaluation: ", "We release an 84-test automated pytest suite verifying rule precedence, sliding-window session correlation, and database savepoints, accompanied by a live Docker multi-stage attack trace (14 events across 6 sessions; primary campaign score 26.0) backed by committed database dumps and a formal Claim Ledger.")

add_h("II. Related Work")
add_p("Early formalizations of network deception by Cohen [12, 13] and practical deployment frameworks introduced by Spitzner [1] and Provos [14] established the division between low-interaction and high-interaction decoys. Low-interaction daemons simulate socket handshakes and basic banners with minimal CPU and memory cost, whereas high-interaction systems expose full operating system kernels at the risk of full container or host escape [15]. Medium-interaction projects such as Cowrie [4] and Dionaea [5] simulate application state machines in user space to capture shell sessions and exploit payloads safely. Aggregated distributions such as Deutsche Telekom's T-Pot [16] bundle dozens of honeypot containers with an Elasticsearch, Logstash, and Kibana (ELK) stack, but require substantial memory overhead and do not provide built-in, weighted MITRE ATT&CK session scoring out of the box. Alert correlation frameworks developed by Ning et al. [18], Valeur et al. [17], and Sadoddin and Ghorbani [19] introduced temporal sliding windows and prerequisite-consequence graphs to link isolated IDS alerts into multi-step intrusion scenarios.")
add_p("More recently, researchers have applied large language models to shell emulation. Systems such as HoneyGPT [7] and the LLM honeypot proposed by Otal and Canbaz [8]—alongside the systematization of knowledge by Bridges et al. [20]—show that transformer models can mimic Linux shell responses without maintaining full virtual machines. However, security evaluations by Greshake et al. [9], Ji et al. [10], and Kang et al. [11] demonstrate that untrusted external inputs routinely hijack LLM control flow, produce erratic outputs, and drive up inference costs. Furthermore, Karanjai et al. [22] demonstrated that passive prompt injection embedded inside network logs can corrupt offline LLM log summarizers during SOC triage. Table 1 compares representative prior work against our design goals.")

# Table 1
t1_data = [
    ["#", "Study", "Year", "Technical Focus", "Primary Capability and Operational Limitation"],
    ["1", "Provos (Honeyd) [14]", "2004", "Virtual low-interaction daemons", "Simulates thousands of IP stacks efficiently; lacks interactive shell or web application state."],
    ["2", "T-Pot Platform [16]", "2015–24", "Multi-honeypot Docker appliance", "Packages diverse decoys with ELK visualization; high RAM footprint (>16 GB) and no native additive ATT&CK scoring."],
    ["3", "Valeur et al. [17]", "2004", "Multi-step IDS alert correlation", "Formalizes temporal alert fusion; designed for network IDS signatures rather than stateful honeypot cookies/sessions."],
    ["4", "Sadoddin & Ghorbani [19]", "2006", "Alert correlation taxonomy", "Categorizes statistical and structural alert grouping; highlights difficulty of cross-sensor schema normalization."],
    ["5", "HoneyGPT (Wang et al.) [7]", "2024", "Prompt-engineered LLM shell decoy", "Generates convincing interactive terminal replies; exposes live sockets to prompt injection and API latency."],
    ["6", "Otal & Canbaz [8]", "2024", "Fine-tuned open-source LLM decoy", "Automates interactive command responses; prone to state drift and hallucinated file system outputs."],
    ["7", "Greshake et al. [9]", "2023", "Indirect prompt injection attacks", "Shows that untrusted external data streams can hijack downstream LLM instruction execution."],
    ["8", "Karanjai et al. [22]", "2026", "Passive prompt injection in SOC logs", "Demonstrates that malicious payloads stored in security logs can poison offline LLM incident summaries."]
]
p_t1 = doc.add_paragraph()
r_t1 = p_t1.add_run("Table 1. Comparison of Representative Honeypot, Correlation, and LLM Security Studies")
r_t1.font.bold = True
r_t1.font.size = Pt(9.5)

table1 = doc.add_table(rows=len(t1_data), cols=5)
table1.alignment = WD_TABLE_ALIGNMENT.CENTER
set_table_borders(table1)
for r_idx, row in enumerate(table1.rows):
    for c_idx, cell in enumerate(row.cells):
        cell.text = t1_data[r_idx][c_idx]
        set_cell_margins(cell, top=45, bottom=45, left=65, right=65)
        cp = cell.paragraphs[0]
        cp.paragraph_format.line_spacing = 1.05
        for r in cp.runs:
            r.font.size = Pt(8.5)
            if r_idx == 0:
                r.font.bold = True
    if r_idx == 0:
        for cell in row.cells:
            set_cell_shading(cell, "F1F5F9")

doc.add_paragraph().paragraph_format.space_after = Pt(6)

add_h("III. Problem Statement")
add_p("Modern enterprise perimeter defense requires rapid, automated detection and attribution of multi-stage network intrusions. While honeypots offer high-fidelity signals by penalizing unauthorized decoy interaction, enterprise deployments face severe telemetry fragmentation across heterogeneous daemons, operational triage latency, and high false-alarm overhead. Furthermore, recent efforts to embed generative LLMs into interactive shell emulation introduce critical vulnerabilities—including prompt injection, non-deterministic hallucinations, and token exhaustion. DeceptionNet resolves this challenge by providing an open-source, containerized active defense framework that pairs multi-service honeypot decoys with deterministic sub-millisecond MITRE ATT&CK attribution, monotonic severity scoring, and a sliding-window correlation engine, while restricting generative LLMs exclusively to post-capture incident reporting.")

add_h("IV. System Objectives")
add_p("To address these operational challenges, DeceptionNet is engineered around ten concrete, testable objectives outlined in Table 2.")

t2_data = [
    ["Objective", "Concrete Implementation in DeceptionNet"],
    ["1. Multi-Honeypot Decoy Orchestration", "Deploy Cowrie (SSH/Telnet), Dionaea (SMB/FTP/HTTP), Custom Decoy, and Flask web app in isolated Docker networks."],
    ["2. Asynchronous Telemetry Ingestion", "Tail heterogeneous decoy logs in real time, normalize into a uniform JSON schema, and forward via HTTP to core-api."],
    ["3. Deterministic MITRE ATT&CK Attribution", "Map shell commands and protocol actions through a 34-rule hierarchy to 22 distinct ATT&CK techniques with zero LLM hallucinations."],
    ["4. Monotonic Additive Severity Scoring", "Increment session threat severity additively upon verified techniques, classifying incidents into Low, Elevated, High, and Critical tiers."],
    ["5. Sliding-Window Cross-Honeypot Correlation", "Isolate concurrent sessions within the same honeypot while fusing cross-honeypot events sharing an IP within a 5-minute window."],
    ["6. Decoupled AI Threat Intelligence", "Bar generative models from live socket emulation; invoke Gemini/Claude strictly post-capture for narrative incident synthesis."],
    ["7. Lexical Grounding Verification", "Enforce that semantic ATT&CK recommendations contain tokens (> 3 characters) present in raw event logs before PDF inclusion."],
    ["8. Operator Web Monitoring Dashboard", "Provide a responsive React 18 single-page dashboard streaming live WebSockets, timelines, and downloadable incident reports."],
    ["9. Comprehensive Automated Verification", "Execute an 84-test pytest suite validating rule boundaries, correlation invariants, and concurrent database savepoints."],
    ["10. Empirical Benchmarking & Reproducibility", "Benchmark rule engine lookup latency with hardware performance counters and execute a multi-stage live Docker attack harness."]
]
p_t2 = doc.add_paragraph()
r_t2 = p_t2.add_run("Table 2. Platform Objectives and Implementation Reality")
r_t2.font.bold = True
r_t2.font.size = Pt(9.5)

table2 = doc.add_table(rows=len(t2_data), cols=2)
table2.alignment = WD_TABLE_ALIGNMENT.CENTER
set_table_borders(table2)
for r_idx, row in enumerate(table2.rows):
    for c_idx, cell in enumerate(row.cells):
        cell.text = t2_data[r_idx][c_idx]
        set_cell_margins(cell, top=45, bottom=45, left=65, right=65)
        cp = cell.paragraphs[0]
        cp.paragraph_format.line_spacing = 1.05
        for r in cp.runs:
            r.font.size = Pt(8.5)
            if r_idx == 0:
                r.font.bold = True
    if r_idx == 0:
        for cell in row.cells:
            set_cell_shading(cell, "F1F5F9")

doc.add_paragraph().paragraph_format.space_after = Pt(6)

add_h("V. Methodology")
add_p("DeceptionNet processes decoy interactions through a pipeline that ingests, normalizes, attributes, scores, and correlates events into actionable threat intelligence. The core methodology encompasses three algorithmic subsystems:")

add_subh("5.1 Deterministic MITRE ATT&CK Mapping Engine")
add_p("To ensure predictable attribution latency and eliminate non-deterministic hallucinations during active attacks, core-api/mitre.py evaluates incoming telemetry against a deterministic two-tier rule hierarchy:")
add_b("Command Keyword Rules (16 rules, 49 signatures): ", "Evaluates shell commands using regex word-boundary matching (\\b) to avoid sub-token false positives (e.g., ensuring 'id' matches user discovery without falsely triggering on 'rapid'). Specific rules take precedence over general ones: reading '/etc/passwd' or '/etc/shadow' maps to T1003.008 (weight 5.0) before generic password manipulation maps to T1098 (weight 3.0). System enumeration commands are strictly differentiated: 'whoami' and 'id' map to T1033 (weight 1.0), whereas 'uname' maps to T1082 (weight 1.0).")
add_b("Event-Type Normalization Rules (18 rules): ", "Evaluates normalized protocol actions directly. Rules are evaluated in specific-to-general order: 'login_failed' maps to T1110 (Brute Force, weight 0.5) and takes precedence over generic 'login' which maps to T1078 (Valid Accounts, weight 1.0). Application exploits map to high-severity techniques, including 'sqli' -> T1190 (weight 4.0), 'file_upload' -> T1505.003 (weight 3.0), and 'shellcode' -> T1210 (weight 5.0).")

add_subh("5.2 Monotonic Additive Severity Scoring")
add_p("Session threat severity is computed as an incremental additive function over positively identified technique weights:\n\nSeverity_new = round(Severity_current + w_i, 2)  for w_i > 0\n\nUnmapped commands or background noise contribute weight 0.0, leaving the cumulative score unchanged. As defined in dashboard/src/utils.js, severity scores map into four operational tiers: Low (< 1.0), Elevated (1.0–2.4), High (2.5–3.9), and Critical (≥ 4.0). Because the severity score is monotonically non-decreasing, once an attacker executes an exploitation step, the session permanently retains its elevated triage priority.")

add_subh("5.3 Sliding-Window Session Correlation")
add_p("Session correlation is governed by get_or_create_session in core-api/main.py. The engine enforces two strict invariants:")
add_b("1. Intra-Honeypot Session Isolation: ", "When an event arrives with an unseen session ID from a honeypot that already has an active session from that IP (e.g., a second Cowrie connection), the system creates a fresh session record. This prevents merging independent brute-force connections into a single synthetic session.")
add_b("2. Cross-Honeypot Campaign Fusion: ", "When an event arrives from a different honeypot (e.g., Dionaea) sharing the same source IP within the correlation window (default: SESSION_CORRELATION_WINDOW_MINUTES = 5 minutes), the engine attaches the event to the most recent session, reconstructing the cross-protocol attack sequence.")

add_subh("5.4 Decoupled AI Threat Intelligence & Reporting")
add_p("Generative AI capabilities (Google Gemini 2.5 Flash and Anthropic Claude 3 Haiku) are decoupled from interactive execution and invoked strictly on demand by SOC analysts. When requested, ai-service/main.py synthesizes committed session events into an executive incident narrative. An auxiliary semantic embedding service (using sentence-transformers all-MiniLM-L6-v2 across a 384-dimensional FAISS index) suggests candidate ATT&CK techniques, which are subjected to a lexical grounding check verifying that technique terms appear in raw event logs before inclusion in final ReportLab PDF incident reports.")

add_h("VI. Implementation")
add_p("DeceptionNet is implemented as five containerized microservices orchestrated via Docker Compose: Decoy Honeypot Subsystem (honeypot_net), Asynchronous Telemetry Forwarders, Central Security Engine (core-api), Decoupled AI Threat Intelligence Service (ai-service), and Operator Web Dashboard (dashboard).")
add_p("Pipeline Architecture Flow: Attacker Probe -> Decoy Container (honeypot_net) -> Shared Volume Log -> Forwarder Daemon -> JSON Normalization -> Central Ingestion API (deceptionnet network) -> Deterministic Rule Engine -> Additive Scoring & Correlation -> PostgreSQL Storage -> Live WebSocket Broadcast -> Operator Dashboard & Post-Capture AI Incident Report (PDF).")

add_subh("6.1 Live Operational Trace and System Outputs")
add_p("The figures below document authentic operational captures during live execution of the DeceptionNet active defense pipeline across the Docker Compose testbed. They illustrate the end-to-end telemetry lifecycle: from adversary attack script initiation, through real-time telemetry streaming and threat scoring on the operator dashboard, to automated post-capture incident report synthesis.")

# Embed Figure 1
add_figure_block(
    doc,
    fig_label="Fig. 1",
    fig_title="Live multi-stage attack simulation execution",
    fig_desc="Automated attack script (attacker/scripts/full-attack.sh) executing inside the containerized attacker environment (172.21.0.5), chaining SQLi authentication bypass, brute-force credential guessing, command injection, path traversal, reflected XSS, and web shell upload.",
    img_filename="fig1.png"
)
add_p("Figure 1 illustrates the live execution of the multi-stage attack harness within the attacker container (172.21.0.5). The harness executes six sequential attack stages against the vulnerable web decoy (attack-target:9090). In Stage 1, an SQL injection payload (admin'--) bypasses authentication, and curl stores the resulting session cookie into a local cookie-jar. In Stage 2, five unauthenticated credential-guessing attempts are launched without cookies; each generates an independent session logged at severity 0.5. In Stages 3 through 6, post-exploitation payloads present the stored session cookie, enabling DeceptionNet to bind all subsequent exploitation events—including system reconnaissance (whoami, uname), credential dumping (/etc/passwd), file retrieval, reflected XSS, and PHP web shell upload—into a single persistent campaign session.")

# Embed Figure 2
add_figure_block(
    doc,
    fig_label="Fig. 2",
    fig_title="DeceptionNet live operator dashboard",
    fig_desc="Real-time telemetry interface showing active decoy session triage (left pane) and granular session inspection (right pane) for the multi-stage attack campaign (172.21.0.5). Displays monotonic additive threat severity (Critical tier: 26.0), decoupled AI threat assessment narrative, and chronological MITRE ATT&CK technique timeline.",
    img_filename="fig2.png"
)
add_p("Figure 2 displays the operator web dashboard streaming live telemetry over WebSockets. The left pane provides an indexed list of active sessions across monitored honeypots (Cowrie SSH, Dionaea, and web decoys), isolating low-severity brute-force attempts (0.5 score, tagged T1110) from high-impact campaigns. The right pane details the selected critical session (web-172.21.0.5-364304df), exhibiting its cumulative threat score (Critical 26.0), an on-demand incident report generator, and an AI threat assessment synthesized by Google Gemini via the decoupled ai-service. Below the assessment, the chronological event stream details executed attack payloads alongside deterministic rule-engine attribution badges (T1190, T1033, T1082, T1003.008), enabling SOC analysts to inspect adversary intent with sub-millisecond rule latency.")

# Embed Figure 3
add_figure_block(
    doc,
    fig_label="Fig. 3",
    fig_title="Decoupled AI threat intelligence and automated incident report",
    fig_desc="Generated post-capture incident summary compiling chronological session events, verified ATT&CK techniques, and operator triage recommendations without exposing generative models to the live execution loop.",
    img_filename="fig3.png"
)
add_p("Figure 3 demonstrates the output of the decoupled AI reporting service (ai-service). Once a session is concluded or flagged for analysis, an analyst can trigger automated PDF report generation. The AI engine synthesizes committed events into an executive incident summary, details session timelines and metadata, and tabulates verified ATT&CK techniques. To guarantee fidelity, every semantic recommendation is passed through a lexical grounding filter, verifying that technique keywords (> 3 characters) appear in raw event logs before inclusion in the final report.")

add_h("VII. Comparative Analysis")
add_p("Table 3 contrasts DeceptionNet's architectural properties against traditional standalone honeypots, integrated multi-honeypot distributions, and emerging interactive LLM honeypots.")

t3_data = [
    ["Capability / Dimension", "Standalone Honeypots", "T-Pot Distribution", "Interactive LLM Decoys", "DeceptionNet (Proposed)"],
    ["Telemetry Unification", "Isolated log files", "Centralized ELK stack", "Application terminal logs", "Unified JSON forwarder pipeline"],
    ["MITRE ATT&CK Attribution", "Manual analyst triage", "Generic search queries", "Non-deterministic LLM output", "Deterministic 34-rule hierarchy (22 techniques)"],
    ["Attribution Latency", "Hours / Days (post-hoc)", "Seconds (ELK index)", "1–5 seconds per command", "Sub-millisecond (mean: 10.56 µs microbenchmark)"],
    ["Threat Severity Tiering", "None (binary alert)", "Static dashboard counts", "Subjective LLM assessment", "Monotonic additive scoring (4 operational tiers)"],
    ["Prompt Injection Surface", "None (daemon emulators)", "None (daemon emulators)", "Severe (direct terminal loop)", "Eliminated from socket loop; residual in post-capture"],
    ["Automated Test Suite", "Rare / Manual", "Service healthchecks", "Empirical prompt benchmarks", "84-test automated pytest suite (100% pass)"],
    ["Deployment Overhead", "Low (single container)", "Heavyweight (>16 GB RAM)", "Moderate (GPU / Cloud API)", "Lightweight Docker microservices (~8 GB RAM)"]
]
p_t3 = doc.add_paragraph()
r_t3 = p_t3.add_run("Table 3. Comparative Architectural Analysis across Deception Paradigms")
r_t3.font.bold = True
r_t3.font.size = Pt(9.5)

table3 = doc.add_table(rows=len(t3_data), cols=5)
table3.alignment = WD_TABLE_ALIGNMENT.CENTER
set_table_borders(table3)
for r_idx, row in enumerate(table3.rows):
    for c_idx, cell in enumerate(row.cells):
        cell.text = t3_data[r_idx][c_idx]
        set_cell_margins(cell, top=45, bottom=45, left=65, right=65)
        cp = cell.paragraphs[0]
        cp.paragraph_format.line_spacing = 1.05
        for r in cp.runs:
            r.font.size = Pt(8.5)
            if r_idx == 0:
                r.font.bold = True
    if r_idx == 0:
        for cell in row.cells:
            set_cell_shading(cell, "F1F5F9")

doc.add_paragraph().paragraph_format.space_after = Pt(6)

add_h("VIII. Advantages of System")
add_b("Deterministic Sub-Millisecond Speed: ", "Executes ATT&CK attribution via in-memory regex and dictionary lookups, achieving a mean evaluation latency of 10.56 µs (0.011 ms) without LLM latency penalties.")
add_b("Decoupled AI Safety Architecture: ", "Excludes generative models from live socket loops, neutralizing interactive terminal hijacking while leveraging LLMs safely for post-capture incident reports.")
add_b("Cross-Protocol Multi-Honeypot Correlation: ", "Fuses events across Cowrie, Dionaea, and custom decoys into unified multi-stage campaigns using a 5-minute temporal window while isolating concurrent brute-force sessions.")
add_b("Monotonic Additive Scoring: ", "Accumulates positive technique weights into monotonically non-decreasing session scores, guaranteeing permanent critical visibility for exploited decoys.")
add_b("100% Automated Test Verification: ", "All architectural invariants are backed by an 84-test automated pytest suite executed with zero failures.")
add_b("Lightweight Containerized Deployment: ", "Orchestrated via standard Docker Compose, enabling rapid replication across educational testbeds and enterprise perimeters on standard commodity hardware.")

add_h("IX. Evaluation & Results")
add_p("In accordance with strict empirical integrity, we evaluate DeceptionNet exclusively against executed unit-test suites, a live Docker network case study, and an in-memory rule table microbenchmark. We make no claims of field deployment, detection accuracy over wild attackers, or superior detection performance relative to external commercial tools.")

add_subh("9.1 Automated Unit-Test Suite")
add_p("Platform logic is verified by an 84-test automated pytest suite in core-api/tests. All 84 tests pass with zero failures. The per-file test breakdown is summarized in Table 4.")

t4_data = [
    ["Test Module", "Focus / Verified Behavioral Invariants", "Pass Count"],
    ["core-api/tests/test_mitre.py", "Rule table dimensions, ATT&CK ID formats, keyword word-boundaries, event-type precedence", "61 passed"],
    ["core-api/tests/test_correlation.py", "Sliding-window bounds, cross-honeypot fusion, intra-honeypot isolation, concurrent savepoints", "12 passed"],
    ["core-api/tests/test_scoring.py", "Monotonic severity accumulation, noise filtering, incremental vs bulk score equivalence", "9 passed"],
    ["core-api/tests/test_evaluation_benchmark.py", "Benchmark schema validation, representative attack sequence mapping, NAT isolation", "2 passed"],
    ["Total Verification Suite", "Comprehensive verification across all core-api platform subsystems", "84 passed (100%)"]
]
p_t4 = doc.add_paragraph()
r_t4 = p_t4.add_run("Table 4. Unit-Test Verification Suite Breakdown")
r_t4.font.bold = True
r_t4.font.size = Pt(9.5)

table4 = doc.add_table(rows=len(t4_data), cols=3)
table4.alignment = WD_TABLE_ALIGNMENT.CENTER
set_table_borders(table4)
for r_idx, row in enumerate(table4.rows):
    for c_idx, cell in enumerate(row.cells):
        cell.text = t4_data[r_idx][c_idx]
        set_cell_margins(cell, top=45, bottom=45, left=65, right=65)
        cp = cell.paragraphs[0]
        cp.paragraph_format.line_spacing = 1.05
        for r in cp.runs:
            r.font.size = Pt(8.5)
            if r_idx == 0:
                r.font.bold = True
    if r_idx == 0:
        for cell in row.cells:
            set_cell_shading(cell, "F1F5F9")

doc.add_paragraph().paragraph_format.space_after = Pt(6)

add_subh("9.2 Illustrative Case Study: Live Docker Network Harness Execution")
add_p("Provenance: The case study results presented herein were produced via a REAL_RUN execution of the automated multi-stage attack harness (attacker/scripts/full-attack.sh) inside the running Docker Compose environment. Real network traffic was transmitted from the attacker container (172.21.0.5) across honeypot_net to the attack-target container (port 9090). Interaction logs were written to a shared volume, tailed in real time by log-forwarder-target, shipped over HTTP across the deceptionnet bridge network to core-api (port 8000), and committed into PostgreSQL. The raw evidence artifacts—including the full container log stream (results/docker_compose_logs.txt), raw PostgreSQL database dump (results/postgres_dump.sql), SQLite export (results/case_study.db), and normalized JSON export (results/case_study_raw.json)—are committed directly to the repository and documented in the supplementary Claim Ledger (docs/CLAIM_LEDGER.md).")
add_p("Session Binding & Campaign Mechanics: During Stage 1 (SQL injection login bypass), curl stores the signed Flask session cookie (session['sid']) using a cookie jar (-c $COOKIE_JAR). Subsequent post-exploitation requests in Stages 3 through 6 present this cookie (-b $COOKIE_JAR), allowing attack-target/app.py:current_sid to bind all 9 authenticated requests to the single session ID 'web-172.21.0.5-364304df'. In contrast, the 5 credential stuffing attempts in Stage 2 carry no session cookie; each unauthenticated request is assigned a distinct random session ID. The complete live execution produced exactly 14 ingested events across 6 distinct sessions. The 5 credential stuffing sessions were scored at severity 0.5 each (Low tier). The primary campaign session accumulated a final severity score of 26.0 (Critical tier) across 9 stages, summarized in Table 5.")

t5_data = [
    ["Step", "Stage", "Payload / Action", "Event", "ATT&CK Technique", "Weight", "Score"],
    ["1", "1. SQLi Login Bypass", "admin'-- on /login", "sqli", "T1190 Exploit Public-Facing App", "4.0", "4.0"],
    ["2", "3. Command Injection", "ping -c 1 127.0.0.1; whoami", "command", "T1033 System Owner/User Discovery", "1.0", "5.0"],
    ["3", "3. Command Injection", "ping -c 1 127.0.0.1; uname -a", "command", "T1082 System Information Discovery", "1.0", "6.0"],
    ["4", "3. Command Injection", "ping -c 1 127.0.0.1; cat /etc/passwd", "command", "T1003.008 OS Credential Dumping", "5.0", "11.0"],
    ["5", "3. Command Injection", "ping ...; wget http://evil.example/malware.sh", "command", "T1105 Ingress Tool Transfer", "3.0", "14.0"],
    ["6", "4. Path Traversal", "cat /etc/passwd via /read", "command", "T1003.008 OS Credential Dumping", "5.0", "19.0"],
    ["7", "4. Path Traversal", "cat /var/etc/portal.conf via /read", "command", "Unmapped (Background Noise)", "0.0", "19.0"],
    ["8", "5. Reflected XSS", "/search?q=<script>alert(1)</script>", "http", "T1190 Exploit Public-Facing App", "4.0", "23.0"],
    ["9", "6. Web Shell Upload", "shell.php (29 bytes) via /upload", "file_upload", "T1505.003 Web Shell", "3.0", "26.0"]
]
p_t5 = doc.add_paragraph()
r_t5 = p_t5.add_run("Table 5. Step-by-Step Live Attack Campaign Progression")
r_t5.font.bold = True
r_t5.font.size = Pt(9.5)

table5 = doc.add_table(rows=len(t5_data), cols=7)
table5.alignment = WD_TABLE_ALIGNMENT.CENTER
set_table_borders(table5)
for r_idx, row in enumerate(table5.rows):
    for c_idx, cell in enumerate(row.cells):
        cell.text = t5_data[r_idx][c_idx]
        set_cell_margins(cell, top=40, bottom=40, left=50, right=50)
        cp = cell.paragraphs[0]
        cp.paragraph_format.line_spacing = 1.05
        for r in cp.runs:
            r.font.size = Pt(8.0)
            if r_idx == 0:
                r.font.bold = True
    if r_idx == 0:
        for cell in row.cells:
            set_cell_shading(cell, "F1F5F9")

doc.add_paragraph().paragraph_format.space_after = Pt(6)

add_subh("9.3 Rule Table Evaluation Latency Microbenchmark")
add_p("Scope & Testbed Specification: To establish empirical timing boundaries for the deterministic rule engine, an automated microbenchmark script (scripts/benchmark_rule_latency.py) was executed. This is an in-memory microbenchmark measuring pure table and regex lookup execution via Python's high-resolution performance counter (time.perf_counter_ns); it explicitly excludes network transmission and database I/O latency. The microbenchmark was executed on a dedicated testbed host equipped with an 11th Gen Intel(R) Core(TM) i5-11320H processor @ 3.20GHz (4 physical cores, 8 logical threads), 8 GB RAM, running Microsoft Windows 11 (Build 26300) and Python 3.14.6 (64-bit).")
add_p("Microbenchmark Results: The evaluation executed 10,000 iterations across a representative corpus of 14 items comprising shell attack payloads, protocol actions, and unmapped background noise (140,000 total evaluations). The rule engine achieved a mean evaluation latency of 10.56 µs (0.01056 ms) with a standard deviation of 20.80 µs. The median latency was 2.50 µs, the 95th percentile was 34.10 µs, and the 99th percentile was 58.10 µs (0.0581 ms). Minimum observed latency was 0.20 µs, and maximum latency was 2,170.20 µs (2.17 ms). The full statistical breakdown is committed under results/rule_latency_benchmark.json.")

add_h("X. Limitations and Threats to Validity")
add_p("A rigorous engineering evaluation requires candid disclosure of system boundaries and known failure modes:")
add_b("1. Cross-Honeypot-Only Session Merging: ", "The sliding-window correlation engine intentionally isolates intra-honeypot connections. While this prevents collapsing independent brute-force probes from the same IP into one session, it also prevents grouping multiple distinct SSH connections executed by the same attacker over time into a unified persistent identity unless they interact with a secondary decoy.")
add_b("2. NAT IP Merging: ", "Because correlation relies on source IPv4 addresses, multiple distinct hosts behind a shared enterprise NAT or public proxy will be aggregated into a single campaign session if their activity falls within the 5-minute correlation window.")
add_b("3. Command Obfuscation Vulnerability: ", "The 16 keyword rules evaluate explicit character sequences. Sophisticated attackers employing shell variable substitution (e.g., c$u\\a\\t /e't'c/pass'w'd), base64 decoding pipes, or wildcard path expansion bypass the keyword matcher, registering weight 0.0 (Unmapped).")
add_b("4. Gameable Lexical Grounding Filter: ", "The post-capture hallucination filter in ai-service checks whether candidate technique terms (> 3 characters) appear in raw logs. An adversary who intentionally places words such as 'credential' or 'discovery' into HTTP query strings can manipulate the grounding check into certifying hallucinated semantic suggestions as verified.")
add_b("5. Lab-Only Evaluation & Lack of Baseline Comparison: ", "The platform was evaluated exclusively against scripted attack harness workflows in a local Docker testbed. The system has not been subjected to unconstrained wild internet traffic, and no empirical throughput or accuracy comparisons were conducted against commercial SIEM platforms under enterprise production loads.")
add_b("6. Residual Passive Prompt Injection in Offline Summarization: ", "Decoupling the LLM from interactive sockets prevents interactive session hijacking and runaway generation. However, because the offline summarization engine ingests attacker-controlled strings (e.g., HTTP user agents and shell parameters), the system remains susceptible to passive prompt injection and context contamination [9], [22] unless strict delimiter sanitization is applied.")

add_h("XI. Conclusion")
add_p("DeceptionNet demonstrates an open-source, reproducible architecture for active cyber defense that harmonizes multi-honeypot orchestration, deterministic ATT&CK mapping, and decoupled generative threat summarization. By strictly excluding LLMs from the live execution loop, DeceptionNet mitigates live prompt injection risks and interactive hallucinations while preserving deterministic attribution speed (microbenchmark mean: 10.56 µs). The platform's internal consistency is validated by an 84-test automated pytest suite, and its operational flow is demonstrated through a verified live Docker harness run capturing 14 events across 6 sessions (cumulative campaign severity: 26.0).")

add_h("XII. Future Research Directions")
add_b("1. Automated Shell De-obfuscation Pipelines: ", "Train and integrate lightweight normalizers to unroll variable substitutions and base64 encodings prior to deterministic rule matching.")
add_b("2. Multi-Subnet & IPv6 Correlation Expansion: ", "Extend sliding-window grouping to accommodate enterprise autonomous system boundaries and IPv6 /64 prefix aggregation.")
add_b("3. Delimiter-Hardened Post-Capture Log Sanitization: ", "Investigate structured prompt sandboxing and template miners to immunize offline LLM summarizers against passive prompt injection.")

add_h("Declarations")
add_b("Competing Interests: ", "The authors declare that they have no competing interests.")
add_b("Funding Information: ", "[NEED FROM AUTHOR: Funding sources or state 'Not Applicable']")
add_b("Author Contribution: ", "P.M. Shinde: conceptualization, methodology, software, and writing – original draft. S. Danwe, [Co-Author 3], [Co-Author 4]: system design, literature review, evaluation, and writing – review and editing. [Project Supervisor]: supervision, validation, review and editing.")
add_b("Data Availability Statement: ", "All source code, Docker configurations, test suites, raw database dumps, and container execution logs are publicly available in the GitHub repository: https://github.com/Pi25sh/DeceptionNet (pinned commit 0d4111142f4970e83bb8eeede43a5a1b08486214). A formal supplementary Claim Ledger is committed at docs/CLAIM_LEDGER.md.")
add_b("Research Involving Human and/or Animals: ", "Not Applicable.")
add_b("Informed Consent: ", "Not Applicable.")

add_h("XIII. References")
refs = [
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
for ref in refs:
    p_ref = doc.add_paragraph()
    p_ref.paragraph_format.left_indent = Inches(0.25)
    p_ref.paragraph_format.first_line_indent = Inches(-0.25)
    p_ref.paragraph_format.space_after = Pt(4)
    p_ref.paragraph_format.line_spacing = 1.05
    r = p_ref.add_run(ref)
    r.font.size = Pt(8.5)

output_dir = os.path.dirname(os.path.abspath(__file__))
output_filename = os.path.join(output_dir, "DeceptionNet_SN_Computer_Science_Manuscript_Latest.docx")
doc.save(output_filename)
print(f"[+] Successfully generated: {output_filename}")

# Also sync to sibling docx names for convenience
for alt_name in [
    os.path.join(output_dir, "DeceptionNet_SN_Computer_Science_Manuscript.docx"),
    os.path.join(output_dir, "DeceptionNet_Submission_Manuscript.docx")
]:
    try:
        import shutil
        shutil.copyfile(output_filename, alt_name)
    except Exception:
        pass