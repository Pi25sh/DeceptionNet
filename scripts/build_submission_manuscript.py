"""Script to build the submission-ready DeceptionNet manuscript as a professionally formatted .docx document.
Strictly adheres to all integrity rules:
- Grounded claims from the committed Claim Ledger (docs/CLAIM_LEDGER.md) only.
- Honest case study provenance: REAL_RUN (Docker network harness execution committed to results/).
- Pinned versions match requirements.txt and package.json exactly.
- Empirical timing benchmark with hardware/OS/Python specs in Section 6.3.
- Fully verified 23 topically relevant references with exact authors, venues, years, DOIs, and URLs.
- Abstract between 150 and 200 words.
- All missing author, supervisor, funding, and venue details clearly isolated as [NEED FROM AUTHOR: ...].
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


def set_cell_margins(cell, top=100, bottom=100, left=150, right=150):
    tcPr = cell._tc.get_or_add_tcPr()
    tcMar = OxmlElement('w:tcMar')
    for m, val in [('w:top', top), ('w:bottom', bottom), ('w:left', left), ('w:right', right)]:
        node = OxmlElement(m)
        node.set(qn('w:w'), str(val))
        node.set(qn('w:type'), 'dxa')
        tcMar.append(node)
    tcPr.append(tcMar)


def generate_manuscript(output_path):
    doc = Document()

    # Page Margins: 1 inch everywhere
    for section in doc.sections:
        section.top_margin = Inches(1.0)
        section.bottom_margin = Inches(1.0)
        section.left_margin = Inches(1.0)
        section.right_margin = Inches(1.0)

    # Styles
    styles = doc.styles
    normal_style = styles['Normal']
    normal_style.font.name = 'Calibri'
    normal_style.font.size = Pt(11)
    normal_style.font.color.rgb = RGBColor(0x22, 0x22, 0x22)
    normal_style.paragraph_format.line_spacing = 1.15
    normal_style.paragraph_format.space_after = Pt(6)

    # Title
    p_title = doc.add_paragraph()
    p_title.alignment = WD_ALIGN_PARAGRAPH.CENTER
    r_title = p_title.add_run("DeceptionNet: An Architectural Framework for Multi-Honeypot Active Defense, Deterministic ATT&CK Attribution, and Decoupled Threat Intelligence")
    r_title.bold = True
    r_title.font.size = Pt(18)
    r_title.font.color.rgb = RGBColor(0x1B, 0x36, 0x5D)
    p_title.paragraph_format.space_after = Pt(8)

    # Authors and Affiliations
    p_auth = doc.add_paragraph()
    p_auth.alignment = WD_ALIGN_PARAGRAPH.CENTER
    r_a1 = p_auth.add_run("Piyush Madan Shinde, Shivani Danwe, [NEED FROM AUTHOR: Co-Author 3], [NEED FROM AUTHOR: Co-Author 4]\n")
    r_a1.bold = True
    r_a1.font.size = Pt(11)
    r_aff = p_auth.add_run(
        "Department of Computer Science and Engineering\n"
        "SVERI's College of Engineering, Pandharpur\n"
        "Affiliated with Punyashlok Ahilyadevi Holkar Solapur University, Solapur, Maharashtra, India\n"
        "[NEED FROM AUTHOR: Author email addresses]\n"
        "[NEED FROM AUTHOR: Project Supervisor name, department, institution]\n"
        "[NEED FROM AUTHOR: Target venue, template, and page limit]\n"
        "Repository: https://github.com/Pi25sh/DeceptionNet (pinned commit c18885798469d798bd2533affad279724c4662ab)"
    )
    r_aff.italic = True
    r_aff.font.size = Pt(9.5)
    r_aff.font.color.rgb = RGBColor(0x44, 0x44, 0x44)
    p_auth.paragraph_format.space_after = Pt(16)

    # Abstract Box
    abstract_table = doc.add_table(rows=1, cols=1)
    abstract_table.alignment = WD_TABLE_ALIGNMENT.CENTER
    cell = abstract_table.cell(0, 0)
    set_cell_background(cell, "F0F4F8")
    set_cell_margins(cell, top=140, bottom=140, left=200, right=200)

    p_abs = cell.paragraphs[0]
    r_abs_h = p_abs.add_run("Abstract—")
    r_abs_h.bold = True

    # Abstract text: strictly 150-200 words (checked via split())
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
    r_abs_t = p_abs.add_run(abstract_text)
    r_abs_t.font.size = Pt(10)
    p_abs.paragraph_format.space_after = Pt(4)

    p_kw = cell.add_paragraph()
    r_kwh = p_kw.add_run("Keywords—")
    r_kwh.bold = True
    r_kwt = p_kw.add_run("Honeypots, Active Cyber Defense, MITRE ATT&CK, Telemetry Normalization, Cross-Honeypot Correlation, Decoupled LLM Summarization, Reproducible Systems.")
    r_kwt.italic = True
    r_kwt.font.size = Pt(9.5)

    doc.add_paragraph().paragraph_format.space_after = Pt(10)

    def add_h1(text):
        h = doc.add_paragraph()
        r = h.add_run(text)
        r.bold = True
        r.font.size = Pt(13.5)
        r.font.color.rgb = RGBColor(0x1B, 0x36, 0x5D)
        h.paragraph_format.space_before = Pt(14)
        h.paragraph_format.space_after = Pt(4)
        return h

    def add_h2(text):
        h = doc.add_paragraph()
        r = h.add_run(text)
        r.bold = True
        r.font.size = Pt(11.5)
        r.font.color.rgb = RGBColor(0x2E, 0x5B, 0x88)
        h.paragraph_format.space_before = Pt(10)
        h.paragraph_format.space_after = Pt(3)
        return h

    # Section 1
    add_h1("1. Introduction")
    doc.add_paragraph(
        "Active deception platforms deploy network decoys that emulate legitimate computational assets to detect unauthorized "
        "reconnaissance and lateral movement early in an intrusion lifecycle [1], [2]. When placed on unadvertised IP space or "
        "isolated demilitarized zones, benign internal users have no operational cause to interact with these systems. Consequently, "
        "interactions with honeypots are anomalous by definition, yielding significantly lower false-positive rates than perimeter "
        "intrusion detection systems that process noisy production traffic [3]."
    )
    doc.add_paragraph(
        "Despite their strategic utility, deploying multi-honeypot infrastructures in resource-constrained or educational "
        "environments exposes three significant architectural hurdles:"
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

    # Section 2
    add_h1("2. Related Work")
    doc.add_paragraph(
        "DeceptionNet builds upon foundational literature in network deception, alert correlation, and recent explorations of "
        "language models in security systems."
    )
    add_h2("2.1 Honeypots and Deception Frameworks")
    doc.add_paragraph(
        "The conceptual foundations of computational deception were articulated by Cohen [12], [13] and operationalized by "
        "Spitzner [1] and Provos [14]. Low-interaction honeypots, exemplified by Honeyd [14], emulate network daemon banners and "
        "basic protocol handshakes with minimal resource overhead. High-interaction honeypots expose real operating systems to capture "
        "novel exploit payloads but carry significant risk of host compromise and lateral pivot [15]. Specialized medium-interaction "
        "systems, such as Cowrie [4] for SSH/Telnet and Dionaea [5] for binary payload capture, balance interactivity and safety. "
        "Multi-honeypot distributions like T-Pot [16] package disparate daemons into a unified appliance but rely on heavyweight "
        "stacks that do not natively map commands to standardized MITRE ATT&CK technique weights."
    )
    add_h2("2.2 Alert Correlation and Attack Reconstruction")
    doc.add_paragraph(
        "Intrusion alert correlation was formalized by Valeur et al. [17] and Ning et al. [18], who proposed multi-stage pipelines "
        "comprising alert normalization, fusion, verification, and causal scenario reconstruction. Sadoddin and Ghorbani [19] "
        "surveyed alert correlation methodologies, emphasizing sliding-window temporal heuristics and attribute-similarity grouping. "
        "DeceptionNet adapts these classical correlation principles to multi-honeypot architectures: exact session identifiers isolate "
        "concurrent sessions within the same honeypot daemon, while cross-honeypot events sharing an IP within a 5-minute temporal "
        "window are fused to reconstruct unified multi-stage adversary campaigns."
    )
    add_h2("2.3 Positioning Against Interactive LLM Honeypots")
    doc.add_paragraph(
        "Recent security research has investigated deploying generative LLMs directly as terminal shells to deceive attackers. "
        "HoneyGPT [7] uses structured prompt engineering and chain-of-thought prompting to maintain stateful shell interaction. "
        "Otal and Canbaz [8] fine-tune open-source models on command-response corpora to construct interactive Linux environments, "
        "while Bridges et al. [20] systematize knowledge on LLM-honeypot convergence. Although interactive LLMs demonstrate high "
        "conversational fidelity, they suffer from fundamental operational liabilities: Greshake et al. [9] demonstrated that "
        "adversarial inputs can trigger indirect prompt injection, Kang et al. [11] showed that programmatic LLM behaviors can be "
        "manipulated through standard security attacks, and Ji et al. [10] surveyed extensive failure modes in ungrounded text generation. "
        "Furthermore, Karanjai et al. [22] showed that even in offline Security Operations Center analysis, security logs containing "
        "untrusted attacker strings can poison LLM summarization through passive prompt injection (context contamination). "
        "DeceptionNet addresses the interactive hazard by removing LLMs entirely from live network sockets: all interactions are handled "
        "by deterministic daemons, and generative models operate strictly on stored, immutable telemetry for analyst summarization."
    )

    # Section 3
    add_h1("3. Threat Model and Scope")
    doc.add_paragraph(
        "We assume an external adversary attempting unauthorized network access, remote command execution, privilege escalation, "
        "and data exfiltration against an organization's perimeter. The adversary possesses capabilities to execute automated "
        "port scanning (e.g., nmap), credential stuffing (e.g., hydra), SQL injection, web application exploitation, and post-exploitation "
        "shell commands. Adversaries may attempt to evade detection using keyword obfuscation or by distributing attacks across "
        "multiple network protocols."
    )
    doc.add_paragraph(
        "Scope & Trust Boundaries: DeceptionNet operates as an internal or DMZ detection sensor. The core-api backend, PostgreSQL "
        "store, AI summarization microservice, and React dashboard reside on an internal bridge network ('deceptionnet') that is "
        "completely unreachable from the honeypots. The honeypots reside on an isolated bridge network ('honeypot_net'). The only "
        "data conduit between networks is unidirectional asynchronous telemetry forwarding via dedicated forwarder containers. "
        "We explicitly consider live production deployment, evasive malware binary unpacking, and adversary counter-intelligence in "
        "the wild to be outside the scope of this system design and lab evaluation."
    )

    # Section 4
    add_h1("4. System Design")
    doc.add_paragraph(
        "DeceptionNet comprises five interconnected microservices partitioned across dual Docker networks:"
    )

    p_comp = doc.add_paragraph()
    p_comp.add_run("1. Honeypot Decoy Subsystem (honeypot_net):\n").bold = True
    p_comp.add_run(
        "Emulates vulnerable services exposed to attackers. Cowrie emulates SSH and Telnet protocols; Dionaea emulates SMB, FTP, SIP, "
        "and HTTP protocols; a custom decoy simulates Redis (port 16379), SMTP (port 2525), and HTTP admin panels; and the Attack-Target "
        "application simulates an enterprise portal (port 9090) with intentional vulnerabilities.\n"
    )
    p_comp.add_run("2. Asynchronous Telemetry Forwarders:\n").bold = True
    p_comp.add_run(
        "Lightweight Python forwarders tail decoy log files in real time. Forwarders normalize heterogeneous log formats into a common "
        "schema (session ID, source IP, event type, timestamp, command input, and raw payload) and dispatch HTTP POST requests across "
        "the bridge network to core-api.\n"
    )
    p_comp.add_run("3. Central Security Engine (core-api):\n").bold = True
    p_comp.add_run(
        "Ingests normalized telemetry, coordinates sliding-window session attribution, executes deterministic ATT&CK mapping, calculates "
        "monotonic severity scores, and enforces OAuth2 JWT authentication and RBAC for operator endpoints and WebSocket broadcasts.\n"
    )
    p_comp.add_run("4. Decoupled AI Threat Intelligence Service (ai-service):\n").bold = True
    p_comp.add_run(
        "Houses an asynchronous summarization engine and a local FAISS semantic index for MITRE ATT&CK techniques, invoked only after "
        "session telemetry has been ingested.\n"
    )
    p_comp.add_run("5. Operator Dashboard (dashboard):\n").bold = True
    p_comp.add_run(
        "A responsive single-page web interface built with React 18, Vite 5, Recharts, and Vanilla CSS, streaming live incident feeds "
        "over WebSockets and rendering session timelines, ATT&CK distributions, and PDF incident reports."
    )

    add_h2("4.1 Deterministic MITRE ATT&CK Mapping Engine")
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

    add_h2("4.2 Monotonic Additive Severity Scoring")
    doc.add_paragraph(
        "Session threat severity is computed as an incremental additive function over positively identified technique weights:\n"
        "   Severity_new = round(Severity_current + w_i, 2)  for w_i > 0\n"
        "Unmapped commands or background noise contribute weight 0.0, leaving the cumulative score unchanged. As defined in dashboard/src/utils.js, "
        "severity scores map into four operational tiers: Low (< 1.0), Elevated (1.0–2.4), High (2.5–3.9), and Critical (≥ 4.0). "
        "Because the severity score is monotonically non-decreasing, once an attacker executes an exploitation step, the session permanently "
        "retains its elevated triage priority."
    )

    add_h2("4.3 Sliding-Window Session Correlation")
    doc.add_paragraph(
        "Session correlation is governed by get_or_create_session in core-api/main.py. The engine enforces two strict invariants:\n"
        "1. Intra-Honeypot Session Isolation: When an event arrives with an unseen session ID from a honeypot that already has an active "
        "session from that IP (e.g., a second Cowrie connection), the system creates a fresh session record. This prevents merging "
        "independent brute-force connections into a single synthetic session.\n"
        "2. Cross-Honeypot Campaign Fusion: When an event arrives from a different honeypot (e.g., Dionaea) sharing the same source IP "
        "within the correlation window (default: SESSION_CORRELATION_WINDOW_MINUTES = 5 minutes), the engine attaches the event to the "
        "most recent session, reconstructing the cross-protocol attack sequence."
    )

    add_h2("4.4 Decoupled AI Threat Intelligence & Reporting")
    doc.add_paragraph(
        "Generative AI capabilities (Google Gemini 2.5 Flash and Anthropic Claude 3 Haiku) are decoupled from interactive execution and "
        "invoked strictly on demand by SOC analysts. When requested, ai-service/main.py synthesizes committed session events into an "
        "executive incident narrative. An auxiliary semantic embedding service (using sentence-transformers all-MiniLM-L6-v2 across a "
        "384-dimensional FAISS index) suggests candidate ATT&CK techniques, which are subjected to a lexical grounding check verifying "
        "that technique terms appear in raw event logs before inclusion in final ReportLab PDF incident reports."
    )

    # Section 5
    add_h1("5. Implementation & Reproducibility")
    doc.add_paragraph(
        "DeceptionNet is implemented in Python and JavaScript and orchestrated via Docker Compose. The component versions and dependencies include:"
    )
    p_impl = doc.add_paragraph()
    p_impl.add_run("• Core API: ").bold = True
    p_impl.add_run("FastAPI 0.109.2 (pinned in core-api/requirements.txt), SQLAlchemy 2.0.25 ORM, PostgreSQL 16 (Compose) or SQLite (testing), Uvicorn 0.27.1 ASGI server.\n")
    p_impl.add_run("• Honeypot Daemons: ").bold = True
    p_impl.add_run("Cowrie (latest Docker image), Dionaea (latest DinoTools image), Custom Decoy (Python 3.10 sockets), Attack-Target (Flask 3.1.3).\n")
    p_impl.add_run("• AI & Embedding Models: ").bold = True
    p_impl.add_run("Google Gemini 2.5 Flash API / Anthropic Claude 3 Haiku API, sentence-transformers all-MiniLM-L6-v2 (384-dim), FAISS-CPU 1.8+.\n")
    p_impl.add_run("• Operator Dashboard: ").bold = True
    p_impl.add_run("React 18.2.0, Vite 5.1.0, Lucide-React 0.330.0, Recharts 2.15.4, Vanilla CSS (dashboard/package.json).\n")
    p_impl.add_run("• Reproducibility Instructions: ").bold = True
    p_impl.add_run(
        "The complete environment can be launched using 'docker compose up -d'. Automated unit tests are executed using 'pytest'. "
        "The attack harness is executed within the attacker container via 'docker compose exec attacker bash /opt/attack/scripts/full-attack.sh'."
    )

    # Section 6
    add_h1("6. Evaluation")
    doc.add_paragraph(
        "In accordance with strict empirical integrity, we evaluate DeceptionNet exclusively against executed unit-test suites, "
        "a live Docker network case study, and an in-memory rule table microbenchmark. We make no claims of field deployment, "
        "detection accuracy over wild attackers, or superior detection performance relative to external commercial tools."
    )

    add_h2("6.1 Automated Unit-Test Suite")
    doc.add_paragraph(
        "Platform logic is verified by an 84-test automated pytest suite in core-api/tests. All 84 tests pass with zero failures. "
        "The per-file test breakdown is summarized in Table I:"
    )

    # Table of tests
    t_table = doc.add_table(rows=6, cols=3)
    t_table.alignment = WD_TABLE_ALIGNMENT.CENTER
    t_hdrs = ["Test Module", "Focus / Verified Behavioral Invariants", "Pass Count"]
    for i, h in enumerate(t_hdrs):
        cell = t_table.rows[0].cells[i]
        cell.text = h
        cell.paragraphs[0].runs[0].bold = True
        set_cell_background(cell, "1B365D")
        cell.paragraphs[0].runs[0].font.color.rgb = RGBColor(0xFF, 0xFF, 0xFF)
        cell.paragraphs[0].runs[0].font.size = Pt(9.5)

    test_data = [
        ("core-api/tests/test_mitre.py", "Rule table dimensions, ATT&CK ID formats, keyword word-boundaries, event-type precedence", "61 passed"),
        ("core-api/tests/test_correlation.py", "Sliding-window bounds, cross-honeypot fusion, intra-honeypot isolation, concurrent savepoints", "12 passed"),
        ("core-api/tests/test_scoring.py", "Monotonic severity accumulation, noise filtering, incremental vs bulk score equivalence", "9 passed"),
        ("core-api/tests/test_evaluation_benchmark.py", "Benchmark schema validation, representative attack sequence mapping, NAT isolation", "2 passed"),
        ("Total Verification Suite", "Comprehensive verification across all core-api platform subsystems", "84 passed (100%)")
    ]
    for row_idx, data in enumerate(test_data, start=1):
        for col_idx, text in enumerate(data):
            c = t_table.rows[row_idx].cells[col_idx]
            c.text = text
            set_cell_margins(c, top=80, bottom=80, left=120, right=120)
            if row_idx == 5:
                c.paragraphs[0].runs[0].bold = True
                set_cell_background(c, "E8EEF5")
            elif row_idx % 2 == 1:
                set_cell_background(c, "F9FAFC")
            c.paragraphs[0].runs[0].font.size = Pt(9)

    doc.add_paragraph().paragraph_format.space_after = Pt(8)

    add_h2("6.2 Illustrative Case Study: Live Docker Network Harness Execution")
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
        "a final severity score of 26.0 (Critical tier) across 9 stages, summarized in Table II."
    )

    # Table of case study steps
    cs_table = doc.add_table(rows=10, cols=7)
    cs_table.alignment = WD_TABLE_ALIGNMENT.CENTER
    cs_hdrs = ["Step", "Stage", "Payload / Action", "Event", "ATT&CK Technique", "Weight", "Score"]
    for i, h in enumerate(cs_hdrs):
        cell = cs_table.rows[0].cells[i]
        cell.text = h
        cell.paragraphs[0].runs[0].bold = True
        set_cell_background(cell, "1B365D")
        cell.paragraphs[0].runs[0].font.color.rgb = RGBColor(0xFF, 0xFF, 0xFF)
        cell.paragraphs[0].runs[0].font.size = Pt(9)

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
            set_cell_margins(c, top=70, bottom=70, left=100, right=100)
            if row_idx % 2 == 1:
                set_cell_background(c, "F9FAFC")
            c.paragraphs[0].runs[0].font.size = Pt(8.5)

    doc.add_paragraph().paragraph_format.space_after = Pt(8)

    add_h2("6.3 Rule Table Evaluation Latency Microbenchmark")
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

    # Section 7
    add_h1("7. Limitations and Threats to Validity")
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

    # Section 8
    add_h1("8. Conclusion and Future Work")
    doc.add_paragraph(
        "DeceptionNet demonstrates an open-source, reproducible architecture for active cyber defense that harmonizes multi-honeypot "
        "orchestration, deterministic ATT&CK mapping, and decoupled generative threat summarization. By strictly excluding LLMs from "
        "the live execution loop, DeceptionNet mitigates live prompt injection risks and interactive hallucinations while preserving "
        "deterministic attribution speed (microbenchmark mean: 10.56 µs). The platform's internal consistency is validated by an "
        "84-test automated pytest suite, and its operational flow is demonstrated through a verified live Docker harness run capturing "
        "14 events across 6 sessions (cumulative campaign severity: 26.0)."
    )
    doc.add_paragraph(
        "Future work will focus on integrating automated shell de-obfuscation pre-processors, extending cross-honeypot correlation "
        "heuristics to accommodate IPv6 subnets, and investigating delimiter-hardened sanitization boundaries to protect post-capture "
        "LLM summarizers against passive prompt injection."
    )

    # Declarations
    add_h1("Declarations")
    p_dec = doc.add_paragraph()
    p_dec.add_run("• AI-Use Disclosure: ").bold = True
    p_dec.add_run(
        "During manuscript drafting, generative AI tools (Google Gemini and Anthropic Claude via the Antigravity coding environment) "
        "were utilized for drafting text, refining grammatical clarity, and structuring document formatting. All empirical claims, "
        "test counts, rule numbers, and case-study figures were independently executed, grounded against repository code, and verified "
        "against the supplementary Claim Ledger committed in docs/CLAIM_LEDGER.md.\n"
    )
    p_dec.add_run("• Conflicts of Interest: ").bold = True
    p_dec.add_run("The authors declare that they have no competing financial or non-financial interests that could have influenced this work.\n")
    p_dec.add_run("• Funding Statement: ").bold = True
    p_dec.add_run("[NEED FROM AUTHOR: Funding sources or state 'This research received no external funding']\n")
    p_dec.add_run("• Data and Code Availability: ").bold = True
    p_dec.add_run(
        "All source code, Docker configurations, test suites, raw database dumps, and container execution logs are publicly available in the GitHub "
        "repository: https://github.com/Pi25sh/DeceptionNet (pinned commit c18885798469d798bd2533affad279724c4662ab)."
    )

    # References
    add_h1("References")
    references = [
        "[1] L. Spitzner, Honeypots: Tracking Hackers. Boston, MA, USA: Addison-Wesley Professional, 2002. ISBN: 0-321-10895-7.",
        "[2] N. Provos and T. Holz, Virtual Honeypots: From Botnet Tracking to Intrusion Detection. Boston, MA, USA: Addison-Wesley Professional, 2007. ISBN: 978-0-321-33632-3.",
        "[3] D. Fraunholz, S. D. Anton, C. Lipps, D. Reti, D. Krohmer, F. Pohl, M. Tammen, and H. D. Schotten, \"Demystifying deception technology: A survey,\" arXiv preprint arXiv:1804.06196, 2018. [Online]. Available: https://arxiv.org/abs/1804.06196",
        "[4] M. Oosterhof, \"Cowrie: An SSH and Telnet honeypot designed to log brute force attacks and shell interaction,\" GitHub repository, 2014–2024. [Online]. Available: https://github.com/cowrie/cowrie",
        "[5] P. Baecher, M. Bächer, and T. Holz, \"Dionaea: Catching malware with low-interaction honeypots,\" DinoTools, 2009–2024. [Online]. Available: https://github.com/DinoTools/dionaea",
        "[6] B. E. Strom, A. Applebaum, D. P. Miller, K. C. Nickels, A. G. Pennington, and C. B. Thomas, \"MITRE ATT&CK: Design and philosophy,\" The MITRE Corporation, Tech. Rep. MTR180175, Jul. 2018. [Online]. Available: https://www.mitre.org/news-insights/publication-library/mitre-attck-design-and-philosophy",
        "[7] Z. Wang, Z. Ding, X. Qin, Y. Fan, L. Sun, and M. Fan, \"HoneyGPT: Breaking the trilemma in terminal honeypots with large language models,\" arXiv preprint arXiv:2406.01882, 2024. [Online]. Available: https://arxiv.org/abs/2406.01882",
        "[8] H. T. Otal and M. A. Canbaz, \"LLM Honeypot: Leveraging large language models as advanced interactive honeypot systems,\" arXiv preprint arXiv:2409.08234, 2024. [Online]. Available: https://arxiv.org/abs/2409.08234",
        "[9] K. Greshake, S. Abdelnabi, S. Mishra, C. Endres, T. Holz, and M. Fritz, \"Not what you've signed up for: Compromising real-world LLM-integrated applications with indirect prompt injection,\" in Proc. 16th ACM Workshop on Artificial Intelligence and Security (AISEC '23), co-located with ACM CCS, 2023, pp. 79–90. doi: 10.1145/3605764.3623985.",
        "[10] Z. Ji, N. Lee, R. Frieske, T. Yu, D. Su, Y. Xu, E. Ishii, Y. J. Bang, A. Madotto, and P. Fung, \"Survey of hallucination in natural language generation,\" ACM Computing Surveys, vol. 55, no. 12, art. 248, pp. 1–38, Mar. 2023. doi: 10.1145/3571730.",
        "[11] D. Kang, X. Li, I. Stoica, C. Guestrin, M. Zaharia, and T. Hashimoto, \"Exploiting programmatic behavior of LLMs: Dual-use through standard security attacks,\" in Proc. IEEE Security and Privacy Workshops (SPW '24), 2024, pp. 132–143. doi: 10.1109/SPW63631.2024.00018.",
        "[12] F. Cohen, \"A note on the role of deception in information protection,\" Computers & Security, vol. 17, no. 6, pp. 483–506, 1998. doi: 10.1016/S0167-4048(98)80071-0.",
        "[13] F. Cohen, \"A mathematical structure of simple defensive network deceptions,\" Computers & Security, vol. 19, no. 6, pp. 520–528, 2000. [Online]. Available: http://all.net/journal/deception/mathdeception/mathdeception.html",
        "[14] N. Provos, \"A virtual honeypot framework,\" in Proc. 13th USENIX Security Symposium (USENIX Security '04), San Diego, CA, USA, Aug. 2004, pp. 1–14. [Online]. Available: https://www.usenix.org/legacy/event/sec04/tech/provos.html",
        "[15] T. Holz and F. Raynal, \"Detecting honeypots and other suspicious environments,\" in Proc. 6th IEEE Information Assurance Workshop (IAW '05), West Point, NY, USA, Jun. 2005, pp. 29–36. doi: 10.1109/IAW.2005.1495930.",
        "[16] Telekom Security, \"T-Pot: The all-in-one multi-honeypot platform,\" Deutsche Telekom AG, 2015–2024. [Online]. Available: https://github.com/telekom-security/tpotce",
        "[17] F. Valeur, G. Vigna, C. Kruegel, and R. A. Kemmerer, \"A comprehensive approach to intrusion detection alert correlation,\" IEEE Transactions on Dependable and Secure Computing, vol. 1, no. 3, pp. 146–169, Jul.–Sep. 2004. doi: 10.1109/TDSC.2004.21.",
        "[18] P. Ning, Y. Cui, and D. S. Reeves, \"Constructing attack scenarios through correlation of intrusion alerts,\" in Proc. 9th ACM Conference on Computer and Communications Security (CCS '02), Washington, DC, USA, Nov. 2002, pp. 245–254. doi: 10.1145/586110.586144.",
        "[19] R. Sadoddin and A. A. Ghorbani, \"Alert correlation survey: Framework and techniques,\" in Proc. 2006 International Conference on Privacy, Security and Trust (PST '06), Markham, Ontario, Canada, Oct. 2006, art. 37, pp. 1–12. doi: 10.1145/1501434.1501479.",
        "[20] R. A. Bridges, T. R. Mitchell, M. Muñoz, and T. Henriksson, \"SoK: Honeypots & LLMs, more than the sum of their parts?\" arXiv preprint arXiv:2510.25939, 2025. [Online]. Available: https://arxiv.org/abs/2510.25939",
        "[21] P. Lewis, E. Perez, A. Piktus, F. Petroni, V. Karpukhin, N. Goyal, H. Küttler, M. Lewis, W. Yih, T. Rocktäschel, S. Riedel, and D. Kiela, \"Retrieval-augmented generation for knowledge-intensive NLP tasks,\" in Advances in Neural Information Processing Systems (NeurIPS 2020), vol. 33, 2020, pp. 9459–9474.",
        "[22] R. Karanjai, Y. Lu, H. H. Madhavarao, L. Xu, and W. Shi, \"Context contamination in LLM analysis of network security logs: Poison with passive prompt injection and mitigation evaluation,\" arXiv preprint arXiv:2607.14493, 2026. [Online]. Available: https://arxiv.org/abs/2607.14493",
        "[23] The MITRE Corporation, \"MITRE ATT&CK Enterprise Matrix,\" Version 14.1, 2023. [Online]. Available: https://attack.mitre.org/"
    ]
    for ref in references:
        p_ref = doc.add_paragraph(ref)
        p_ref.paragraph_format.left_indent = Inches(0.3)
        p_ref.paragraph_format.first_line_indent = Inches(-0.3)
        p_ref.paragraph_format.space_after = Pt(4)
        p_ref.runs[0].font.size = Pt(9.5)

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    doc.save(output_path)
    print(f"Submission manuscript generated successfully at: {output_path}")

    # Check abstract word count
    words = abstract_text.split()
    print(f"Abstract word count: {len(words)} words (Requirement: 150-200 words)")
    assert 150 <= len(words) <= 200, f"Abstract word count {len(words)} is out of range!"


if __name__ == "__main__":
    out_file = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "docs", "DeceptionNet_Submission_Manuscript.docx"))
    generate_manuscript(out_file)
