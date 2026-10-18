from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List, Optional
import os
try:
    import anthropic
except ImportError:
    anthropic = None
import requests

from embeddings_index import get_index, initialize_index

app = FastAPI(title="DeceptionNet AI Service")

# Initialize LLM support (supports Google Gemini and Anthropic Claude)
anthropic_api_key = os.environ.get("ANTHROPIC_API_KEY")
client = None
if anthropic and anthropic_api_key and anthropic_api_key.startswith("sk-ant"):
    try:
        client = anthropic.Anthropic(api_key=anthropic_api_key)
    except Exception as e:
        print(f"Anthropic init error: {e}")


def get_gemini_api_key() -> Optional[str]:
    gemini_key = os.environ.get("GEMINI_API_KEY") or os.environ.get("GOOGLE_API_KEY")
    if gemini_key:
        return gemini_key
    # Handle Gemini keys placed inside ANTHROPIC_API_KEY (e.g. AQ.* or AIza*)
    if anthropic_api_key and (anthropic_api_key.startswith("AQ.") or anthropic_api_key.startswith("AIza")):
        return anthropic_api_key
    return None


def is_llm_configured() -> bool:
    return bool(get_gemini_api_key() or client)


def call_llm(prompt: str, system_instruction: str = "You are a helpful cybersecurity analyst.", max_tokens: int = 1000) -> Optional[str]:
    """Call Google Gemini or Anthropic Claude depending on configured API keys."""
    gemini_key = get_gemini_api_key()
    if gemini_key:
        url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key={gemini_key}"
        payload = {
            "contents": [{"parts": [{"text": prompt}]}],
            "systemInstruction": {"parts": [{"text": system_instruction}]},
            "generationConfig": {"maxOutputTokens": max_tokens, "temperature": 0.0}
        }
        res = requests.post(url, json=payload, timeout=30)
        res.raise_for_status()
        data = res.json()
        candidates = data.get("candidates", [])
        if candidates and "content" in candidates[0]:
            parts = candidates[0]["content"].get("parts", [])
            if parts:
                return parts[0].get("text", "")
        return None

    if client:
        response = client.messages.create(
            model="claude-3-haiku-20240307",
            max_tokens=max_tokens,
            temperature=0,
            system=system_instruction,
            messages=[{"role": "user", "content": prompt}]
        )
        return response.content[0].text

    return None

# Initialize MITRE embeddings index on startup
@app.on_event("startup")
async def startup_event():
    initialize_index()


class SummaryRequest(BaseModel):
    events: List[str]


class SemanticMitreRequest(BaseModel):
    events: List[dict]  # [{"timestamp": "...", "event_type": "...", "message": "..."}, ...]


class SemanticMitreResponse(BaseModel):
    techniques: List[dict]  # [{"technique": "T1078 - Valid Accounts", "confidence": 0.87, "weight": 1.0, "id": "T1078"}, ...]


class ReportNarrativeRequest(BaseModel):
    summary: str
    techniques: List[dict]  # [{"technique": "...", "source": "rule|semantic", "confidence": 0.87}, ...]


class ReportNarrativeResponse(BaseModel):
    narrative: str


@app.post("/summarize")
def summarize_session(req: SummaryRequest):
    """Generate a concise 2-3 sentence summary of attacker activity."""
    if not is_llm_configured():
        return {"summary": f"Simulated AI Summary: The attacker generated {len(req.events)} events. Please configure GEMINI_API_KEY or ANTHROPIC_API_KEY to enable real summaries."}

    if not req.events:
        return {"summary": "No events found in this session."}

    prompt = f"""You are a cybersecurity analyst. Review the following timeline of events from an SSH honeypot.
Provide a concise, 2-3 sentence plain-language summary of what the attacker was trying to accomplish.
Base your summary strictly on the provided log. Do not speculate beyond what is in the data.

Events:
{chr(10).join(req.events)}
"""

    try:
        summary_text = call_llm(prompt, system_instruction="You are a helpful cybersecurity analyst.", max_tokens=1000)
        if summary_text:
            return {"summary": summary_text}
        return {"summary": f"Simulated AI Summary: The attacker generated {len(req.events)} events."}
    except Exception as e:
        print(f"LLM API error: {e}")
        return {"summary": f"Failed to generate summary: {str(e)}"}


@app.post("/api/v1/ai/semantic-mitre", response_model=SemanticMitreResponse)
def semantic_mitre(req: SemanticMitreRequest):
    """Given a session's events, return top-matching MITRE techniques by semantic similarity.

    Returns techniques with confidence scores. The core-api will apply grounding check.
    """
    if not req.events:
        return {"techniques": []}

    # Combine event texts for embedding
    event_texts = []
    for e in req.events:
        parts = []
        if e.get("timestamp"):
            parts.append(f"Time: {e['timestamp']}")
        if e.get("event_type"):
            parts.append(f"Type: {e['event_type']}")
        if e.get("message"):
            parts.append(e["message"])
        event_texts.append(" | ".join(parts))

    combined_text = "\n".join(event_texts)

    # Search FAISS index
    index = get_index()
    results = index.search(combined_text, top_k=15)

    # Format response with technique info and confidence
    techniques = []
    for r in results:
        techniques.append({
            "technique": f"{r['id']} - {r['name']}",
            "confidence": r["confidence"],
            "weight": 1.0,  # Default weight, core-api can adjust
            "id": r["id"],
            "tactics": r.get("tactics", []),
            "url": r.get("url", "")
        })

    return {"techniques": techniques}


def _grounding_check(events: List[dict], techniques: List[dict]) -> List[dict]:
    """
    Grounding check: strip or flag techniques not backed by session events.

    This is a heuristic check - it verifies that each technique has some
    semantic overlap with the actual event data.
    """
    if not events or not techniques:
        return techniques

    # Build searchable text from events
    event_text = " ".join([
        f"{e.get('event_type', '')} {e.get('message', '')}"
        for e in events
    ]).lower()

    grounded = []
    for tech in techniques:
        tech_id = tech.get("id") or tech.get("technique", "").split(" - ")[0]
        tech_name = tech.get("technique", "").lower()

        # Check if technique ID or key terms appear in event text
        # This is a simple heuristic - in production, could use more sophisticated NLP
        id_parts = tech_id.replace(".", " ").split()
        name_parts = tech_name.split()

        # Look for technique ID parts or key tactic terms in events
        matched = False
        for part in id_parts + name_parts:
            if len(part) > 3 and part in event_text:
                matched = True
                break

        # Also check tactics
        tactics = tech.get("tactics", [])
        for tactic in tactics:
            if tactic.lower() in event_text:
                matched = True
                break

        if matched:
            tech["grounded"] = True
            grounded.append(tech)
        else:
            tech["grounded"] = False
            # Still include but flagged - core-api decides whether to use
            grounded.append(tech)

    return grounded


@app.post("/api/v1/ai/report-narrative", response_model=ReportNarrativeResponse)
def report_narrative(req: ReportNarrativeRequest):
    """Generate a narrative paragraph for the PDF report from summary + techniques."""
    if not is_llm_configured():
        # Fallback narrative
        rule_techs = [t for t in req.techniques if t.get("source") == "rule"]
        semantic_techs = [t for t in req.techniques if t.get("source") == "semantic"]
        parts = []
        if rule_techs:
            parts.append(f"Rule-based analysis identified {len(rule_techs)} MITRE techniques.")
        if semantic_techs:
            parts.append(f"Semantic analysis suggested {len(semantic_techs)} additional techniques.")
        return {"narrative": " ".join(parts) + " " + req.summary}

    # Build technique list for prompt
    tech_lines = []
    for t in req.techniques:
        source_label = "[rule-based]" if t.get("source") == "rule" else "[semantic]"
        conf = f" (confidence: {t.get('confidence', 0):.2f})" if t.get("confidence") else ""
        tech_lines.append(f"- {t.get('technique', 'Unknown')} {source_label}{conf}")

    techniques_text = "\n".join(tech_lines) if tech_lines else "No techniques identified."

    prompt = f"""You are a cybersecurity analyst writing an incident report narrative.

Given:
1. An executive summary of the attack
2. A list of identified MITRE ATT&CK techniques (some rule-based, some semantic-suggested)

Write a single cohesive narrative paragraph (3-5 sentences) that:
- Weaves together the summary and techniques naturally
- Distinguishes between rule-based and semantic-suggested techniques
- Uses professional cybersecurity language
- Does not speculate beyond the provided data
- Flows as a single paragraph

Executive Summary:
{req.summary}

Identified Techniques:
{techniques_text}

Write the narrative paragraph:"""

    try:
        narrative_text = call_llm(
            prompt,
            system_instruction="You are a helpful cybersecurity analyst writing incident report narratives.",
            max_tokens=1000
        )
        if narrative_text:
            return {"narrative": narrative_text}
        rule_techs = [t for t in req.techniques if t.get("source") == "rule"]
        semantic_techs = [t for t in req.techniques if t.get("source") == "semantic"]
        parts = []
        if rule_techs:
            parts.append(f"Rule-based analysis identified {len(rule_techs)} MITRE techniques.")
        if semantic_techs:
            parts.append(f"Semantic analysis suggested {len(semantic_techs)} additional techniques.")
        return {"narrative": " ".join(parts) + " " + req.summary}
    except Exception as e:
        print(f"LLM API error: {e}")
        # Fallback
        rule_techs = [t for t in req.techniques if t.get("source") == "rule"]
        semantic_techs = [t for t in req.techniques if t.get("source") == "semantic"]
        parts = []
        if rule_techs:
            parts.append(f"Rule-based analysis identified {len(rule_techs)} MITRE techniques.")
        if semantic_techs:
            parts.append(f"Semantic analysis suggested {len(semantic_techs)} additional techniques.")
        return {"narrative": " ".join(parts) + " " + req.summary}


# Add grounding check endpoint for internal use
@app.post("/api/v1/ai/grounding-check")
def grounding_check(req: SemanticMitreRequest):
    """Internal endpoint: apply grounding check to techniques from semantic-mitre."""
    if not req.events:
        return {"techniques": []}

    index = get_index()
    event_texts = []
    for e in req.events:
        parts = []
        if e.get("timestamp"):
            parts.append(f"Time: {e['timestamp']}")
        if e.get("event_type"):
            parts.append(f"Type: {e['event_type']}")
        if e.get("message"):
            parts.append(e["message"])
        event_texts.append(" | ".join(parts))

    combined_text = "\n".join(event_texts)
    results = index.search(combined_text, top_k=15)

    techniques = []
    for r in results:
        techniques.append({
            "technique": f"{r['id']} - {r['name']}",
            "confidence": r["confidence"],
            "weight": 1.0,
            "id": r["id"],
            "tactics": r.get("tactics", []),
            "url": r.get("url", "")
        })

    grounded = _grounding_check(req.events, techniques)
    return {"techniques": grounded}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)