from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List
import os
import anthropic

app = FastAPI(title="DeceptionNet AI Service")

# Initialize Anthropic client
api_key = os.environ.get("ANTHROPIC_API_KEY")
client = anthropic.Anthropic(api_key=api_key) if api_key else None

class SummaryRequest(BaseModel):
    events: List[str]

@app.post("/summarize")
def summarize_session(req: SummaryRequest):
    if not client:
        # Fallback if no API key is provided
        return {"summary": f"Simulated AI Summary: The attacker generated {len(req.events)} events. Please configure ANTHROPIC_API_KEY to enable real summaries."}

    if not req.events:
        return {"summary": "No events found in this session."}

    prompt = f"""You are a cybersecurity analyst. Review the following timeline of events from an SSH honeypot.
Provide a concise, 2-3 sentence plain-language summary of what the attacker was trying to accomplish.
Base your summary strictly on the provided log. Do not speculate beyond what is in the data.

Events:
{chr(10).join(req.events)}
"""

    try:
        response = client.messages.create(
            model="claude-3-haiku-20240307",
            max_tokens=150,
            temperature=0,
            system="You are a helpful cybersecurity analyst.",
            messages=[
                {"role": "user", "content": prompt}
            ]
        )
        return {"summary": response.content[0].text}
    except Exception as e:
        print(f"Anthropic API error: {e}")
        return {"summary": f"Failed to generate summary: {str(e)}"}
