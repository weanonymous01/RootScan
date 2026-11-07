"""Modular AI explanation engine for individual security findings (PRD Section 9.3.C)."""

from __future__ import annotations

from typing import Dict, Optional

from app.ai.nim_client import NimClient
from app.reports.schemas import NormalizedFinding


class FindingExplainer:
    """Generates dual-audience (beginner-friendly and technical) vulnerability explanations."""

    def __init__(self, nim_client: Optional[NimClient] = None):
        self.nim_client = nim_client or NimClient()

    async def explain(self, finding: NormalizedFinding) -> Dict[str, str]:
        """Generate beginner and technical explanations for a specific finding."""
        if not self.nim_client.is_configured:
            return {
                "beginner": f"Finding: {finding.title}. Severity: {finding.severity.value}.",
                "technical": f"{finding.title} on port {finding.port or 'unknown'}. Evidence: {finding.evidence or 'None'}."
            }

        prompt = f"""Explain this security finding for two different audiences:

FINDING TITLE: {finding.title}
SEVERITY: {finding.severity.value}
AFFECTED COMPONENT: {finding.affected_component or 'Unknown'}
VERSION: {finding.observed_version or 'Unknown'}
CVE: {finding.cve_id or 'None'}
EVIDENCE:
{finding.evidence or 'None'}

Provide two distinct sections:
[BEGINNER EXPLANATION]
Explain what this vulnerability means in simple, clear terms without unnecessary jargon. Explain why it matters and what could happen.

[TECHNICAL BREAKDOWN]
Provide a detailed technical breakdown:
- Underlying root cause (protocol flaw, parsing bug, injection, misconfiguration)
- Prerequisites required for exploitation
- Potential technical blast radius
- Specific code or configuration verification step
"""

        try:
            client = self.nim_client._get_client()
            resp = await client.chat.completions.create(
                model=self.nim_client.model,
                messages=[{"role": "user", "content": prompt}],
                max_tokens=1500,
                temperature=0.2
            )
            msg = resp.choices[0].message
            content = msg.content or getattr(msg, "reasoning_content", None) or ""

            # Split beginner and technical sections
            beginner = content
            technical = content
            if "[TECHNICAL BREAKDOWN]" in content:
                parts = content.split("[TECHNICAL BREAKDOWN]")
                beginner = parts[0].replace("[BEGINNER EXPLANATION]", "").strip()
                technical = parts[1].strip()

            return {
                "beginner": beginner,
                "technical": technical
            }
        except Exception as e:
            return {
                "beginner": f"Failed to generate explanation: {e}",
                "technical": f"AI inference error: {e}"
            }
