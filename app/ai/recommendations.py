"""Prioritized remediation and next-step recommendation engine (PRD Section 9.3.G/H)."""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from app.ai.nim_client import NimClient
from app.reports.schemas import FinalReport, NormalizedFinding


class RecommendationEngine:
    """Formulates prioritized, actionable defensive next steps and remediation guides."""

    def __init__(self, nim_client: Optional[NimClient] = None):
        self.nim_client = nim_client or NimClient()

    async def generate_recommendations(self, report: FinalReport) -> Dict[str, Any]:
        """Synthesize prioritized immediate, short-term, and verification actions."""
        if not self.nim_client.is_configured:
            return {
                "immediate_actions": ["Review exposed network ports and restrict access using firewall rules."],
                "remediations": [f.remediation for f in report.findings if f.remediation],
                "verification_steps": ["Re-run quick assessment after configuration updates."]
            }

        findings_summary = [
            {
                "title": f.title,
                "severity": f.severity.value,
                "cve": f.cve_id,
                "component": f.affected_component,
                "version": f.observed_version
            }
            for f in report.findings[:15]
        ]

        prompt = f"""Generate actionable defensive recommendations based on this assessment:

TARGET: {report.target.normalized_target}
TOTAL FINDINGS: {len(report.findings)}
FINDINGS SUMMARY:
```json
{json.dumps(findings_summary, indent=2)}
```

Structure your output into:
1. IMMEDIATE HIGH-PRIORITY ACTIONS (Within 24 hours):
   - What must be patched or isolated first?
2. SECONDARY HARDENING (Within 7 days):
   - Configuration changes, header additions, cipher deprecations.
3. VERIFICATION & VALIDATION:
   - Specific safe commands or requests the operator can run to confirm fixes have succeeded.
"""

        try:
            client = self.nim_client._get_client()
            resp = await client.chat.completions.create(
                model=self.nim_client.model,
                messages=[{"role": "user", "content": prompt}],
                max_tokens=2000,
                temperature=0.2
            )
            msg = resp.choices[0].message
            content = msg.content or getattr(msg, "reasoning_content", None) or ""
            return {"recommendation_guide": content}
        except Exception as e:
            return {"error": str(e)}
