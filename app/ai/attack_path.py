"""Attack path correlation engine constructing plausible threat chains (PRD Section 9.3.E)."""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

from app.ai.nim_client import NimClient
from app.reports.schemas import FinalReport, NormalizedFinding, ServiceResult


class AttackPathEngine:
    """Synthesizes plausible attacker progression chains from observed evidence."""

    def __init__(self, nim_client: Optional[NimClient] = None):
        self.nim_client = nim_client or NimClient()

    async def generate_attack_paths(self, report: FinalReport) -> List[Dict[str, Any]]:
        """Construct multi-step attacker progression hypotheses supported by evidence."""
        if not self.nim_client.is_configured or (not report.services and not report.findings):
            return []

        evidence_payload = {
            "target": report.target.normalized_target,
            "services": [s.model_dump() for s in report.services],
            "findings": [f.model_dump() for f in report.findings]
        }

        prompt = f"""Analyze the following normalized assessment evidence to map potential attacker progression paths:

EVIDENCE:
```json
{json.dumps(evidence_payload, indent=2, default=str)}
```

INSTRUCTIONS:
1. Identify any multi-step progression paths (e.g. Exposed Service -> Weak Configuration -> Privilege Elevation / Data Exposure).
2. For each path, clearly cite the specific open port, software version, or finding that serves as the entrypoint.
3. Explicitly label unverified steps as [HYPOTHESIS].
4. Return a structured list of paths with:
   - title
   - entry_point
   - progression_steps (ordered list)
   - estimated_impact
   - required_prerequisites
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

            return [{
                "title": f"Attack Surface Progression for {report.target.normalized_target}",
                "analysis": content
            }]
        except Exception:
            return []

