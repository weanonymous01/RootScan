"""Large report chunking and multi-section synthesis engine (PRD Section 10.2)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from app.ai.nim_client import NimClient
from app.reports.schemas import AIAnalysisReport, FinalReport


class ReportAnalyzer:
    """Orchestrates chunked analysis and unified synthesis of large assessment reports."""

    def __init__(self, nim_client: Optional[NimClient] = None):
        self.nim_client = nim_client or NimClient()
        self.prompts_dir = Path(__file__).resolve().parent / "prompts"

    def _read_prompt(self, filename: str) -> str:
        prompt_file = self.prompts_dir / filename
        if prompt_file.exists():
            return prompt_file.read_text(encoding="utf-8")
        return ""

    async def analyze(self, report: FinalReport) -> Optional[AIAnalysisReport]:
        """
        Analyze report using single-pass for small/medium scans or sectional synthesis for large scans.
        """
        if not self.nim_client.is_configured:
            return None

        # Check total findings and services count to determine if chunking is needed
        total_items = len(report.ports) + len(report.services) + len(report.findings)

        if total_items <= 15:
            # Efficient single-pass analysis
            return await self.nim_client.analyze_scan_report(report)

        # Multi-section analysis for large scan reports
        section_summaries: List[str] = []

        # 1. Section: Recon & Network Surface
        recon_data = {
            "target": report.target.model_dump(),
            "reconnaissance": report.reconnaissance,
            "ports": [p.model_dump() for p in report.ports[:30]]
        }
        recon_summary = await self._analyze_section("Reconnaissance & Ports", recon_data)
        if recon_summary:
            section_summaries.append(f"### SECTION: Network & Port Surface\n{recon_summary}")

        # 2. Section: Services & Technology
        services_data = {"services": [s.model_dump() for s in report.services[:30]]}
        services_summary = await self._analyze_section("Services & Technology Fingerprints", services_data)
        if services_summary:
            section_summaries.append(f"### SECTION: Services & Technology\n{services_summary}")

        # 3. Section: Vulnerability Findings (chunked into batches of 10)
        chunk_size = 10
        for i in range(0, len(report.findings), chunk_size):
            batch = report.findings[i : i + chunk_size]
            batch_data = {"findings": [f.model_dump() for f in batch]}
            finding_summary = await self._analyze_section(f"Vulnerability Findings Batch {i // chunk_size + 1}", batch_data)
            if finding_summary:
                section_summaries.append(f"### SECTION: Findings Batch {i // chunk_size + 1}\n{finding_summary}")

        # 4. Final Comprehensive Synthesis
        return await self._synthesize_final_report(report, "\n\n".join(section_summaries))

    async def _analyze_section(self, section_type: str, data: Dict[str, Any]) -> Optional[str]:
        prompt_tmpl = self._read_prompt("section_analysis.txt")
        if not prompt_tmpl:
            prompt_tmpl = "Analyze this section: {section_type}\n{section_data}"

        user_content = prompt_tmpl.format(
            section_type=section_type,
            section_data=json.dumps(data, indent=2, default=str)
        )

        try:
            client = self.nim_client._get_client()
            resp = await client.chat.completions.create(
                model=self.nim_client.model,
                messages=[
                    {"role": "system", "content": self._read_prompt("system.txt")},
                    {"role": "user", "content": user_content}
                ],
                max_tokens=1500,
                temperature=0.2
            )
            msg = resp.choices[0].message
            return msg.content or getattr(msg, "reasoning_content", None) or ""
        except Exception:
            return None

    async def _synthesize_final_report(self, report: FinalReport, all_sections: str) -> Optional[AIAnalysisReport]:
        synth_tmpl = self._read_prompt("final_synthesis.txt")
        if not synth_tmpl:
            synth_tmpl = "Synthesize these sections into a final assessment:\n{section_summaries}"

        user_content = synth_tmpl.format(
            target=report.target.normalized_target,
            target_type=report.target.target_type,
            section_summaries=all_sections
        )

        try:
            client = self.nim_client._get_client()
            resp = await client.chat.completions.create(
                model=self.nim_client.model,
                messages=[
                    {"role": "system", "content": self._read_prompt("system.txt")},
                    {"role": "user", "content": user_content}
                ],
                max_tokens=4000,
                temperature=0.2
            )
            msg = resp.choices[0].message
            raw_text = msg.content or getattr(msg, "reasoning_content", None) or ""

            return AIAnalysisReport(
                scan_id=report.metadata.scan_id,
                model=self.nim_client.model,
                executive_summary=raw_text[:1000],
                attack_surface_analysis=raw_text,
                vulnerability_explanation=raw_text,
                exploit_intelligence=raw_text,
                attack_path_analysis=raw_text,
                risk_prioritization="High",
                recommendations=raw_text,
                limitations="Multi-section synthesized assessment without active payload execution.",
                conclusion=raw_text[-500:]
            )
        except Exception as e:
            print(f"[!] Synthesis failed: {e}")
            return None

