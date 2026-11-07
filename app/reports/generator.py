"""Report generation for RootScan assessments (JSON and GitHub Flavored Markdown)."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List

from app.reports.schemas import FinalReport, NormalizedFinding, Severity


class ReportGenerator:
    """Generates structured Markdown and JSON reports for RootScan assessments."""

    @staticmethod
    def generate_markdown(report: FinalReport) -> str:
        """Render complete assessment as GitHub Flavored Markdown."""
        meta = report.metadata
        target = report.target

        # Severity breakdown
        counts = {s.value: 0 for s in Severity}
        for finding in report.findings:
            counts[finding.severity.value] = counts.get(finding.severity.value, 0) + 1

        md_lines = [
            f"# RootScan Security Assessment Report",
            f"",
            f"**Scan ID:** `{meta.scan_id}`  ",
            f"**Target:** `{target.normalized_target}` ({target.target_type})  ",
            f"**Profile:** `{meta.profile}`  ",
            f"**Status:** `{meta.status.upper()}`  ",
            f"**Generated:** {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}  ",
            f"**Duration:** {meta.duration_seconds or 0.0:.2f} seconds  ",
            f"",
            f"---",
            f"",
            f"## 1. Executive Summary & Metrics",
            f"",
            f"| Metric | Count |",
            f"|---|---|",
            f"| Discovered Open Ports | {len(report.ports)} |",
            f"| Detected Services | {len(report.services)} |",
            f"| Critical Vulnerabilities | {counts['critical']} |",
            f"| High Vulnerabilities | {counts['high']} |",
            f"| Medium Vulnerabilities | {counts['medium']} |",
            f"| Low Vulnerabilities | {counts['low']} |",
            f"| Informational Findings | {counts['info']} |",
            f"",
            f"---",
            f"",
            f"## 2. Target & Scope Information",
            f"",
            f"- **Target Input:** `{target.raw_input}`",
            f"- **Normalized Target:** `{target.normalized_target}`",
            f"- **Resolved IP Addresses:** {', '.join(f'`{ip}`' for ip in target.resolved_ips) if target.resolved_ips else 'N/A'}",
            f"- **Private Range Scope:** {'Internal Authorized' if target.is_private else 'Public Exposure'}",
            f"",
        ]

        # Reconnaissance
        if report.reconnaissance:
            md_lines.extend([
                f"## 3. Reconnaissance & Intelligence",
                f"",
            ])
            for k, v in report.reconnaissance.items():
                md_lines.append(f"- **{k.replace('_', ' ').title()}:** {v}")
            md_lines.append("")

        # Discovered Ports & Services
        md_lines.extend([
            f"## 4. Discovered Ports & Services",
            f"",
            f"| Port | Protocol | State | Service | Version | Technology Banner |",
            f"|---|---|---|---|---|---|",
        ])

        if not report.services:
            md_lines.append(f"| - | - | None detected | - | - | - |")
        else:
            for s in report.services:
                banner_str = (s.banner or "")[:40].replace("|", "\\|")
                md_lines.append(
                    f"| {s.port} | {s.protocol.upper()} | {s.state} | {s.service_name or 'unknown'} | {s.service_version or '-'} | {banner_str} |"
                )
        md_lines.extend(["", "---", "", "## 5. Vulnerability Findings", ""])

        if not report.findings:
            md_lines.append("No active vulnerabilities or security misconfigurations were identified.")
        else:
            for idx, f in enumerate(report.findings, start=1):
                badge = f"**[{f.severity.value.upper()}]**"
                cve_badge = f" (`{f.cve_id}`)" if f.cve_id else ""
                md_lines.extend([
                    f"### Finding {idx}: {badge} {f.title}{cve_badge}",
                    f"",
                    f"- **Severity:** `{f.severity.value}`",
                    f"- **Confidence:** `{f.confidence.value}`",
                    f"- **Source Tool:** `{f.source_tool}`",
                ])
                if f.affected_component:
                    md_lines.append(f"- **Affected Component:** `{f.affected_component}` (Version: `{f.observed_version or 'unknown'}`)")
                if f.port:
                    md_lines.append(f"- **Exposed Port:** `{f.port}/{f.protocol or 'tcp'}`")
                if f.evidence:
                    md_lines.extend([
                        f"",
                        f"**Evidence:**",
                        f"```text",
                        f"{f.evidence.strip()}",
                        f"```",
                    ])
                if f.remediation:
                    md_lines.extend([
                        f"",
                        f"**Remediation Recommendation:**",
                        f"{f.remediation}",
                    ])
                if f.references:
                    md_lines.extend([
                        f"",
                        f"**References:**",
                        *[f"- {ref}" for ref in f.references],
                    ])
                md_lines.append("")

        # Limitations & Tools
        md_lines.extend([
            f"---",
            f"",
            f"## 6. Assessment Methodology & Tool Executions",
            f"",
        ])
        for tool, summary in report.tool_summary.items():
            md_lines.append(f"- **{tool}:** {summary}")

        if report.skipped_stages:
            md_lines.extend([
                f"",
                f"### Skipped Stages",
                *[f"- {stage}" for stage in report.skipped_stages],
            ])

        md_lines.extend([
            f"",
            f"---",
            f"*Report generated automatically by RootScan v{meta.rootscan_version}.*",
        ])

        return "\n".join(md_lines)

