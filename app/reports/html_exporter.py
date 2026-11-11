"""Standalone HTML report generator for RootScan assessments (FR-19)."""

from __future__ import annotations

import html
from typing import Optional

from app.reports.schemas import AIAnalysisReport, FinalReport, Severity


class HtmlReportExporter:
    """Renders a self-contained, responsive, dark-themed HTML report."""

    @classmethod
    def export(cls, report: FinalReport, ai_analysis: Optional[AIAnalysisReport] = None) -> str:
        meta = report.metadata
        target = report.target

        counts = {s.value: 0 for s in Severity}
        for f in report.findings:
            counts[f.severity.value] = counts.get(f.severity.value, 0) + 1

        ports_rows = ""
        for p in report.ports:
            p_sources = ", ".join(p.all_sources()) if hasattr(p, "all_sources") else ""
            p_sources = p_sources or p.discovery_source
            ports_rows += f"""
            <tr>
                <td><strong>{p.port}</strong></td>
                <td>{p.protocol.upper()}</td>
                <td><span class="badge badge-success">{p.state.value}</span></td>
                <td>{html.escape(p_sources)}</td>
            </tr>
            """
        if not report.ports:
            ports_rows = "<tr><td colspan='4' class='text-muted'>No open ports detected.</td></tr>"

        services_rows = ""
        for s in report.services:
            banner = html.escape(s.banner or "-")
            s_sources = ", ".join(s.all_sources()) if hasattr(s, "all_sources") else ""
            s_sources = s_sources or s.source_tool
            services_rows += f"""
            <tr>
                <td><strong>{s.port}/{s.protocol.upper()}</strong></td>
                <td><span class="badge badge-info">{html.escape(s.service_name or 'unknown')}</span></td>
                <td>{html.escape(s.service_version or '-')}</td>
                <td><small>{html.escape(s_sources)}</small></td>
                <td><small>{banner}</small></td>
            </tr>
            """
        if not report.services:
            services_rows = "<tr><td colspan='5' class='text-muted'>No services identified.</td></tr>"

        findings_cards = ""
        for idx, f in enumerate(report.findings, start=1):
            sev_class = f"badge-{f.severity.value}"
            evidence_block = f"<pre class='evidence-box'>{html.escape(f.evidence)}</pre>" if f.evidence else ""
            remediation_block = f"<div class='remediation-box'><strong>Remediation:</strong> {html.escape(f.remediation)}</div>" if f.remediation else ""
            cve_badge = f"<span class='badge badge-cve'>{html.escape(f.cve_id)}</span>" if f.cve_id else ""

            findings_cards += f"""
            <div class="card finding-card">
                <div class="card-header">
                    <div>
                        <span class="badge {sev_class}">{f.severity.value.upper()}</span>
                        {cve_badge}
                        <strong class="finding-title">Finding #{idx}: {html.escape(f.title)}</strong>
                    </div>
                    <small class="text-muted">Source: {html.escape(f.source_tool)}</small>
                </div>
                <div class="card-body">
                    {evidence_block}
                    {remediation_block}
                </div>
            </div>
            """
        if not report.findings:
            findings_cards = "<p class='text-success'>✓ No security vulnerabilities or misconfigurations were detected.</p>"

        ai_section = ""
        if ai_analysis:
            ai_section = f"""
            <div class="section">
                <h2>🤖 AI Security Analyst ({html.escape(ai_analysis.model)})</h2>
                <div class="card ai-card">
                    <h3>Executive Summary</h3>
                    <p>{html.escape(ai_analysis.executive_summary)}</p>
                    <hr>
                    <h3>Attack Surface & Risk Assessment</h3>
                    <pre class="ai-text">{html.escape(ai_analysis.attack_surface_analysis)}</pre>
                </div>
            </div>
            """

        html_template = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>RootScan Report - {html.escape(meta.scan_id)}</title>
    <style>
        :root {{
            --bg-primary: #0b0f19;
            --bg-secondary: #151d2f;
            --bg-card: #1c263c;
            --border-color: #26334d;
            --text-primary: #e2e8f0;
            --text-secondary: #94a3b8;
            --accent-cyan: #00d4aa;
            --accent-blue: #3b82f6;
            --critical: #ef4444;
            --high: #f97316;
            --medium: #f59e0b;
            --low: #3b82f6;
            --info: #64748b;
        }}
        body {{
            background-color: var(--bg-primary);
            color: var(--text-primary);
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            margin: 0;
            padding: 30px;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}
        .header {{
            border-bottom: 2px solid var(--border-color);
            padding-bottom: 20px;
            margin-bottom: 30px;
        }}
        h1, h2, h3 {{ color: #ffffff; }}
        .header h1 {{ color: var(--accent-cyan); margin: 0 0 10px 0; }}
        .meta-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-top: 15px;
        }}
        .metrics-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
            gap: 15px;
            margin-bottom: 30px;
        }}
        .card {{
            background: var(--bg-secondary);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 20px;
        }}
        .metric-card {{
            text-align: center;
        }}
        .metric-val {{
            font-size: 2rem;
            font-weight: bold;
            color: var(--accent-cyan);
            margin: 5px 0;
        }}
        .badge {{
            display: inline-block;
            padding: 4px 10px;
            border-radius: 4px;
            font-size: 0.8rem;
            font-weight: bold;
            color: #fff;
        }}
        .badge-critical {{ background: var(--critical); }}
        .badge-high {{ background: var(--high); }}
        .badge-medium {{ background: var(--medium); color: #000; }}
        .badge-low {{ background: var(--low); }}
        .badge-info {{ background: var(--info); }}
        .badge-cve {{ background: #475569; }}
        .badge-success {{ background: #10b981; }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
        }}
        th, td {{
            text-align: left;
            padding: 12px;
            border-bottom: 1px solid var(--border-color);
        }}
        th {{ background: var(--bg-card); color: var(--text-secondary); }}
        .finding-card {{
            margin-bottom: 15px;
        }}
        .card-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
        }}
        .evidence-box {{
            background: #080c14;
            padding: 12px;
            border-radius: 6px;
            border: 1px solid var(--border-color);
            overflow-x: auto;
            color: #a5f3fc;
            font-size: 0.9rem;
        }}
        .remediation-box {{
            background: #111e38;
            border-left: 4px solid var(--accent-cyan);
            padding: 12px;
            margin-top: 10px;
            border-radius: 0 4px 4px 0;
        }}
        .ai-text {{
            white-space: pre-wrap;
            background: #080c14;
            padding: 15px;
            border-radius: 6px;
            color: #e2e8f0;
            line-height: 1.5;
        }}
        .text-muted {{ color: var(--text-secondary); }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>RootScan Security Assessment</h1>
            <div class="meta-grid">
                <div><strong>Scan ID:</strong> {html.escape(meta.scan_id)}</div>
                <div><strong>Target:</strong> {html.escape(target.normalized_target)} ({target.target_type})</div>
                <div><strong>Profile:</strong> {html.escape(meta.profile.upper())}</div>
                <div><strong>Status:</strong> {html.escape(meta.status.upper())}</div>
                <div><strong>Duration:</strong> {meta.duration_seconds or 0.0:.2f}s</div>
            </div>
        </div>

        <div class="metrics-grid">
            <div class="card metric-card">
                <div class="text-muted">OPEN PORTS</div>
                <div class="metric-val">{len(report.ports)}</div>
            </div>
            <div class="card metric-card">
                <div class="text-muted">SERVICES</div>
                <div class="metric-val">{len(report.services)}</div>
            </div>
            <div class="card metric-card">
                <div class="text-muted">CRITICAL</div>
                <div class="metric-val" style="color: var(--critical);">{counts['critical']}</div>
            </div>
            <div class="card metric-card">
                <div class="text-muted">HIGH</div>
                <div class="metric-val" style="color: var(--high);">{counts['high']}</div>
            </div>
            <div class="card metric-card">
                <div class="text-muted">MEDIUM</div>
                <div class="metric-val" style="color: var(--medium);">{counts['medium']}</div>
            </div>
        </div>

        <div class="section">
            <h2>Open Ports Discovery ({len(report.ports)})</h2>
            <div class="card">
                <table>
                    <thead>
                        <tr>
                            <th>Port</th>
                            <th>Protocol</th>
                            <th>State</th>
                            <th>Discovered By</th>
                        </tr>
                    </thead>
                    <tbody>
                        {ports_rows}
                    </tbody>
                </table>
            </div>
        </div>

        <br>
        <div class="section">
            <h2>Discovered Ports & Services</h2>
            <div class="card">
                <table>
                    <thead>
                        <tr>
                            <th>Port</th>
                            <th>Service</th>
                            <th>Version</th>
                            <th>Source Tool(s)</th>
                            <th>Banner / Details</th>
                        </tr>
                    </thead>
                    <tbody>
                        {services_rows}
                    </tbody>
                </table>
            </div>
        </div>

        <br>
        <div class="section">
            <h2>Security Findings ({len(report.findings)})</h2>
            {findings_cards}
        </div>

        {ai_section}

        {cls._render_tool_audit(report)}

        <br>
        <footer class="text-muted" style="text-align: center; border-top: 1px solid var(--border-color); padding-top: 20px;">
            Generated by RootScan v{meta.rootscan_version} • Evidence-based local execution
        </footer>
    </div>
</body>
</html>
"""
        return html_template

    @staticmethod
    def _render_tool_audit(report: FinalReport) -> str:
        """Render tool execution audit and skipped stages table."""
        if not report.tool_summary and not report.skipped_stages:
            return ""

        rows = ""
        for tool_name, info in report.tool_summary.items():
            if hasattr(info, "model_dump"):
                info = info.model_dump()
            summary_str = html.escape(str(info))
            rows += (
                f"<tr><td><strong>{html.escape(str(tool_name))}</strong></td>"
                f"<td><small>{summary_str}</small></td></tr>"
            )

        skipped_html = ""
        if report.skipped_stages:
            items = "".join(
                f"<li>{html.escape(str(stage))}</li>" for stage in report.skipped_stages
            )
            skipped_html = f"<h3 style='margin-top:16px;'>Skipped Stages</h3><ul>{items}</ul>"

        table_html = (
            f"<table><thead><tr><th>Tool</th><th>Execution Summary</th></tr></thead>"
            f"<tbody>{rows}</tbody></table>"
            if rows
            else ""
        )
        return (
            f"<br><div class='section'><h2>Tool Execution Audit</h2>"
            f"<div class='card'>{table_html}{skipped_html}</div></div>"
        )

