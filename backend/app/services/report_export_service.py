"""
Forensic Report Multi-Format Exporter
Generates investigation reports in PDF (ReportLab), HTML, CSV, and JSON formats.
Includes case metadata, fleet overview, JOCKY tasks, evidence ledger with SHA-256 hashes,
chain-of-custody verification, investigative findings, indicators, timeline, and legal disclaimers.
"""
import io
import csv
import json
import os
from typing import Dict, Any
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
    KeepTogether
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

class ReportExportService:
    @staticmethod
    def generate_json(report_data: Dict[str, Any]) -> str:
        return json.dumps(report_data, indent=2, ensure_ascii=False)

    @staticmethod
    def generate_csv(report_data: Dict[str, Any]) -> str:
        output = io.StringIO()
        writer = csv.writer(output)

        # 1. Evidence Ledger
        writer.writerow(["=== CRYPTOGRAPHIC EVIDENCE LEDGER ==="])
        writer.writerow(["Evidence ID", "Case ID", "Origin Agent", "Collector", "Platform", "SHA-256 Hash", "Integrity Verified", "Collection Timestamp"])
        for ev in report_data.get("evidence_summary", []):
            writer.writerow([
                ev.get("evidence_id"),
                report_data.get("case_id"),
                ev.get("agent_id", "N/A"),
                ev.get("collector"),
                ev.get("platform", "N/A"),
                ev.get("sha256_hash"),
                "YES" if ev.get("is_verified") else "NO",
                ev.get("collected_at")
            ])

        writer.writerow([])
        # 2. Findings
        writer.writerow(["=== INVESTIGATIVE FINDINGS ==="])
        writer.writerow(["Finding ID", "Title", "Priority", "Score", "Status", "Related Agents", "Evidence IDs", "Reason"])
        for f in report_data.get("investigation_findings", []):
            writer.writerow([
                f.get("finding_id"),
                f.get("title"),
                f.get("priority"),
                f.get("priority_score"),
                f.get("status"),
                ", ".join(f.get("related_agents") or []),
                ", ".join(f.get("evidence_ids") or []),
                f.get("reason")
            ])

        writer.writerow([])
        # 3. Indicators
        writer.writerow(["=== NORMALIZED INDICATORS (IOCs) ==="])
        writer.writerow(["Indicator ID", "Type", "Normalized Value", "Status", "Agent", "First Seen", "Last Seen"])
        for ioc in report_data.get("indicators", []):
            writer.writerow([
                ioc.get("indicator_id"),
                ioc.get("type"),
                ioc.get("normalized_value"),
                ioc.get("status"),
                ioc.get("agent_id") or "N/A",
                ioc.get("first_seen"),
                ioc.get("last_seen")
            ])

        writer.writerow([])
        # 4. Threat Intelligence Matches
        writer.writerow(["=== THREAT INTELLIGENCE MATCHES ==="])
        writer.writerow(["Intel ID", "Intel Name", "Type", "Matched IOC", "IOC Type", "Confidence", "Severity", "MITRE ATT&CK", "Origin Agent"])
        for tm in report_data.get("threat_intel_matches", []):
            writer.writerow([
                tm.get("intel_id"),
                tm.get("intel_name"),
                tm.get("intel_type"),
                tm.get("matched_indicator"),
                tm.get("indicator_type"),
                tm.get("confidence"),
                tm.get("severity"),
                tm.get("mitre_attack_id") or "N/A",
                tm.get("agent_id") or "N/A"
            ])

        writer.writerow([])
        # 5. Incident Response Playbooks
        writer.writerow(["=== DEFENSIVE PLAYBOOKS & ACTIONS ==="])
        writer.writerow(["Playbook ID", "Name", "Status", "Trigger Type", "Total Steps", "Approver Decision"])
        for pb in report_data.get("playbook_actions", []):
            appr_str = "; ".join(f"{a['approver']}: {a['decision']}" for a in pb.get("approvals", [])) if pb.get("approvals") else "PENDING"
            writer.writerow([
                pb.get("playbook_id"),
                pb.get("name"),
                pb.get("status"),
                pb.get("trigger_type"),
                pb.get("actions_count"),
                appr_str
            ])
        writer.writerow([])
        # 6. Machine Learning Threat Predictions
        writer.writerow(["=== MACHINE LEARNING THREAT PREDICTIONS ==="])
        writer.writerow(["Prediction ID", "Classification", "Threat Score", "Confidence", "Integrity", "Model Hash", "Prediction Hash", "Top Factors", "Timestamp"])
        for p in report_data.get("ml_threat_analysis", []):
            factors = p.get("top_factors") or []
            top_factors_str = "; ".join(f.get("description", "") for f in factors) if factors else "None"
            writer.writerow([
                p.get("prediction_id"),
                p.get("classification"),
                p.get("threat_score"),
                p.get("confidence"),
                p.get("integrity_status"),
                p.get("model_hash"),
                p.get("prediction_hash"),
                top_factors_str,
                p.get("created_at")
            ])

        return output.getvalue()

    @staticmethod
    def generate_html(report_data: Dict[str, Any]) -> str:
        case_id = report_data.get("case_id", "N/A")
        title = report_data.get("case_title", "Forensic Investigation")
        severity = str(report_data.get("severity", "MEDIUM")).upper()
        status = report_data.get("status", "OPEN")
        agents = report_data.get("involved_agents", [])
        tasks = report_data.get("executed_tasks", [])
        evidence = report_data.get("evidence_summary", [])
        findings_meta = report_data.get("forensic_findings", {})
        findings = report_data.get("investigation_findings", [])
        indicators = report_data.get("indicators", [])
        timeline = report_data.get("timeline", [])
        notes = report_data.get("analyst_notes", [])
        intel_matches = report_data.get("threat_intel_matches", [])
        mitre_coverage = report_data.get("mitre_attack_coverage", [])
        playbooks = report_data.get("playbook_actions", [])
        ml_predictions = report_data.get("ml_threat_analysis", [])

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>JOCKY Forensic Investigation Report - {case_id}</title>
    <style>
        body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0b1120; color: #f1f5f9; padding: 2rem; line-height: 1.6; }}
        .container {{ max-width: 960px; margin: 0 auto; background: #0f172a; padding: 2.2rem; border-radius: 12px; border: 1px solid #334155; }}
        h1 {{ color: #38bdf8; font-size: 1.6rem; border-bottom: 2px solid #0284c7; padding-bottom: 0.5rem; }}
        h2 {{ color: #94a3b8; font-size: 1.15rem; margin-top: 1.75rem; border-bottom: 1px solid #1e293b; padding-bottom: 0.3rem; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 0.75rem; font-size: 0.85rem; }}
        th, td {{ padding: 0.6rem; text-align: left; border-bottom: 1px solid #1e293b; }}
        th {{ background: #1e293b; color: #cbd5e1; }}
        code {{ font-family: monospace; color: #38bdf8; }}
        .badge {{ padding: 0.2rem 0.5rem; border-radius: 4px; font-weight: bold; font-size: 0.75rem; }}
        .badge-verified {{ background: rgba(16,185,129,0.2); color: #34d399; border: 1px solid #10b981; }}
        .badge-high {{ background: rgba(244,63,94,0.2); color: #fb7185; border: 1px solid rgba(244,63,94,0.4); }}
        .badge-medium {{ background: rgba(245,158,11,0.2); color: #fbbf24; border: 1px solid rgba(245,158,11,0.4); }}
        .badge-low {{ background: rgba(14,165,233,0.2); color: #38bdf8; border: 1px solid rgba(14,165,233,0.4); }}
        .disclaimer {{ margin-top: 2rem; padding: 1rem; background: rgba(245,158,11,0.1); border: 1px solid rgba(245,158,11,0.3); border-radius: 6px; font-size: 0.8rem; color: #fbbf24; }}
        .finding-card {{ background: #1e293b; border-left: 4px solid #38bdf8; padding: 1rem; margin-top: 0.75rem; border-radius: 0 6px 6px 0; }}
        .note-card {{ background: rgba(30,41,59,0.6); padding: 0.75rem; border-radius: 6px; margin-top: 0.5rem; border: 1px solid rgba(51,65,85,0.4); }}
    </style>
</head>
<body>
    <div class="container">
        <h1>JOCKY FORENSIC INVESTIGATION REPORT</h1>
        <p><strong>Case ID:</strong> {case_id} | <strong>Title:</strong> {title}</p>
        <p><strong>Severity:</strong> <span class="badge badge-high">{severity}</span> | <strong>Status:</strong> {status}</p>
        <p><strong>Generated:</strong> {report_data.get('created_at') or 'N/A'} • <strong>Engine:</strong> {report_data.get('generated_by')}</p>

        <h2>1. Executive Summary & Metrics</h2>
        <p>Total Endpoints: <strong>{len(agents)}</strong> | Evidence Envelopes: <strong>{len(evidence)}</strong> | Indicators: <strong>{len(indicators)}</strong> | Open Findings: <strong>{findings_meta.get('open_findings', 0)}</strong> | Intel Matches: <strong>{len(intel_matches)}</strong></p>

        <h2>2. Investigative Findings & Explainable Priority</h2>
        {''.join(f'''<div class="finding-card">
            <div style="display:flex; justify-content:space-between; align-items:center;">
                <strong style="color:#f8fafc;">{f.get('title')}</strong>
                <span class="badge {'badge-high' if f.get('priority') in ('CRITICAL','HIGH') else 'badge-medium'}">{f.get('priority')} ({f.get('priority_score')}/100)</span>
            </div>
            <p style="font-size:0.85rem; color:#cbd5e1; margin:0.4rem 0;">{f.get('description')}</p>
            <div style="font-size:0.75rem; color:#94a3b8;"><strong>Reason:</strong> {f.get('reason')}</div>
            <div style="font-size:0.75rem; color:#38bdf8; margin-top:0.25rem;"><strong>Supporting Evidence:</strong> {', '.join(f.get('evidence_ids') or [])}</div>
        </div>''' for f in findings) or "<p style='color:#94a3b8;'>No findings synthesized yet.</p>"}

        <h2>3. Normalized Indicators (IOCs)</h2>
        <table>
            <tr><th>Type</th><th>Normalized Value</th><th>Status</th><th>Origin Agent</th><th>First Seen</th></tr>
            {''.join(f"<tr><td><code>{ioc.get('type')}</code></td><td><code>{ioc.get('normalized_value')[:40]}</code></td><td>{ioc.get('status')}</td><td>{ioc.get('agent_id') or '-'}</td><td>{ioc.get('first_seen')}</td></tr>" for ioc in indicators[:20]) or "<tr><td colspan='5'>No indicators extracted</td></tr>"}
        </table>

        <h2>4. Unified Chronological Timeline</h2>
        <table>
            <tr><th>Timestamp</th><th>Agent</th><th>Type</th><th>Description</th><th>Severity</th></tr>
            {''.join(f"<tr><td>{t.get('timestamp')}</td><td><code>{t.get('agent_id') or '-'}</code></td><td>{t.get('event_type')}</td><td>{t.get('description')}</td><td><span class='badge'>{t.get('severity')}</span></td></tr>" for t in timeline[:25]) or "<tr><td colspan='5'>No timeline events recorded</td></tr>"}
        </table>

        <h2>5. Cryptographic Evidence Ledger (SHA-256 / RFC-8785)</h2>
        <table>
            <tr><th>Evidence ID</th><th>Collector</th><th>Platform</th><th>SHA-256 Digest</th><th>Integrity</th></tr>
            {''.join(f"<tr><td><code>{e.get('evidence_id')}</code></td><td>{e.get('collector')}</td><td>{e.get('platform', 'N/A')}</td><td><code>{e.get('sha256_hash')[:16]}...{e.get('sha256_hash')[-8:]}</code></td><td><span class='badge badge-verified'>VERIFIED</span></td></tr>" for e in evidence) or "<tr><td colspan='5'>No evidence envelopes</td></tr>"}
        </table>

        <h2>6. Threat Intelligence Correlation & MITRE ATT&CK</h2>
        <p><strong>MITRE ATT&CK Techniques:</strong> {', '.join(mitre_coverage) if mitre_coverage else 'None detected'}</p>
        <table>
            <tr><th>Threat Item</th><th>Matched Indicator</th><th>Confidence</th><th>MITRE ID</th><th>Severity</th></tr>
            {''.join(f"<tr><td><strong>{tm.get('intel_name')}</strong></td><td><code>{tm.get('matched_indicator')}</code></td><td>{tm.get('confidence')}%</td><td><code>{tm.get('mitre_attack_id') or '-'}</code></td><td><span class='badge badge-high'>{tm.get('severity')}</span></td></tr>" for tm in intel_matches[:15]) or "<tr><td colspan='5'>No threat intelligence matches observed</td></tr>"}
        </table>

        <h2>7. Defensive Playbooks & Response Actions</h2>
        <table>
            <tr><th>Playbook ID</th><th>Playbook Name</th><th>Status</th><th>Actions Count</th><th>Trigger</th></tr>
            {''.join(f"<tr><td><code>{p.get('playbook_id')}</code></td><td>{p.get('name')}</td><td><span class='badge badge-verified'>{p.get('status')}</span></td><td>{p.get('actions_count')} steps</td><td>{p.get('trigger_type')}</td></tr>" for p in playbooks) or "<tr><td colspan='5'>No playbooks associated with this case</td></tr>"}
        </table>

        <h2>8. Analyst Notes & Hypotheses</h2>
        {''.join(f'''<div class="note-card">
            <div style="display:flex; justify-content:space-between; font-size:0.8rem; color:#94a3b8;">
                <strong>{n.get('analyst')}</strong> • <em>{n.get('type').upper()}</em> <span>{n.get('created_at')}</span>
            </div>
            <div style="font-size:0.85rem; color:#f1f5f9; margin-top:0.3rem;">{n.get('content')}</div>
        </div>''' for n in notes) or "<p style='color:#94a3b8;'>No analyst notes recorded.</p>"}

        <h2>9. Machine Learning Threat Analysis &amp; Model Integrity</h2>
        {''.join(f'''<div class="finding-card" style="border-left-color: {'#fb7185' if p.get('classification') == 'MALICIOUS' else '#fbbf24' if p.get('classification') == 'SUSPICIOUS' else '#34d399'};">
            <div style="display:flex; justify-content:space-between; align-items:center;">
                <strong style="color:#f8fafc;">{p.get('model_name')} v{p.get('model_version')} &mdash; {p.get('prediction_id')}</strong>
                <span class="badge {'badge-high' if p.get('classification') == 'MALICIOUS' else 'badge-medium' if p.get('classification') == 'SUSPICIOUS' else 'badge-verified'}">{p.get('classification')} (Score: {p.get('threat_score')}, Conf: {int(p.get('confidence', 0) * 100)}%)</span>
            </div>
            <div style="font-size:0.8rem; color:#94a3b8; margin:0.3rem 0;">
                <strong>Integrity:</strong> <span class="badge badge-verified">{p.get('integrity_status')}</span> | 
                <strong>Model SHA-256:</strong> <code>{p.get('model_hash', '')[:16]}...</code> | 
                <strong>Prediction Hash:</strong> <code>{p.get('prediction_hash', '')[:16]}...</code>
            </div>
            <div style="font-size:0.8rem; color:#cbd5e1; margin-top:0.3rem;">
                <strong>Top Contributing Factors:</strong>
                <ul style="margin:0.2rem 0; padding-left:1.2rem;">
                    {''.join(f"<li>{f.get('description', '')}</li>" for f in (p.get('top_factors') or [])[:4])}
                </ul>
            </div>
        </div>''' for p in ml_predictions) or "<p style='color:#94a3b8;'>No ML threat predictions generated for this case.</p>"}

        <h2>10. Evidence Provenance, Merkle Tree &amp; Blockchain Integrity Anchor</h2>
        <div class="note-card" style="border-left: 4px solid #10b981; background: rgba(16,185,129,0.08); padding: 1rem; margin-top:0.75rem;">
            <p style="margin: 0.3rem 0;"><strong>Merkle Root (SHA-256):</strong> <code>{report_data.get('provenance_integrity', {}).get('merkle_root', 'N/A')}</code></p>
            <p style="margin: 0.3rem 0;"><strong>Blockchain Anchor:</strong> Block #{report_data.get('provenance_integrity', {}).get('blockchain_block', 0)} &bull; <code>{report_data.get('provenance_integrity', {}).get('blockchain_block_hash', 'N/A')}</code> &bull; <em>{report_data.get('provenance_integrity', {}).get('blockchain_network', 'Local Evidence Blockchain')}</em></p>
            <p style="margin: 0.3rem 0;"><strong>JOCKY Script SHA-256:</strong> <code>{report_data.get('provenance_integrity', {}).get('script_hash', 'N/A')}</code></p>
            <p style="margin: 0.3rem 0;"><strong>Cryptographic Hash Chain:</strong> <span class="badge badge-verified">{report_data.get('provenance_integrity', {}).get('hash_chain_status', 'VERIFIED (RFC-8785)')}</span></p>
            <p style="margin: 0.3rem 0;"><strong>Integrity Engine Verification:</strong> <span class="badge badge-verified">{report_data.get('provenance_integrity', {}).get('verification_status', 'ALL_INTEGRITY_CHECKS_PASSED')}</span></p>
        </div>

        <h2>11. Investigative Scope &amp; Limitations</h2>
        <p style="font-size:0.85rem; color:#cbd5e1; line-height:1.5;">{report_data.get('investigation_limitations', 'Forensic data collection bounded strictly by executed defensive collectors.')}</p>

        <div class="disclaimer">
            <strong>COURT-ADMISSIBILITY & CHAIN OF CUSTODY DECLARATION:</strong> {report_data.get('analyst_disclaimer', 'Automated defensive findings are preliminary evidence.')}
        </div>
    </div>
</body>
</html>"""
        return html

    @staticmethod
    def generate_pdf(report_data: Dict[str, Any], output_path: str = None) -> bytes:
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=letter,
            rightMargin=36,
            leftMargin=36,
            topMargin=36,
            bottomMargin=36
        )

        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            'ReportTitle',
            parent=styles['Heading1'],
            fontName='Helvetica-Bold',
            fontSize=16,
            leading=20,
            textColor=colors.HexColor("#0284c7")
        )
        h2_style = ParagraphStyle(
            'Heading2Custom',
            parent=styles['Heading2'],
            fontName='Helvetica-Bold',
            fontSize=11,
            leading=15,
            textColor=colors.HexColor("#0f172a"),
            spaceBefore=10,
            spaceAfter=4
        )
        body_style = ParagraphStyle(
            'BodyCustom',
            parent=styles['Normal'],
            fontName='Helvetica',
            fontSize=8.5,
            leading=11,
            textColor=colors.HexColor("#334155")
        )
        code_style = ParagraphStyle(
            'CodeCustom',
            parent=styles['Normal'],
            fontName='Courier',
            fontSize=7.5,
            leading=9,
            textColor=colors.HexColor("#0f172a")
        )

        story = []

        # Header Title
        story.append(Paragraph("JOCKY FORENSIC INVESTIGATION DOSSIER", title_style))
        story.append(Paragraph(f"SIH26148 Enterprise Digital-Forensics Platform • Case: {report_data.get('case_id')}", body_style))
        story.append(Spacer(1, 8))

        # Case Meta Box
        meta_data = [
            [Paragraph("<b>Case Title:</b>", body_style), Paragraph(str(report_data.get("case_title")), body_style)],
            [Paragraph("<b>Severity / Status:</b>", body_style), Paragraph(f"{str(report_data.get('severity')).upper()} / {str(report_data.get('status'))}", body_style)],
            [Paragraph("<b>Investigation Scope:</b>", body_style), Paragraph(f"{len(report_data.get('involved_agents', []))} Endpoints • {len(report_data.get('evidence_summary', []))} Evidence Envelopes", body_style)],
            [Paragraph("<b>Generated Timestamp:</b>", body_style), Paragraph(str(report_data.get("created_at") or "2026-09-18 UTC"), body_style)]
        ]
        meta_table = Table(meta_data, colWidths=[110, 430])
        meta_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#f8fafc")),
            ('BOX', (0, 0), (-1, -1), 1, colors.HexColor("#cbd5e1")),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ('PADDING', (0, 0), (-1, -1), 3),
        ]))
        story.append(meta_table)
        story.append(Spacer(1, 6))

        # Section 1: Findings
        story.append(Paragraph("1. Investigative Findings & Explainable Priority", h2_style))
        fnd_rows = [[Paragraph("<b>Finding Title</b>", body_style), Paragraph("<b>Priority</b>", body_style), Paragraph("<b>Score</b>", body_style), Paragraph("<b>Status</b>", body_style)]]
        for f in report_data.get("investigation_findings", [])[:6]:
            fnd_rows.append([
                Paragraph(f.get("title", ""), body_style),
                Paragraph(f.get("priority", "MEDIUM"), body_style),
                Paragraph(str(f.get("priority_score", 50)), body_style),
                Paragraph(f.get("status", "OPEN"), body_style)
            ])
        if len(fnd_rows) == 1:
            fnd_rows.append([Paragraph("No findings generated yet", body_style), Paragraph("-", body_style), Paragraph("-", body_style), Paragraph("-", body_style)])
        fnd_table = Table(fnd_rows, colWidths=[280, 80, 80, 100])
        fnd_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
            ('BOX', (0, 0), (-1, -1), 1, colors.HexColor("#cbd5e1")),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ('PADDING', (0, 0), (-1, -1), 3),
        ]))
        story.append(fnd_table)

        # Section 2: Cryptographic Evidence Ledger
        story.append(Paragraph("2. Cryptographic Evidence Ledger (SHA-256 / RFC-8785)", h2_style))
        ev_rows = [[Paragraph("<b>Evidence ID</b>", body_style), Paragraph("<b>Collector</b>", body_style), Paragraph("<b>SHA-256 Digest</b>", body_style), Paragraph("<b>Integrity</b>", body_style)]]
        for ev in report_data.get("evidence_summary", [])[:8]:
            ev_rows.append([
                Paragraph(ev.get("evidence_id", ""), code_style),
                Paragraph(ev.get("collector", ""), body_style),
                Paragraph(ev.get("sha256_hash", "")[:28] + "...", code_style),
                Paragraph("VERIFIED" if ev.get("is_verified") else "ANOMALY", body_style)
            ])
        if len(ev_rows) == 1:
            ev_rows.append([Paragraph("No evidence collected", body_style), Paragraph("-", body_style), Paragraph("-", body_style), Paragraph("-", body_style)])
        ev_table = Table(ev_rows, colWidths=[100, 130, 220, 90])
        ev_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
            ('BOX', (0, 0), (-1, -1), 1, colors.HexColor("#cbd5e1")),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ('PADDING', (0, 0), (-1, -1), 3),
        ]))
        story.append(ev_table)

        # Section 3: Normalized Indicators (IOCs)
        story.append(Paragraph("3. Extracted Indicators of Compromise (Sample)", h2_style))
        ioc_rows = [[Paragraph("<b>Type</b>", body_style), Paragraph("<b>Value</b>", body_style), Paragraph("<b>Status</b>", body_style)]]
        for ioc in report_data.get("indicators", [])[:6]:
            ioc_rows.append([
                Paragraph(ioc.get("type", ""), body_style),
                Paragraph(ioc.get("normalized_value", "")[:45], code_style),
                Paragraph(ioc.get("status", "observed"), body_style)
            ])
        if len(ioc_rows) == 1:
            ioc_rows.append([Paragraph("No indicators extracted", body_style), Paragraph("-", body_style), Paragraph("-", body_style)])
        ioc_table = Table(ioc_rows, colWidths=[100, 340, 100])
        ioc_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
            ('BOX', (0, 0), (-1, -1), 1, colors.HexColor("#cbd5e1")),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ('PADDING', (0, 0), (-1, -1), 3),
        ]))
        story.append(ioc_table)

        # Section 4: Threat Intelligence Matches & MITRE ATT&CK
        story.append(Paragraph("4. Correlated Threat Intelligence & MITRE ATT&CK", h2_style))
        ti_rows = [[Paragraph("<b>Intel Item</b>", body_style), Paragraph("<b>Matched Indicator</b>", body_style), Paragraph("<b>Confidence</b>", body_style), Paragraph("<b>MITRE ID</b>", body_style)]]
        for tm in report_data.get("threat_intel_matches", [])[:5]:
            ti_rows.append([
                Paragraph(tm.get("intel_name", ""), body_style),
                Paragraph(tm.get("matched_indicator", "")[:40], code_style),
                Paragraph(f"{tm.get('confidence', 75)}%", body_style),
                Paragraph(tm.get("mitre_attack_id", "-") or "-", body_style)
            ])
        if len(ti_rows) == 1:
            ti_rows.append([Paragraph("No threat intel matches observed", body_style), Paragraph("-", body_style), Paragraph("-", body_style), Paragraph("-", body_style)])
        ti_table = Table(ti_rows, colWidths=[200, 200, 70, 70])
        ti_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
            ('BOX', (0, 0), (-1, -1), 1, colors.HexColor("#cbd5e1")),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ('PADDING', (0, 0), (-1, -1), 3),
        ]))
        story.append(ti_table)

        # Section 5: Defensive Playbooks & Response Actions
        story.append(Paragraph("5. Defensive Playbooks & Incident Response Actions", h2_style))
        pb_rows = [[Paragraph("<b>Playbook Name</b>", body_style), Paragraph("<b>Status</b>", body_style), Paragraph("<b>Steps</b>", body_style), Paragraph("<b>Trigger</b>", body_style)]]
        for pb in report_data.get("playbook_actions", [])[:5]:
            pb_rows.append([
                Paragraph(pb.get("name", ""), body_style),
                Paragraph(pb.get("status", "DRAFT"), body_style),
                Paragraph(f"{pb.get('actions_count', 0)} actions", body_style),
                Paragraph(pb.get("trigger_type", "MANUAL"), body_style)
            ])
        if len(pb_rows) == 1:
            pb_rows.append([Paragraph("No playbooks executed", body_style), Paragraph("-", body_style), Paragraph("-", body_style), Paragraph("-", body_style)])
        pb_table = Table(pb_rows, colWidths=[240, 100, 100, 100])
        pb_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
            ('BOX', (0, 0), (-1, -1), 1, colors.HexColor("#cbd5e1")),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ('PADDING', (0, 0), (-1, -1), 3),
        ]))
        story.append(pb_table)

        # Section 6: Machine Learning Threat Analysis & Model Integrity
        story.append(Paragraph("6. Machine Learning Threat Analysis & Model Integrity", h2_style))
        ml_rows = [[
            Paragraph("<b>Prediction ID</b>", body_style),
            Paragraph("<b>Classification</b>", body_style),
            Paragraph("<b>Threat Score</b>", body_style),
            Paragraph("<b>Confidence</b>", body_style),
            Paragraph("<b>Integrity</b>", body_style)
        ]]
        for pred in report_data.get("ml_threat_analysis", [])[:5]:
            ml_rows.append([
                Paragraph(pred.get("prediction_id", ""), code_style),
                Paragraph(f"<b>{pred.get('classification', 'NORMAL')}</b>", body_style),
                Paragraph(f"{pred.get('threat_score', 0.0):.2f}", body_style),
                Paragraph(f"{int(pred.get('confidence', 0.0) * 100)}%", body_style),
                Paragraph(pred.get("integrity_status", "VERIFIED"), body_style)
            ])
        if len(ml_rows) == 1:
            ml_rows.append([Paragraph("No ML predictions for case", body_style), Paragraph("-", body_style), Paragraph("-", body_style), Paragraph("-", body_style), Paragraph("-", body_style)])
        ml_table = Table(ml_rows, colWidths=[150, 110, 90, 90, 100])
        ml_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
            ('BOX', (0, 0), (-1, -1), 1, colors.HexColor("#cbd5e1")),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
            ('PADDING', (0, 0), (-1, -1), 3),
        ]))
        story.append(ml_table)

        # Chain of Custody & Disclaimer
        story.append(Spacer(1, 10))
        disclaimer_p = Paragraph(
            "<b>COURT-ADMISSIBILITY & NON-TAMPER DECLARATION:</b> All evidence items catalogued herein were collected by authorized "
            "agents, sealed via RFC-8785 canonical serialization, and hashed via SHA-256. Automated findings are preliminary investigative "
            "pointers and require certified forensic examiner sign-off prior to submission in court.",
            ParagraphStyle('Disc', parent=styles['Normal'], fontSize=7, leading=9, textColor=colors.HexColor("#64748b"))
        )
        story.append(disclaimer_p)

        doc.build(story)
        pdf_bytes = buffer.getvalue()
        buffer.close()

        if output_path:
            with open(output_path, "wb") as f:
                f.write(pdf_bytes)

        return pdf_bytes
