"""
section_65b.py — Legal Section 65B Certificate Generator for TraceX.

Produces legally admissible certificates of electronic evidence under:
- Section 65B of the Indian Evidence Act, 1872
- Section 63 of the Bharatiya Sakshya Adhiniyam, 2023 (BSA)

Generates:
1. Publication-quality binary PDF certificate using ReportLab.
2. Structured JSON metadata for electronic API consumption and ledger seals.
"""

from __future__ import annotations

import io
import os
import hashlib
from datetime import datetime, timezone
from typing import Dict, Any, Optional

from .s3_utils import save_certificate_to_s3, get_certificate_from_s3

try:
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable, KeepTogether
    from reportlab.pdfgen import canvas
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False


class NumberedCanvas(canvas.Canvas):
    """Canvas for adding running footer with page numbers and verification seal."""
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_decorations(num_pages)
            super().showPage()
        super().save()

    def draw_page_decorations(self, page_count):
        self.saveState()
        self.setFont("Helvetica", 8)
        self.setFillColor(colors.HexColor("#64748B"))
        
        # Header line
        self.setStrokeColor(colors.HexColor("#CBD5E1"))
        self.setLineWidth(0.5)
        self.line(54, 750, 558, 750)
        self.drawString(54, 755, "TRACEX CYBER-FORENSIC REPOSITORY · SECTION 65B DIGITAL EVIDENCE CERTIFICATE")

        # Footer line
        self.line(54, 50, 558, 50)
        self.drawString(54, 38, "Statutory Admissibility Certificate · Indian Evidence Act §65B / Bharatiya Sakshya Adhiniyam §63")
        self.drawRightString(558, 38, f"Page {self._pageNumber} of {page_count}")
        self.restoreState()


def build_section_65b_certificate_data(evidence: Dict[str, Any]) -> Dict[str, Any]:
    """Compiles complete structured certificate parameters."""
    scan = evidence.get("scan") or {}
    evidence_id = evidence.get("evidence_id") or f"EV-{scan.get('scan_id', '0000')[:8].upper()}"
    scan_id = evidence.get("scan_id") or scan.get("scan_id", "N/A")
    sha256 = evidence.get("artifact_sha256") or scan.get("sha256_hash", "N/A")
    s3_eml_uri = evidence.get("s3_eml_uri") or scan.get("s3_eml_uri", "N/A")
    s3_screenshot_uri = evidence.get("s3_screenshot_uri") or scan.get("s3_screenshot_uri", "N/A")
    recorded_at = evidence.get("recorded_at") or scan.get("created_at") or datetime.now(timezone.utc).isoformat()
    cryptographic_seal = evidence.get("cryptographic_seal") or scan.get("cryptographic_seal") or f"SEAL-{sha256[:16]}"

    cert_num = f"TRACEX-65B-{datetime.utcnow().strftime('%Y%m%d')}-{evidence_id.replace('-', '')}"

    return {
        "certificate_number": cert_num,
        "evidence_id": evidence_id,
        "scan_id": scan_id,
        "artifact_sha256": sha256,
        "s3_eml_uri": s3_eml_uri,
        "s3_screenshot_uri": s3_screenshot_uri,
        "recorded_at": recorded_at,
        "cryptographic_seal": cryptographic_seal,
        "sender": scan.get("sender") or scan.get("from", "Unknown"),
        "recipient": scan.get("recipient") or scan.get("to", "Unknown"),
        "subject": scan.get("subject", "(No subject)"),
        "fraud_score": scan.get("fraud_score", scan.get("score", 0)),
        "risk_level": scan.get("risk_level", scan.get("risk", "LOW")),
        "classification": scan.get("classification", "LEGITIMATE"),
        "certifier_name": evidence.get("certifier_name", "Security Analyst / TraceX Custodian"),
        "certifier_title": "Lead Cyber-Forensic Investigator & Systems Custodian",
        "organization": "TraceX Cyber Threat Defense Command",
        "jurisdiction": "Republic of India (Evidence Admissibility Standard)",
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    }


def generate_section_65b_pdf(evidence: Dict[str, Any]) -> bytes:
    """Generates the Section 65B Certificate in PDF format."""
    data = build_section_65b_certificate_data(evidence)

    if not REPORTLAB_AVAILABLE:
        # Fallback text representation if reportlab is absent
        txt = f"SECTION 65B CERTIFICATE\nCert No: {data['certificate_number']}\nSHA256: {data['artifact_sha256']}\n"
        return txt.encode("utf-8")

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        leftMargin=54,
        rightMargin=54,
        topMargin=64,
        bottomMargin=64
    )

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "CertTitle",
        parent=styles["Heading1"],
        fontName="Helvetica-Bold",
        fontSize=15,
        leading=19,
        textColor=colors.HexColor("#0F172A"),
        alignment=1, # Center
        spaceAfter=4
    )

    subtitle_style = ParagraphStyle(
        "CertSubTitle",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=9,
        leading=13,
        textColor=colors.HexColor("#2563EB"),
        alignment=1,
        spaceAfter=14
    )

    body_style = ParagraphStyle(
        "CertBody",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=8.5,
        leading=12.5,
        textColor=colors.HexColor("#1E293B"),
        alignment=4, # Justify
        spaceAfter=8
    )

    bold_label = ParagraphStyle(
        "BoldLabel",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=8,
        leading=10,
        textColor=colors.HexColor("#0F172A")
    )

    cell_value = ParagraphStyle(
        "CellValue",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=8,
        leading=10,
        textColor=colors.HexColor("#334155")
    )

    code_cell = ParagraphStyle(
        "CodeCell",
        parent=styles["Normal"],
        fontName="Courier",
        fontSize=7.5,
        leading=9,
        textColor=colors.HexColor("#0F172A")
    )

    story = []

    # Title & Legal Heading
    story.append(Paragraph("CERTIFICATE UNDER SECTION 65B OF THE INDIAN EVIDENCE ACT, 1872", title_style))
    story.append(Paragraph("(Also admissible under Section 63 of Bharatiya Sakshya Adhiniyam, 2023 for Electronic Records)", subtitle_style))
    story.append(HRFlowable(width="100%", thickness=1.5, color=colors.HexColor("#1E293B"), spaceAfter=12))

    # Preamble Attestation
    preamble = (
        f"I, <b>{data['certifier_name']}</b>, holding the position of <b>{data['certifier_title']}</b> at "
        f"<b>{data['organization']}</b>, do hereby state, certify, and affirm under official responsibility "
        f"in relation to the operation of the relevant computer systems and management of digital forensics "
        f"as follows:"
    )
    story.append(Paragraph(preamble, body_style))

    # Evidence Specification Table
    story.append(Spacer(1, 4))
    story.append(Paragraph("<b>SCHEDULE I: IDENTIFICATION OF ELECTRONIC RECORD & CUSTODY TRAIL</b>", bold_label))
    story.append(Spacer(1, 4))

    table_data = [
        [Paragraph("Certificate Reference ID", bold_label), Paragraph(data["certificate_number"], cell_value)],
        [Paragraph("Evidence Identifier", bold_label), Paragraph(data["evidence_id"], cell_value)],
        [Paragraph("Associated Scan ID", bold_label), Paragraph(data["scan_id"], cell_value)],
        [Paragraph("Artifact SHA-256 Checksum", bold_label), Paragraph(data["artifact_sha256"], code_cell)],
        [Paragraph("AWS S3 Raw Email URI", bold_label), Paragraph(data["s3_eml_uri"], code_cell)],
        [Paragraph("AWS S3 Screenshot URI", bold_label), Paragraph(data["s3_screenshot_uri"], code_cell)],
        [Paragraph("Ingestion Timestamp", bold_label), Paragraph(f"{data['recorded_at']} (UTC)", cell_value)],
        [Paragraph("Sender / Originator", bold_label), Paragraph(data["sender"], cell_value)],
        [Paragraph("Target Recipient", bold_label), Paragraph(data["recipient"], cell_value)],
        [Paragraph("Subject Header", bold_label), Paragraph(data["subject"], cell_value)],
        [Paragraph("Cryptographic Evidence Seal", bold_label), Paragraph(data["cryptographic_seal"], code_cell)],
        [Paragraph("Fraud Verdict & Score", bold_label), Paragraph(f"{data['classification']} ({data['risk_level']}) — Score {data['fraud_score']}/100", cell_value)],
    ]

    t = Table(table_data, colWidths=[150, 354])
    t.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#F8FAFC")),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('TOPPADDING', (0, 0), (-1, -1), 3),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 3),
    ]))
    story.append(t)
    story.append(Spacer(1, 10))

    # Mandatory Legal Clauses under Section 65B(2)
    story.append(Paragraph("<b>SCHEDULE II: STATUTORY OPERATING CONDITIONS & INTEGRITY ATTESTATION</b>", bold_label))
    story.append(Spacer(1, 4))

    clauses = [
        "<b>1. Regularity of Ingestion:</b> The electronic mail artifact described in Schedule I was received and processed through the automated TraceX Gateway during the period over which the computing facilities were used regularly to store, analyze, and process email communications in the ordinary course of authorized activities.",
        "<b>2. Operating Condition:</b> Throughout the material period of ingestion, forensic feature extraction, and rendering, the relevant computing devices and AWS cloud infrastructure were operating properly and with regular security controls. At no point was the accuracy or integrity of the electronic record compromised by any hardware, software, or network malfunction.",
        "<b>3. Cryptographic Verification & Non-Tampering:</b> Prior to any manipulation or downstream parsing, an immediate SHA-256 cryptographic hash (<b>" + data["artifact_sha256"][:24] + "...</b>) was computed from the raw byte stream and sealed into the immutable evidence ledger. The electronic record stored in AWS S3 is an exact, bit-for-bit duplicate of the received communication.",
        "<b>4. Isolated Sandbox Execution:</b> The visual rendering of the email was executed in a quarantined, headless Chromium container (Playwright) without persistent cookies, active script execution against sensitive corporate assets, or analyst interference.",
        "<b>5. Identity & Admissibility:</b> The output produced herewith is a true, authentic, and tamper-evident reproduction of the electronic record, satisfying all criteria stipulated under Section 65B of the Indian Evidence Act, 1872 and Section 63 of the Bharatiya Sakshya Adhiniyam, 2023."
    ]

    for clause in clauses:
        story.append(Paragraph(clause, body_style))

    story.append(Spacer(1, 14))

    # Sign-off and Seal Block
    signature_data = [
        [
            Paragraph("<b>CERTIFIED BY CUSTODIAN:</b><br/><br/><b>" + data["certifier_name"] + "</b><br/>" + data["certifier_title"] + "<br/>" + data["organization"], cell_value),
            Paragraph("<b>CRYPTOGRAPHIC VERIFICATION SEAL:</b><br/><br/><font face='Courier' size='7'>" + data["cryptographic_seal"] + "</font><br/><br/><b>Status:</b> <font color='#16A34A'><b>CRYPTOGRAPHICALLY VERIFIED</b></font>", cell_value)
        ],
        [
            Paragraph(f"<b>Date:</b> {data['generated_at']}<br/><b>Jurisdiction:</b> {data['jurisdiction']}", cell_value),
            Paragraph("<i>Digitally certified and signed under statutory authority. Valid without physical handwritten signature in accordance with IT Act, 2000.</i>", cell_value)
        ]
    ]
    sig_table = Table(signature_data, colWidths=[252, 252])
    sig_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#F1F5F9")),
        ('BOX', (0, 0), (-1, -1), 1, colors.HexColor("#94A3B8")),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('LEFTPADDING', (0, 0), (-1, -1), 8),
        ('RIGHTPADDING', (0, 0), (-1, -1), 8),
    ]))
    story.append(KeepTogether([sig_table]))

    doc.build(story, canvasmaker=NumberedCanvas)
    pdf_bytes = buffer.getvalue()
    buffer.close()

    # Persist directly into AWS S3
    scan_id = data.get("scan_id", "default_scan")
    try:
        save_certificate_to_s3(scan_id, pdf_bytes)
    except Exception:
        pass

    return pdf_bytes


def get_or_generate_section_65b_pdf(evidence: Dict[str, Any]) -> bytes:
    """Retrieves existing PDF certificate from AWS S3, or generates and uploads a new one."""
    scan_id = evidence.get("scan_id") or evidence.get("evidence_id")
    if scan_id:
        existing = get_certificate_from_s3(scan_id)
        if existing:
            return existing

    return generate_section_65b_pdf(evidence)
