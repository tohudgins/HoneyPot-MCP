"""File-based honeytoken provider — PDF/DOCX documents with DNS callback tracking."""

from __future__ import annotations

import secrets
import uuid
from pathlib import Path
from typing import Any

from honeypot_mcp.tokens.base import HoneytokenProvider


class FileTokenProvider(HoneytokenProvider):
    async def create(self, options: dict[str, Any]) -> tuple[str, dict[str, Any]]:
        from honeypot_mcp.config import get_settings

        settings = get_settings()
        token_uid = uuid.uuid4().hex
        file_type = options.get("file_type", "pdf")
        title = options.get("document_title", "Confidential Report")

        # DNS canary subdomain: {token_uid}.canary.<domain>
        # We use the callback host's domain (or localhost for testing)
        callback_base = settings.canary_public_url.replace("http://", "").replace("https://", "").split(":")[0]
        dns_canary = f"{token_uid}.canary.{callback_base}"

        output_dir = Path("reports/generated")
        output_dir.mkdir(parents=True, exist_ok=True)
        output_path = output_dir / f"{token_uid}.{file_type}"

        if file_type == "pdf":
            output_path = await _create_pdf(str(output_path), title, dns_canary, token_uid, settings)
        elif file_type == "docx":
            output_path = await _create_docx(str(output_path), title, dns_canary, token_uid, settings)

        meta = {
            "file_type": file_type,
            "file_path": str(output_path),
            "document_title": title,
            "dns_canary": dns_canary,
            "token_uid": token_uid,
        }
        return token_uid, meta

    def plant_instructions(self, token_value: str, metadata: dict[str, Any]) -> str:
        file_path = metadata.get("file_path", "reports/generated/<token>.pdf")
        dns_canary = metadata.get("dns_canary", "")
        return (
            f"File honeytoken created at: {file_path}\n\n"
            f"DNS canary domain: {dns_canary}\n\n"
            f"Plant this file where an attacker might open it:\n"
            f"  - Shared network drive as 'Passwords.pdf' or 'Internal_Credentials.docx'\n"
            f"  - Email attachment in a spear-phishing simulation\n"
            f"  - USB drop scenario\n"
            f"  - Backup directory on a honeypot server\n\n"
            f"When the file is opened, it makes a DNS lookup to {dns_canary}.\n"
            f"The DNS honeypot captures this and triggers an alert."
        )


async def _create_pdf(
    path: str, title: str, dns_canary: str, token_uid: str, settings: Any
) -> Path:
    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.platypus import Image, Paragraph, SimpleDocTemplate, Spacer
        import io

        doc = SimpleDocTemplate(path, pagesize=letter)
        styles = getSampleStyleSheet()
        story = []

        story.append(Paragraph(title, styles["Title"]))
        story.append(Spacer(1, 20))
        story.append(Paragraph(
            "This document contains sensitive information. Unauthorized access is prohibited.",
            styles["Normal"]
        ))
        story.append(Spacer(1, 12))
        story.append(Paragraph(
            "CLASSIFICATION: CONFIDENTIAL — INTERNAL USE ONLY",
            styles["Heading2"]
        ))
        story.append(Spacer(1, 12))
        story.append(Paragraph(
            "Please refer to the appendix for technical details and access credentials.",
            styles["Normal"]
        ))

        # Embed 1x1 transparent pixel image that resolves the DNS canary
        tracking_url = f"http://{dns_canary}/t/{token_uid}.png"
        story.append(Paragraph(
            f'<img src="{tracking_url}" width="1" height="1"/>',
            styles["Normal"]
        ))

        doc.build(story)
    except ImportError:
        # reportlab not installed — create a minimal PDF manually
        pdf_content = (
            b"%PDF-1.4\n"
            b"1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n"
            b"2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n"
            b"3 0 obj<</Type/Page/MediaBox[0 0 612 792]/Parent 2 0 R"
            b"/Contents 4 0 R/Resources<</Font<</F1<</Type/Font"
            b"/Subtype/Type1/BaseFont/Helvetica>>>>>>>>>>endobj\n"
            b"4 0 obj<</Length 44>>\nstream\nBT /F1 12 Tf 100 700 Td"
            b" (Confidential) Tj ET\nendstream\nendobj\n"
            b"xref\n0 5\n0000000000 65535 f\n"
            b"%%EOF\n"
        )
        Path(path).write_bytes(pdf_content)

    return Path(path)


async def _create_docx(
    path: str, title: str, dns_canary: str, token_uid: str, settings: Any
) -> Path:
    try:
        from docx import Document
        from docx.shared import Pt

        doc = Document()
        doc.add_heading(title, 0)
        doc.add_paragraph(
            "This document contains sensitive information. Unauthorized access is prohibited."
        )
        doc.add_heading("CLASSIFICATION: CONFIDENTIAL", level=1)
        doc.add_paragraph(
            "Please refer to the appendix for technical details."
        )

        # Add tracking URL as a 1x1 invisible image reference in footer
        section = doc.sections[0]
        footer = section.footer
        tracking_url = f"http://{dns_canary}/t/{token_uid}"
        footer.paragraphs[0].text = f"\x00{tracking_url}"  # Zero-width, not visible

        doc.save(path)
    except ImportError:
        Path(path).write_bytes(b"PK\x03\x04")  # Minimal ZIP stub

    return Path(path)
