"""CSV and PDF writers for the alert export. PLAN §9 / CONTRACT §2.5.

**FORMULA INJECTION IS ESCAPED.** A CSV cell beginning `=`, `+`, `-`, `@`, a
tab or a carriage return is interpreted as a FORMULA by Excel, LibreOffice and
Google Sheets. Alert text is attacker-influenced — a Suricata signature comes
from a rule matching traffic the attacker generated, and on the live-demo path
the attacker chose the bytes — so `=cmd|'/c calc'!A1` in a signature becomes
code execution on the analyst's workstation when they open the export. Every
cell is prefixed with a single quote when it starts with one of those
characters. The escape is applied to VALUES, not to the file, so the data is
still readable and the provenance of the quote is obvious.

**HEADERS ARE EMITTED EVEN ON AN EMPTY SET.** A zero-byte file is
indistinguishable from a failed download, and the frozen frontend swallows
export errors to `console.error` (WorkspacePanel.jsx:626) — the user sees
nothing. A header row proves the export ran.

`csv.DictWriter` with an explicit field list rather than a hand-rolled join:
quoting, embedded commas and embedded newlines are its job, and getting any of
them wrong produces a file that opens with the columns shifted.
"""

from __future__ import annotations

import csv
import io
from datetime import UTC, datetime
from typing import Any

# OWASP's CSV-injection set, plus the two whitespace characters that let a
# payload smuggle itself past a naive first-character check.
DANGEROUS_PREFIXES: tuple[str, ...] = ("=", "+", "-", "@", "\t", "\r")

COLUMNS: tuple[str, ...] = (
    "id",
    "timestamp",
    "source",
    "severity",
    "attack_type",
    "src_ip",
    "dest_ip",
    "dest_port",
    "protocol",
    "signature",
    "mitre_technique",
    "ioc_checked",
    "ioc_reputation",
    "vt_ip",
    "confidence",
    "degraded",
    "tags",
    "rules_fired",
    "explanation",
    "remediation",
)


def escape_cell(value: Any) -> str:
    """One cell, safe to open in a spreadsheet.

    A leading `'` is the documented neutraliser: the spreadsheet treats the
    rest as literal text. Numbers are formatted first so a negative number
    (which starts with `-`) is quoted too — that is not a false positive, it is
    the same character a formula starts with, and a quoted `-3` still reads as
    -3 to a human.
    """
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, list | tuple):
        text = ",".join(str(item) for item in value)
    else:
        text = str(value)
    if text.startswith(DANGEROUS_PREFIXES):
        return "'" + text
    return text


def _row(alert: Any) -> dict[str, str]:
    fired = sum(1 for entry in (alert.rule_trace or []) if entry.get("fired"))
    values: dict[str, Any] = {
        "id": alert.id,
        "timestamp": _iso(alert.timestamp),
        "source": alert.source,
        "severity": alert.severity,
        "attack_type": alert.attack_type,
        "src_ip": alert.src_ip,
        "dest_ip": alert.dest_ip,
        "dest_port": alert.dest_port,
        "protocol": alert.protocol,
        "signature": alert.signature,
        "mitre_technique": alert.mitre_technique,
        "ioc_checked": alert.ioc_checked,
        "ioc_reputation": alert.ioc_reputation,
        "vt_ip": alert.vt_ip,
        "confidence": alert.confidence,
        "degraded": alert.degraded,
        "tags": alert.tags or [],
        "rules_fired": fired,
        "explanation": alert.explanation,
        "remediation": alert.remediation,
    }
    return {key: escape_cell(values[key]) for key in COLUMNS}


def _iso(value: datetime) -> str:
    return (value if value.tzinfo else value.replace(tzinfo=UTC)).isoformat()


def write_csv(alerts: list[Any]) -> bytes:
    """UTF-8 with a BOM.

    The BOM is what makes Excel on Windows read the file as UTF-8 instead of
    the system codepage; without it an IPv6 address or a non-ASCII signature
    renders as mojibake and the export looks broken.
    """
    buffer = io.StringIO(newline="")
    writer = csv.DictWriter(buffer, fieldnames=list(COLUMNS), extrasaction="ignore")
    writer.writeheader()
    for alert in alerts:
        writer.writerow(_row(alert))
    return buffer.getvalue().encode("utf-8-sig")


# ---------------------------------------------------------------------------
# PDF
# ---------------------------------------------------------------------------

PDF_COLUMNS: tuple[tuple[str, str, int], ...] = (
    ("id", "ALERT", 62),
    ("timestamp", "TIME", 74),
    ("severity", "SEV", 44),
    ("attack_type", "VECTOR", 66),
    ("src_ip", "SOURCE", 78),
    ("dest_ip", "DEST", 78),
    ("dest_port", "PORT", 32),
    ("mitre_technique", "MITRE", 50),
    ("signature", "SIGNATURE", 168),
)


def write_pdf(alerts: list[Any], *, filters: dict[str, Any]) -> bytes:
    """A formatted report, not a CSV with a different extension.

    The filter set that produced the export is printed on the cover line: a
    report that does not say what it is a report OF is unreadable a week later,
    and the frozen UI sends the live dashboard filters without echoing them
    anywhere the reader can see.
    """
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import landscape, letter
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import (
        Paragraph,
        SimpleDocTemplate,
        Spacer,
        Table,
        TableStyle,
    )

    buffer = io.BytesIO()
    document = SimpleDocTemplate(
        buffer,
        pagesize=landscape(letter),
        leftMargin=12 * mm,
        rightMargin=12 * mm,
        topMargin=12 * mm,
        bottomMargin=12 * mm,
        title="Flare alert export",
        author="Flare",
    )
    styles = getSampleStyleSheet()
    cell = styles["BodyText"].clone("cell")
    cell.fontSize = 6.5
    cell.leading = 8

    described = ", ".join(f"{k}={v}" for k, v in sorted(filters.items()) if v) or "none"
    story: list[Any] = [
        Paragraph("Flare — alert export", styles["Title"]),
        Paragraph(
            f"{len(alerts)} alert(s) · filters: {described} · generated "
            f"{datetime.now(UTC).isoformat(timespec='seconds')}",
            styles["Normal"],
        ),
        Spacer(1, 6 * mm),
    ]

    header = [Paragraph(f"<b>{label}</b>", cell) for _, label, _ in PDF_COLUMNS]
    body: list[list[Any]] = [header]
    for alert in alerts:
        row = _row(alert)
        body.append([Paragraph(row[key], cell) for key, _, _ in PDF_COLUMNS])

    if len(body) == 1:
        # Same reasoning as the CSV header: an empty page that says it is empty
        # beats a blank page that could be a failure.
        story.append(
            Paragraph(
                "No alerts matched these filters.", styles["Normal"]
            )
        )
    else:
        table = Table(
            body,
            colWidths=[width for _, _, width in PDF_COLUMNS],
            repeatRows=1,
        )
        table.setStyle(
            TableStyle(
                [
                    ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#B0B4BA")),
                    (
                        "BACKGROUND",
                        (0, 0),
                        (-1, 0),
                        colors.HexColor("#1F2933"),
                    ),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    (
                        "ROWBACKGROUNDS",
                        (0, 1),
                        (-1, -1),
                        [colors.white, colors.HexColor("#F2F4F6")],
                    ),
                ]
            )
        )
        story.append(table)

    document.build(story)
    return buffer.getvalue()
