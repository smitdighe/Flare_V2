"""CSV and PDF export. PLAN §9 / CONTRACT §2.5.

**FORMULA INJECTION IS THE POINT OF THIS FILE.** A cell beginning `=`, `+`, `-`
or `@` is executed as a formula by Excel, LibreOffice and Google Sheets. Alert
text is attacker-influenced — a Suricata signature comes from a rule matching
traffic the attacker generated — so a payload in a signature becomes code
running on the analyst's workstation when they open the export we handed them.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from app.export.writers import COLUMNS, escape_cell, write_csv, write_pdf
from app.store.models import Alert

PAYLOAD = '=cmd|\'/c calc\'!A1'


def alert(**overrides: object) -> Alert:
    base: dict[str, object] = {
        "id": "ALT-ABC123",
        "timestamp": datetime(2025, 9, 5, 7, 40, tzinfo=UTC),
        "source": "cicids_replay",
        "severity": "high",
        "attack_type": "dos",
        "src_ip": "118.25.6.39",
        "dest_ip": "192.168.10.50",
        "dest_port": 80,
        "protocol": "TCP",
        "signature": "Flow to TCP/80 — SYN-heavy",
        "mitre_technique": "T1498",
        "ioc_checked": True,
        "ioc_reputation": 92,
        "vt_ip": "3/94",
        "explanation": "A burst of unanswered SYNs.",
        "remediation": "Rate-limit at the edge.",
        "confidence": 1.0,
        "degraded": False,
        "tags": [],
        "trace": [],
        "rule_trace": [],
    }
    base.update(overrides)
    return Alert(**base)  # type: ignore[arg-type]


def _lines(payload: bytes) -> list[str]:
    return payload.decode("utf-8-sig").splitlines()


# ---------------------------------------------------------------------------
# formula injection
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("prefix", ["=", "+", "-", "@", "\t", "\r"])
def test_every_dangerous_prefix_is_neutralised(prefix: str) -> None:
    assert escape_cell(f"{prefix}danger").startswith("'")


def test_a_formula_in_a_signature_does_not_survive_into_the_csv() -> None:
    body = write_csv([alert(signature=PAYLOAD)])
    text = body.decode("utf-8-sig")

    assert PAYLOAD in text, "the value is preserved — it is quoted, not deleted"
    assert f",{PAYLOAD}" not in text, "…and never as the first character of a cell"
    assert "'=cmd" in text


def test_a_formula_in_a_tag_written_by_a_rule_is_also_escaped() -> None:
    """Tags come from a rule an operator typed — still not trusted input."""
    text = write_csv([alert(tags=["@SUM(1+1)"])]).decode("utf-8-sig")
    assert "'@SUM(1+1)" in text


def test_ordinary_text_is_not_mangled() -> None:
    text = write_csv([alert()]).decode("utf-8-sig")
    assert "Flow to TCP/80 — SYN-heavy" in text
    assert "'Flow" not in text


def test_an_embedded_comma_and_newline_stay_inside_one_cell() -> None:
    """This is why it is `csv.DictWriter` and not a join.

    A hand-rolled join shifts every column after the comma, and the file opens
    looking plausible and being wrong.
    """
    rows = _lines(write_csv([alert(signature='DoS, "flood"\nsecond line')]))
    assert len(rows) == 3, "header + one record spanning two physical lines"
    assert rows[0].startswith("id,timestamp")


# ---------------------------------------------------------------------------
# headers and shape
# ---------------------------------------------------------------------------


def test_headers_are_emitted_on_an_empty_set() -> None:
    """A zero-byte file is indistinguishable from a failed download, and the
    frozen frontend swallows export errors to console.error."""
    rows = _lines(write_csv([]))
    assert rows == [",".join(COLUMNS)]


def test_the_utf8_bom_is_present_so_excel_reads_it_as_utf8() -> None:
    assert write_csv([]).startswith(b"\xef\xbb\xbf")


def test_the_ground_truth_label_is_not_exported() -> None:
    """PLAN I4 — the label never travels with a rendered alert, anywhere."""
    assert "ground_truth_class" not in COLUMNS
    assert "ground_truth" not in write_csv([alert()]).decode("utf-8-sig")


# ---------------------------------------------------------------------------
# PDF
# ---------------------------------------------------------------------------


def test_the_pdf_is_a_real_pdf_and_carries_the_rows() -> None:
    payload = write_pdf([alert()], filters={"severity": "high"})
    assert payload.startswith(b"%PDF-")
    assert len(payload) > 1000


def test_an_empty_pdf_says_it_is_empty_rather_than_being_blank() -> None:
    payload = write_pdf([], filters={})
    assert payload.startswith(b"%PDF-")
