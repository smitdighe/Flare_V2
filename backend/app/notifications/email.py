"""Async SMTP and the message templates. PLAN §8.4.

**THE TIMEOUT IS THE POINT.** The prior codebase called `smtplib.SMTP()` with
no timeout on the request path. Against a host that accepts the TCP connection
and then answers nothing — a black-holed relay, a firewall that drops rather
than rejects — that call blocks a worker forever. `aiosmtplib` with an explicit
timeout, on a background worker, is the fix for both halves of that: the call
cannot outlive the timeout, and it was never on a request path to begin with.

**TRANSIENT AND PERMANENT FAILURES ARE DIFFERENT.** A connection refused, a
timeout or a 4xx is worth retrying. A 5xx is the server saying "not this
message, not ever" — bad mailbox, blocked sender, message rejected — and
retrying it spends the same quota to reproduce the same rejection. The
distinction is made here rather than in the dispatcher because it is a property
of SMTP, not of the policy.

**NO EXTERNAL ASSET, EVER.** No hosted image, no web font, no tracking pixel,
no inline SVG. The card is built from HTML tables and inline CSS only; the
wordmark is text. Two reasons: a security tool that phones home when its own
alert email is opened is an odd thing to demo to a judge, and every hosted
asset is one more thing a spam filter scores against. `test_..._no_external_
asset...` asserts there is exactly one URL in the whole HTML — the dashboard
link — so nothing else can creep in.

**THE HTML IS EMAIL-CLIENT HTML, NOT BROWSER HTML.** Inline CSS on every
element (Gmail strips `<style>`), table layout (Outlook has no flexbox/grid),
web-safe font stacks, ~600px wide. Every block sets BOTH `background-color` and
`color` explicitly, because a client that inverts for dark mode will otherwise
paint dark text on a dark ground. The plain-text alternative carries the same
information — some clients render only that, and it is the accessible path.

**EVERY INTERPOLATED FIELD IS ESCAPED.** A signature is attacker-influenced by
construction (PLAN §9) — the attacker chooses the traffic that generates it —
and the LLM explanation is model output, so both are HTML-escaped on the way
into the HTML part, exactly like any other untrusted input.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from email.headerregistry import Address
from email.message import EmailMessage
from html import escape
from typing import Any, Protocol

import aiosmtplib

from app.config import Settings

logger = logging.getLogger("flare.notifications.email")


class TransientSendError(RuntimeError):
    """The send failed in a way that a retry might fix."""


class PermanentSendError(RuntimeError):
    """The server rejected the message itself. Retrying reproduces it."""


@dataclass(frozen=True)
class Envelope:
    to: str
    subject: str
    text: str
    html: str


class Transport(Protocol):
    async def send(self, envelope: Envelope) -> None: ...


class SmtpTransport:
    """aiosmtplib, fully async, with a timeout on every call."""

    def __init__(self, settings: Settings) -> None:
        if not settings.smtp_host or not settings.smtp_from:
            # Unreachable through config validation, which fails closed at
            # startup. Kept because a transport built by hand in a test or a
            # script would otherwise post to nowhere and report success.
            raise ValueError("SmtpTransport requires smtp_host and smtp_from")
        self.host = settings.smtp_host
        self.port = settings.smtp_port
        self.username = settings.smtp_username
        self.password = settings.smtp_password
        self.sender = settings.smtp_from
        self.sender_name = settings.smtp_from_name
        self.use_tls = settings.smtp_use_tls
        self.start_tls = settings.smtp_start_tls
        self.timeout = settings.smtp_timeout_seconds

    def build(self, envelope: Envelope) -> EmailMessage:
        message = EmailMessage()
        local, _, domain = self.sender.partition("@")
        message["From"] = str(Address(self.sender_name, local, domain))
        message["To"] = envelope.to
        message["Subject"] = envelope.subject
        message.set_content(envelope.text)
        message.add_alternative(envelope.html, subtype="html")
        return message

    async def send(self, envelope: Envelope) -> None:
        try:
            await aiosmtplib.send(
                self.build(envelope),
                hostname=self.host,
                port=self.port,
                username=self.username,
                password=self.password,
                use_tls=self.use_tls,
                start_tls=self.start_tls,
                timeout=self.timeout,
            )
        except aiosmtplib.SMTPResponseException as exc:
            # 4xx is "try again later"; 5xx is "no".
            if 400 <= exc.code < 500:
                raise TransientSendError(f"SMTP {exc.code}: {exc.message}") from exc
            raise PermanentSendError(f"SMTP {exc.code}: {exc.message}") from exc
        except aiosmtplib.SMTPRecipientsRefused as exc:
            raise PermanentSendError(f"recipient refused: {exc}") from exc
        except (TimeoutError, aiosmtplib.SMTPException, OSError) as exc:
            raise TransientSendError(f"{type(exc).__name__}: {exc}") from exc


# ---------------------------------------------------------------------------
# templates
# ---------------------------------------------------------------------------

# Web-safe stacks only. No web fonts — a hosted font is an external asset and a
# spam-filter signal. Monospace carries the technical values (IPs, ports, alert
# ids, signatures); the sans stack carries prose.
_SANS = (
    "-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif"
)
_MONO = "'SFMono-Regular',Consolas,'Liberation Mono',Menlo,Courier,monospace"

# Flare dashboard palette: dark surface, amber/orange accent. Every value is
# used with an explicit partner (bg always paired with fg) so an inverting
# client cannot produce an unreadable block.
_C_PAGE = "#0d0f13"       # outermost ground
_C_CARD = "#161a21"       # card body
_C_BAND = "#12151b"       # header / footer band
_C_INSET = "#0d0f13"      # inset mono panels (flow route, alert rows)
_C_BORDER = "#2b313b"
_C_TEXT = "#e6edf3"       # primary text
_C_DIM = "#9aa4b2"        # labels / secondary
_C_FOOT = "#8b949e"       # footer text
_C_PROSE = "#c9d1d9"      # explanation body
_C_ACCENT = "#f59e0b"     # amber accent
_C_MONO_VAL = "#f0b866"   # warm tint for mono values on the inset

# Severity -> (pill background, pill foreground). Red for critical, amber for
# high; anything else (a rule match below the floor) gets a neutral slate so
# the pill never renders with an undefined colour.
_SEV_PILL: dict[str, tuple[str, str]] = {
    "critical": ("#b3261e", "#ffffff"),
    "high": ("#f59e0b", "#1a1200"),
    "medium": ("#3f4651", "#e6edf3"),
    "low": ("#3f4651", "#e6edf3"),
}
_SEV_PILL_DEFAULT = ("#3f4651", "#e6edf3")

_TECHNIQUE_NAMES: dict[str, str] | None = None


def _technique_name(technique_id: str | None) -> str | None:
    """Best-effort ATT&CK id -> name, from the committed corpus.

    The corpus is the same one the retriever loads (and `load_corpus` is itself
    cached), so this costs one dict comprehension on first use and nothing
    after. Wrapped so a missing or unreadable corpus degrades the email to the
    bare technique id rather than failing the send.
    """
    global _TECHNIQUE_NAMES
    if not technique_id:
        return None
    if _TECHNIQUE_NAMES is None:
        try:
            from app.rag.loader import load_corpus

            _TECHNIQUE_NAMES = {t.technique_id: t.name for t in load_corpus()}
        except Exception:
            # The email must still render if the corpus is missing or broken.
            _TECHNIQUE_NAMES = {}
    return _TECHNIQUE_NAMES.get(technique_id)


def _mitre_display(alert: dict[str, Any]) -> str:
    # ASCII only: this string goes into both the text part and the HTML part,
    # and a client that misreads the charset should still render it cleanly.
    tid = alert.get("mitre_technique")
    if not tid:
        return "not mapped"
    name = _technique_name(str(tid))
    return f"{tid} ({name})" if name else str(tid)


def _flow(alert: dict[str, Any]) -> str:
    src = alert.get("src_ip") or "?"
    dest = alert.get("dest_ip") or "?"
    port = alert.get("dest_port")
    target = f"{dest}:{port}" if port is not None else str(dest)
    return f"{src} -> {target}"


def _verdict(alert: dict[str, Any]) -> str | None:
    """The artifact that produced the verdict, from the payload if it is there.

    `confidence` is a top-level field; the producing tier and its version are on
    the `classify` entry of the trace (I16). Either, both or neither may be
    present — a rollup line carries none of it, a single replayed alert carries
    all of it.
    """
    provider: str | None = None
    version: str | None = None
    for entry in alert.get("trace") or []:
        if isinstance(entry, dict) and entry.get("node") == "classify":
            provider = entry.get("provider")
            version = entry.get("model_version")
            break

    bits: list[str] = []
    if provider:
        bits.append(f"{provider} {version}".strip() if version else provider)
    confidence = alert.get("confidence")
    if isinstance(confidence, (int, float)) and not isinstance(confidence, bool):
        bits.append(f"confidence {round(float(confidence) * 100)}%")
    # ASCII separator on purpose (shared by the text and HTML parts).
    return " | ".join(bits) or None


def _line(alert: dict[str, Any]) -> str:
    """One compact line for a rollup/digest list and for the plain-text body."""
    return (
        f"[{str(alert.get('severity', 'unknown')).upper()}] "
        f"{alert.get('id', '?')}  {alert.get('attack_type', 'unknown')}  "
        f"{_flow(alert)}"
    )


def _detail_pairs(alert: dict[str, Any]) -> list[tuple[str, str]]:
    """Label/value rows for the single-alert detail block, both parts."""
    pairs: list[tuple[str, str]] = [
        ("Alert", str(alert.get("id", "?"))),
        ("Severity", str(alert.get("severity", "unknown")).upper()),
        ("Attack type", str(alert.get("attack_type", "unknown"))),
        ("Flow", f"{_flow(alert)} / {alert.get('protocol', '?')}"),
        ("Protocol", str(alert.get("protocol", "?"))),
        ("Signature", str(alert.get("signature", "") or "-")),
        ("MITRE", _mitre_display(alert)),
    ]
    verdict = _verdict(alert)
    if verdict:
        pairs.append(("Verdict by", verdict))
    return pairs


def _minutes(window_minutes: float) -> int | float:
    whole = window_minutes == int(window_minutes)
    return int(window_minutes) if whole else round(window_minutes, 1)


# -- HTML fragments ---------------------------------------------------------
#
# Kept as small functions rather than one f-string so the table nesting stays
# readable. Every fragment sets background-color AND color on its own cells.


def _html_shell(inner: str) -> str:
    return (
        f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0" '
        f'border="0" bgcolor="{_C_PAGE}" style="margin:0;padding:0;'
        f'background-color:{_C_PAGE};width:100%;">'
        f'<tr><td align="center" style="padding:24px 12px;'
        f'background-color:{_C_PAGE};">'
        f'<table role="presentation" width="600" cellpadding="0" cellspacing="0" '
        f'border="0" style="width:600px;max-width:600px;background-color:{_C_CARD};'
        f'border:1px solid {_C_BORDER};border-radius:10px;">'
        f"{inner}"
        f"</table></td></tr></table>"
    )


def _html_header(severity: str, count: int) -> str:
    bg, fg = _SEV_PILL.get(severity.lower(), _SEV_PILL_DEFAULT)
    pill_text = escape(severity.upper()) or "ALERT"
    badge = (
        f'&nbsp;<span style="font-family:{_MONO};font-size:12px;font-weight:700;'
        f'color:{fg};background-color:{bg};">x{count}</span>'
        if count > 1
        else ""
    )
    return (
        f'<tr><td style="padding:18px 24px;background-color:{_C_BAND};'
        f'border-bottom:1px solid {_C_BORDER};border-radius:10px 10px 0 0;">'
        f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0" '
        f'border="0" style="background-color:{_C_BAND};"><tr>'
        f'<td style="font-family:{_MONO};font-size:18px;font-weight:700;'
        f'letter-spacing:3px;color:{_C_ACCENT};background-color:{_C_BAND};">'
        f"FLARE</td>"
        f'<td align="right" style="background-color:{_C_BAND};">'
        f'<span style="display:inline-block;padding:5px 12px;border-radius:4px;'
        f'font-family:{_MONO};font-size:12px;font-weight:700;letter-spacing:1px;'
        f'background-color:{bg};color:{fg};">{pill_text}</span>{badge}</td>'
        f"</tr></table></td></tr>"
    )


def _html_hero_single(alert: dict[str, Any]) -> str:
    alert_id = escape(str(alert.get("id", "?")))
    attack = escape(str(alert.get("attack_type", "alert")))
    flow = escape(_flow(alert))
    return (
        f'<tr><td style="padding:24px 24px 6px;background-color:{_C_CARD};">'
        f'<div style="font-family:{_SANS};font-size:11px;letter-spacing:1px;'
        f'color:{_C_DIM};background-color:{_C_CARD};">ALERT '
        f'<span style="font-family:{_MONO};color:{_C_TEXT};">{alert_id}</span>'
        f"</div>"
        f'<div style="font-family:{_SANS};font-size:20px;font-weight:700;'
        f'color:{_C_TEXT};background-color:{_C_CARD};padding-top:4px;">{attack}</div>'
        f'<div style="font-family:{_MONO};font-size:14px;color:{_C_MONO_VAL};'
        f'background-color:{_C_INSET};border:1px solid {_C_BORDER};'
        f'border-radius:6px;padding:11px 13px;margin-top:12px;">{flow}</div>'
        f"</td></tr>"
    )


def _html_hero_rollup(headline: str, top_alert: dict[str, Any]) -> str:
    return (
        f'<tr><td style="padding:24px 24px 8px;background-color:{_C_CARD};">'
        f'<div style="font-family:{_SANS};font-size:11px;letter-spacing:1px;'
        f'color:{_C_DIM};background-color:{_C_CARD};">NOTIFICATION DIGEST</div>'
        f'<div style="font-family:{_SANS};font-size:20px;font-weight:700;'
        f'color:{_C_TEXT};background-color:{_C_CARD};padding-top:4px;">'
        f"{escape(headline)}</div>"
        f'<div style="font-family:{_SANS};font-size:13px;color:{_C_DIM};'
        f'background-color:{_C_CARD};padding-top:6px;">Most severe: '
        f'<span style="font-family:{_MONO};color:{_C_MONO_VAL};">'
        f'{escape(str(top_alert.get("attack_type", "unknown")))} '
        f'{escape(_flow(top_alert))}</span></div>'
        f"</td></tr>"
    )


def _html_detail(alert: dict[str, Any]) -> str:
    rows = "".join(
        f'<tr>'
        f'<td style="padding:5px 14px 5px 0;font-family:{_SANS};font-size:12px;'
        f'color:{_C_DIM};background-color:{_C_CARD};vertical-align:top;'
        f'white-space:nowrap;">{escape(label)}</td>'
        f'<td style="padding:5px 0;font-family:{_MONO};font-size:13px;'
        f'color:{_C_TEXT};background-color:{_C_CARD};">{escape(value)}</td>'
        f"</tr>"
        for label, value in _detail_pairs(alert)
        if label != "Flow"  # the flow is the hero panel in HTML; keep it in text
    )
    return (
        f'<tr><td style="padding:14px 24px 6px;background-color:{_C_CARD};">'
        f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0" '
        f'border="0" style="background-color:{_C_CARD};border-top:1px solid '
        f'{_C_BORDER};padding-top:8px;">{rows}</table></td></tr>'
    )


def _html_alert_list(shown: list[dict[str, Any]], hidden: int) -> str:
    items = "".join(
        f'<tr><td style="padding:8px 13px;font-family:{_MONO};font-size:12px;'
        f'color:{_C_MONO_VAL};background-color:{_C_INSET};'
        f'border-bottom:1px solid {_C_BORDER};">{escape(_line(a))}</td></tr>'
        for a in shown
    )
    more = (
        f'<tr><td style="padding:8px 13px;font-family:{_SANS};font-size:12px;'
        f'color:{_C_DIM};background-color:{_C_INSET};">... and {hidden} '
        f"more</td></tr>"
        if hidden > 0
        else ""
    )
    return (
        f'<tr><td style="padding:12px 24px 4px;background-color:{_C_CARD};">'
        f'<table role="presentation" width="100%" cellpadding="0" cellspacing="0" '
        f'border="0" style="background-color:{_C_INSET};border:1px solid '
        f'{_C_BORDER};border-radius:6px;">{items}{more}</table></td></tr>'
    )


def _html_explanation(explanation: str) -> str:
    body = escape(explanation).replace("\n", "<br>")
    return (
        f'<tr><td style="padding:16px 24px 4px;background-color:{_C_CARD};">'
        f'<div style="background-color:{_C_BAND};border-left:3px solid {_C_ACCENT};'
        f'border-radius:4px;padding:14px 16px;">'
        f'<div style="font-family:{_SANS};font-size:11px;letter-spacing:1px;'
        f'color:{_C_DIM};background-color:{_C_BAND};padding-bottom:6px;">'
        f"ANALYST NOTE</div>"
        f'<div style="font-family:{_SANS};font-size:14px;line-height:1.55;'
        f'color:{_C_PROSE};background-color:{_C_BAND};">{body}</div>'
        f"</div></td></tr>"
    )


def _html_cta(dashboard_url: str) -> str:
    href = escape(dashboard_url)
    return (
        f'<tr><td align="center" style="padding:18px 24px 24px;'
        f'background-color:{_C_CARD};">'
        f'<table role="presentation" cellpadding="0" cellspacing="0" border="0" '
        f'style="background-color:{_C_ACCENT};border-radius:6px;">'
        f'<tr><td align="center" bgcolor="{_C_ACCENT}" '
        f'style="background-color:{_C_ACCENT};border-radius:6px;">'
        f'<a href="{href}" style="display:inline-block;padding:12px 30px;'
        f'font-family:{_SANS};font-size:14px;font-weight:700;color:#1a1200;'
        f'text-decoration:none;">View in Flare</a>'
        f"</td></tr></table></td></tr>"
    )


def _html_footer(event_type: str) -> str:
    return (
        f'<tr><td style="padding:16px 24px;background-color:{_C_BAND};'
        f'border-top:1px solid {_C_BORDER};border-radius:0 0 10px 10px;'
        f'font-family:{_SANS};font-size:12px;line-height:1.5;color:{_C_FOOT};">'
        f"Sent because you subscribed to {escape(event_type)} and were not "
        f"watching the live feed. Turn this off under Notifications in the "
        f"dashboard.</td></tr>"
    )


def render(
    *,
    to: str,
    event_type: str,
    alerts: list[dict[str, Any]],
    total: int,
    window_minutes: float,
    dashboard_url: str,
    digest_max: int,
) -> Envelope:
    """One email for one dispatch window.

    `total` is how many alerts the window covered; `alerts` is what is being
    listed, which is fewer once the digest cap bites. The two are reported
    separately rather than collapsed, so the email never implies it is showing
    everything it counted.

    A single alert renders as the full card — hero flow, detail block, analyst
    note. A rollup (two or more) renders the count, a compact monospace list
    capped at `digest_max` with "and N more", and no per-alert detail. Both go
    through the same shell, CTA and footer.
    """
    top = alerts[0] if alerts else {}
    severity = str(top.get("severity", "unknown"))
    minutes = _minutes(window_minutes)

    if total == 1:
        attack = top.get("attack_type", "alert")
        subject = (
            f"[Flare] {severity.upper()} - {attack} {top.get('id', '')}".strip()
        )
        headline = f"1 {severity.lower()} alert"
    else:
        subject = f"[Flare] {total} alerts in the last {minutes} minutes"
        headline = f"{total} alerts in the last {minutes} minutes"

    shown = alerts[:digest_max]
    hidden = total - len(shown)

    # -- plain text (kept close to the prior shape; some clients render only
    #    this, and it is the accessible path) --------------------------------
    text_parts = [headline, "", *[_line(a) for a in shown]]
    if hidden > 0:
        text_parts.append(f"... and {hidden} more")
    if total == 1 and top:
        text_parts += ["", *[f"{label}: {value}" for label, value in _detail_pairs(top)]]
        explanation = top.get("explanation")
        if explanation:
            text_parts += ["", str(explanation)]
    text_parts += [
        "",
        f"Open the dashboard: {dashboard_url}",
        "",
        f"Sent because you subscribed to {event_type} and were not watching the "
        "live feed. Turn this off under Notifications in the dashboard.",
    ]

    # -- HTML card --------------------------------------------------------------
    blocks = [_html_header(severity, total)]
    if total == 1:
        blocks.append(_html_hero_single(top))
        blocks.append(_html_detail(top))
        explanation = top.get("explanation")
        if explanation:
            blocks.append(_html_explanation(str(explanation)))
    else:
        blocks.append(_html_hero_rollup(headline, top))
        blocks.append(_html_alert_list(shown, hidden))
    blocks.append(_html_cta(dashboard_url))
    blocks.append(_html_footer(event_type))
    html = _html_shell("".join(blocks))

    return Envelope(to=to, subject=subject, text="\n".join(text_parts), html=html)
