"""The forwarder's credential. PLAN §9 / §4.4a / §21 item 10.

**A DEDICATED SERVICE TOKEN, NOT A USER JWT.** The forwarder runs unattended on
the box we are deliberately attacking. Giving it a user's access token would put
that account's full authority — every alert, every rule, every export — on the
most compromisable machine in the room, and a JWT additionally expires in 30
minutes, so the only way to make one work unattended would be to store refresh
credentials there too.

The token is a shared secret compared in CONSTANT TIME. `==` on a secret leaks
its prefix through timing, and this is the one endpoint an outsider can reach.

It is never logged, never traced, never echoed in an error. A wrong token gets
the same message as a missing one, so the response cannot be used to learn
whether a guessed prefix was closer.
"""

from __future__ import annotations

import hmac

from fastapi import Request, status

from app.api.errors import AppError
from app.config import get_settings

#: Non-standard scheme name on purpose. `Bearer` is the user-JWT scheme in
#: `app/api/deps.py`, and a header that looks identical to the user one invites
#: exactly the confusion this module exists to prevent — a forwarder configured
#: with someone's access token, working, and nobody noticing.
SCHEME = "ServiceToken"


def verify_service_token(request: Request) -> None:
    """Authorize an ingest request, or raise 401. Never says which half failed."""
    settings = get_settings()

    header = request.headers.get("Authorization", "")
    scheme, _, presented = header.partition(" ")

    configured = settings.ingest_service_token
    # Config already fails closed at startup when the feature is on, so an
    # empty value here means the feature is off and the route should not have
    # been reachable. Refuse rather than compare against "".
    if not configured or scheme != SCHEME or not presented:
        raise _unauthorized()

    if not hmac.compare_digest(presented, configured):
        raise _unauthorized()


def _unauthorized() -> AppError:
    return AppError(
        "unauthorized",
        f"Ingest requires a valid {SCHEME} credential.",
        status.HTTP_401_UNAUTHORIZED,
    )
