import os
from functools import lru_cache
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Runtime configuration.

    PLAN §14: every field here is read by real code. A setting that nothing reads
    does not belong in this class.
    """

    model_config = SettingsConfigDict(
        # Tests set FLARE_DISABLE_ENV_FILE so the suite is hermetic — a local
        # .env carrying real provider keys must not change what passes.
        env_file=None if os.getenv("FLARE_DISABLE_ENV_FILE") else ".env",
        env_file_encoding="utf-8",
        extra="forbid",
    )

    # PLAN §9: no hardcoded fallback, no default that silently works.
    # Absence is a startup failure, not a warning.
    jwt_secret: str = Field(min_length=32)

    jwt_algorithm: Literal["HS256"] = "HS256"

    # PLAN §3.1 / CONTRACT §5.2: the login panel renders "jwt · 30m access".
    # That claim is only true because this value is 30.
    access_token_ttl_minutes: int = Field(default=30, gt=0)
    refresh_token_ttl_days: int = Field(default=7, gt=0)

    database_url: str = "sqlite+aiosqlite:///./flare.db"

    environment: Literal["dev", "test", "prod"] = "dev"

    # PLAN §9: closed by default; `*` only under an explicit dev flag, and never
    # together with credentials.
    cors_origins: list[str] = ["http://localhost:5174"]
    cors_allow_credentials: bool = False

    # PLAN §9 / CONTRACT §1.5: a real 429 as a JSONResponse.
    rate_limit_requests: int = Field(default=120, gt=0)
    rate_limit_window_seconds: int = Field(default=60, gt=0)

    # CONTRACT §9.5: cached provider state is served for 60s and refreshed once
    # it passes 120s. Phase 1 serves the cache; Phase 3 fills it.
    health_cache_ttl_seconds: int = Field(default=60, gt=0)
    health_cache_stale_seconds: int = Field(default=120, gt=0)

    # PLAN §9 / CONTRACT §8.7: admin@flare.dev exists ONLY when this is on.
    # Default boot must not create it.
    demo_seed_enabled: bool = False

    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"

    # Replay feed. PLAN §10: rate is a first-class config, tuned so a 5-10
    # minute demo stays under every provider cap with headroom.
    replay_alerts_per_minute: float = Field(default=30.0, gt=0)
    replay_autostart: bool = True

    # PLAN D26 — provider key pool, N per provider, N is config not a constant.
    # Purposes: `dev` burns during development, `reserved` is untouched until
    # the demo, `spare` is the fallback if reserved runs out mid-demo.
    # `app/providers/keypool.py` is the single reader: sticky-until-exhausted
    # selection, cooling on 429, dead-on-403. A Phase 2 configuration-view
    # module (`app/core/providers.py`) described the same thing and was
    # superseded by that pool in Phase 3; it was deleted in Phase 8 rather than
    # left as a second, stale definition of one concept. Values are NEVER
    # logged, traced or returned — only the label and the count (I16).
    groq_api_key_dev: str | None = None
    groq_api_key_reserved: str | None = None
    groq_api_key_spare: str | None = None

    gemini_api_key_dev: str | None = None
    gemini_api_key_reserved: str | None = None
    gemini_api_key_spare: str | None = None

    abuseipdb_api_key: str | None = None
    virustotal_api_key: str | None = None

    # ------------------------------------------------------------------
    # Providers — PLAN D31. Every string here was verified by a live call
    # against this project's own keys, not read off a docs page and not
    # recalled. `python -m scripts.verify_models` reproduces the check.
    # ------------------------------------------------------------------
    groq_model_primary: str = "openai/gpt-oss-120b"
    groq_model_fallback: str = "qwen/qwen3.8-27b"

    # PLAN D29 / I18. GPT OSS is a reasoning model and has returned 200 with an
    # empty `message.content` because the answer went to a separate channel.
    # "hidden" suppresses that channel and leaves the final answer in `content`.
    # Set explicitly rather than trusted: the default DOES populate content
    # today, but it also emits a `reasoning` sibling, so the default is a
    # behaviour we are not in control of.
    groq_reasoning_format: Literal["hidden", "parsed", "raw"] = "hidden"
    groq_reasoning_effort: Literal["low", "medium", "high"] = "low"

    # PLAN D30/D31. gemini-2.5-flash is LISTED by the models endpoint and 404s
    # on generateContent ("no longer available to new users … use
    # models/gemini-3.6-flash"). Being listed is not being callable.
    gemini_model: str = "gemini-3.6-flash"

    # PLAN D30 — THIS AND `llm_timeout_seconds_gemini` ARE ONE SETTING IN TWO
    # FIELDS. Changing either alone is the bug the decision exists to prevent.
    # Measured at "low": 3.1-5.0s median, 20.6s tail. A 12s ceiling failed
    # roughly one call in eight.
    gemini_thinking_level: Literal["low", "high"] = "low"

    llm_timeout_seconds_groq: float = Field(default=15.0, gt=0)
    llm_timeout_seconds_gemini: float = Field(default=25.0, gt=0)
    intel_timeout_seconds: float = Field(default=8.0, gt=0)

    # PLAN §10.3 — how long a key stays cooling after a 429 with no
    # Retry-After. Long enough that a burst does not immediately re-burn it.
    key_cooldown_seconds: float = Field(default=60.0, gt=0)

    # PLAN §4.1 — the whole graph gets a wall clock. Past it the run returns
    # PARTIAL state with traced skips rather than hanging a stream slot.
    graph_budget_seconds: float = Field(default=45.0, gt=0)
    max_concurrent_pipelines: int = Field(default=8, gt=0)

    # ------------------------------------------------------------------
    # Tiering — PLAN D18/D19. TWO INDEPENDENT GATES, deliberately.
    # ------------------------------------------------------------------
    # Gate 1: CLASSIFICATION escalation. Measured on the eval partition in
    # Phase 2a (MODEL_CARD "Escalation threshold"). Expect it to fire on ~0.3%
    # of replay alerts — isotonic on a well-separated problem pushes 99.7% of
    # confident predictions to exactly 1.0. That is a correct outcome, not a
    # broken gate.
    escalation_confidence_threshold: float = Field(default=0.99, gt=0, le=1)

    # Gate 2: REASONING. NOT the same gate, and not derived from gate 1. A
    # perfectly-classified critical alert still needs an explanation for the
    # analyst — reasoning is narrative, MITRE mapping and remediation, which is
    # a different job from classification. Gating it on classifier confidence
    # would silence the LLM on exactly the alerts that most need it.
    reason_severity_floor: Literal["low", "medium", "high", "critical"] = "high"

    # PLAN §10.4 — rate is first-class config, and THIS is what actually keeps
    # the demo under cap. The floor alone does not: measured on the replay
    # partition, `high` and above is 67% of alerts, so at 30 alerts/min the
    # floor admits ~20/min against Gemini's ~15 RPM free tier.
    #
    # 10/min is 67% of that cap. A measured run at 12/min still drew 429s when
    # alerts arrived in a burst, so the headroom is bought deliberately rather
    # than trusted to averaging. An alert over budget gets a TRACED skip naming
    # the budget — never a silent drop (T12/I5).
    reason_calls_per_minute: float = Field(default=10.0, gt=0)

    # ------------------------------------------------------------------
    # Enrichment — PLAN §10.2 / Part D.
    # ------------------------------------------------------------------
    # AbuseIPDB confidence at or above this forces `high` when the model said
    # less. Intel outranks the model (it is evidence about the actual internet,
    # not an inference about a flow shape).
    intel_escalation_score: int = Field(default=50, ge=0, le=100)
    intel_cache_ttl_seconds: float = Field(default=900.0, gt=0)
    intel_cache_max_entries: int = Field(default=2048, gt=0)

    # ------------------------------------------------------------------
    # Retrieval — PLAN §4.4.
    # ------------------------------------------------------------------
    retrieval_top_k: int = Field(default=5, gt=0)
    # Below this the match is reported as low-confidence in the trace. It does
    # NOT drop the result: webattack-brute-force legitimately retrieves
    # T1505.003 over T1110 because the flow shapes are identical, and hiding
    # that would be presenting a weak match as a confident one.
    retrieval_low_confidence_score: float = Field(default=0.45, ge=0, le=1)

    # PLAN §10.4 / E9 — declared and labelled, never silent. Every payload
    # produced in this mode carries `degraded: true` and a trace entry naming
    # `offline` as the provider.
    offline_mode: bool = False

    # ------------------------------------------------------------------
    # Phase 4 — product surface.
    # ------------------------------------------------------------------
    # CONTRACT §9.5 — /health/deep spends FOUR metered quotas per call and is
    # manual-refresh-only. The global limiter is not what the contract asks
    # for: it is sized for ordinary API traffic (120/min), so one operator
    # holding the refresh button could draw 480 provider calls a minute
    # through it. This is a SECOND, per-user budget applied to that route
    # only.
    health_deep_calls_per_minute: float = Field(default=4.0, gt=0)

    # PLAN §9 / CONTRACT RuleCondition — the `contains` operator compiles
    # USER-SUPPLIED text as a regex. Three bounds, applied at different times:
    # the first two at rule-creation, the last two on every match.
    rule_regex_max_length: int = Field(default=200, gt=0)
    rule_regex_max_quantifiers: int = Field(default=8, gt=0)
    rule_regex_match_timeout_seconds: float = Field(default=0.05, gt=0)
    rule_regex_max_subject_length: int = Field(default=1024, gt=0)

    # The frozen export button always sends limit=500 (WorkspacePanel.jsx:610).
    export_max_rows: int = Field(default=500, gt=0)

    # PLAN §3.1 — threat clusters are served from the DB with a REAL
    # min_alerts threshold, not a client-side reduce over the 200-alert buffer.
    correlation_min_alerts: int = Field(default=3, gt=0)
    correlation_window_minutes: int = Field(default=1440, gt=0)

    # CONTRACT §9.4 / PLAN D7 — the event-velocity histogram. One-minute
    # buckets over a 30-minute window, so a bucket count IS alerts-per-minute
    # and `alert_velocity` (the mean over the window) needs no rescaling.
    stats_window_minutes: int = Field(default=30, gt=0)
    stats_bucket_seconds: int = Field(default=60, gt=0)

    # PLAN §3.1 right rail. `signal velocity` is a SAMPLED series — the
    # scheduler records one observation per interval and the panel plots those
    # samples, which is what "real samples" means. The forecast window is the
    # window-over-window delta of PLAN D8.
    metrics_sample_interval_seconds: int = Field(default=60, gt=0)
    metrics_sample_window_minutes: int = Field(default=60, gt=0)
    forecast_window_minutes: int = Field(default=30, gt=0)
    # How many recent alerts the pipeline-activity panel reads trace entries
    # from. Bounded so the panel cannot turn into a full-table scan.
    pipeline_activity_sample_size: int = Field(default=200, gt=0)

    # PLAN §4.1 — APScheduler. Every job persists what it computes.
    scheduler_enabled: bool = True
    correlation_refresh_seconds: int = Field(default=120, gt=0)

    # A playbook whose alert_type and severity_threshold match an incoming
    # alert executes automatically. D27 governs the comparison: `unknown` sits
    # outside the severity order and satisfies no threshold, ever.
    playbook_autotrigger_enabled: bool = True

    # ------------------------------------------------------------------
    # Phase 6 — the eval. PLAN §7 / E5 / E6.
    # ------------------------------------------------------------------
    # PLAN E6 — capped. An uncapped run over the 1,800-row partition is
    # hundreds of live provider calls and near-certain rate limiting. 80 gives
    # every one of the six classes a real share while staying inside a free
    # tier. The LightGBM tier is ALSO scored on the full partition, because it
    # costs nothing and it is the only sample on which the accuracy-ceiling
    # guards can conclude.
    eval_sample_size: int = Field(default=300, ge=6)
    # PLAN E5 — threaded through sampling and shuffling. Residual
    # non-determinism (provider temperature and server-side variance) is
    # disclosed in the run notice rather than pretended away.
    eval_seed: int = 20260904
    # Sequential pacing between LLM-tier calls. Groq's free tier for the
    # classify model is ~30 RPM; 2s keeps an 80-row run inside it without
    # relying on key rotation to absorb a burst.
    eval_llm_pace_seconds: float = Field(default=2.0, ge=0)
    eval_score_full_partition: bool = True

    # ------------------------------------------------------------------
    # Phase 4a — live staged-attack injection. PLAN D23 / §4.4a.
    # ------------------------------------------------------------------
    # OFF BY DEFAULT, and off means the route is not mounted at all rather than
    # mounted and refusing. Replay is the load-bearing path; this is a toggle on
    # top of it and I19 says the toggle can be in either position with no effect
    # on replay, the eval or any screen.
    live_ingest_enabled: bool = False

    # PLAN §9 / §21 item 10 — a DEDICATED SERVICE TOKEN, never a user JWT. The
    # forwarder runs unattended on the target box; handing it a user's
    # credentials would put an account's full authority on a machine we are
    # deliberately attacking. Rotation is: change this value, restart, re-point
    # the forwarder. Revocation is: clear it, which also fails the feature
    # closed. Minimum length is enforced because this is the only endpoint that
    # accepts unsolicited external input (§4.4a).
    ingest_service_token: str = ""

    # This endpoint's OWN budget, separate from the global 120/min. The
    # forwarder batches, so a sane rate is a handful of POSTs a second at most;
    # anything above this is a misconfigured tail loop or someone else.
    ingest_requests_per_minute: float = Field(default=60.0, gt=0)
    ingest_burst: int = Field(default=10, gt=0)

    # Payload size cap, checked BEFORE the body is parsed. An unbounded body on
    # an unauthenticated-by-JWT route is a memory attack that costs the attacker
    # one request.
    ingest_max_body_bytes: int = Field(default=1_048_576, gt=0)
    # Per-batch event cap, checked after parsing. Bounds the work one accepted
    # request can create on the live lane.
    ingest_max_events_per_batch: int = Field(default=200, gt=0)

    # ------------------------------------------------------------------
    # Phase 5 — presence-aware notifications. PLAN §8, D11, D12.
    # ------------------------------------------------------------------
    # The master switch. OFF by default: a build with no SMTP credentials must
    # start and run normally rather than failing on a feature nobody asked for.
    # Turned ON, §8.4's fail-closed rule applies and startup refuses without
    # credentials.
    notifications_enabled: bool = False

    # PLAN §8.2. How long a connection's last frame stays evidence that someone
    # is watching. Chosen at 15 minutes, and the number follows from the
    # frozen frontend's frame cadence rather than being picked to look tidy:
    # FE-2 sends `presence` on connect and on every `visibilitychange`, and
    # nothing periodic, so a genuinely-watching analyst who never switches tabs
    # emits no frames at all. Anything near a normal reading session would
    # mark that analyst away and email them about an alert on the screen in
    # front of them. Fifteen minutes is long enough to cover an unbroken
    # reading session and short enough that a crashed tab stops suppressing
    # within one debounce window of a demo. The socket-close path, not this,
    # is the primary away signal; this is the backstop for a connection that
    # neither closes nor speaks.
    presence_stale_seconds: float = Field(default=900.0, gt=0)

    # PLAN §8.3. Which severities notify at all. `unknown` is REJECTED here,
    # not merely absent: D27 puts it outside the severity order because it
    # means classification failed, and emailing an analyst about the
    # pipeline's own failure is the fail-open this whole ordering exists to
    # prevent.
    notify_severities: list[str] = ["critical", "high"]

    # One email per user per event type per window, carrying a rollup count.
    notification_debounce_seconds: float = Field(default=300.0, gt=0)
    # Above this many alerts in one window the email is presented as a digest.
    # It is the SAME collapse the debounce already performs — one email, not N
    # — with a listing instead of a single alert's detail.
    notification_digest_threshold: int = Field(default=3, gt=0)
    # How many alerts a digest lists before it says "and N more". A digest that
    # prints 400 rows is not a digest.
    notification_digest_max_alerts: int = Field(default=10, gt=0)
    # Alerts held for a window, per key. Bounded: a wedged flusher must not
    # grow memory without limit.
    notification_pending_max: int = Field(default=200, gt=0)
    # How often the flusher drains windows whose debounce has expired. Well
    # below the debounce window, so the rollup email arrives close to when the
    # window actually ends rather than up to a full window late. Matched to the
    # metrics sampler's cadence: every tick writes a job receipt and an audit
    # row, and a faster flusher buys a tighter rollup at the cost of burying
    # human actions in the audit screen.
    notification_flush_seconds: int = Field(default=60, gt=0)

    # PLAN §8.3 retry. Bounded, exponential, and only on transient failures —
    # a permanent SMTP rejection (a 5xx: bad mailbox, blocked sender) is
    # re-sent to reproduce the same rejection and burn the same quota.
    notification_max_attempts: int = Field(default=3, gt=0)
    notification_retry_backoff_seconds: float = Field(default=2.0, gt=0)

    # Bounded hand-off from the replay loop. The dispatcher runs on its own
    # worker so an SMTP round trip can never stall the feed; a full queue drops
    # and counts, exactly like the triage queue.
    notification_queue_size: int = Field(default=500, gt=0)

    # PLAN §8.4 — SMTP. Credentials from the environment, never in code.
    smtp_host: str | None = None
    smtp_port: int = Field(default=587, gt=0, le=65535)
    smtp_username: str | None = None
    smtp_password: str | None = None
    smtp_from: str | None = None
    smtp_from_name: str = "Flare SOC"
    smtp_use_tls: bool = False  # implicit TLS on connect (port 465)
    smtp_start_tls: bool = True  # STARTTLS after connect (port 587)
    # PLAN §8.3 — THE POINT OF THE REWRITE. The prior code used blocking
    # smtplib with no timeout and hung a worker forever on a black-holed host.
    smtp_timeout_seconds: float = Field(default=15.0, gt=0)

    # Where the email's link points. No tracking pixel, no external asset —
    # one link, to the app the recipient already uses.
    dashboard_base_url: str = "http://localhost:5174"

    def model_post_init(self, __context: object) -> None:
        if "*" in self.cors_origins and self.cors_allow_credentials:
            raise ValueError(
                "cors_origins='*' with cors_allow_credentials=True is forbidden (PLAN §9)"
            )
        if self.health_cache_stale_seconds <= self.health_cache_ttl_seconds:
            raise ValueError(
                "health_cache_stale_seconds must exceed health_cache_ttl_seconds"
            )
        # PLAN D30 — the pair. A thinking level the timeout cannot absorb turns
        # every reasoning call into a timeout, which is how the previous build
        # 504'd its entire reason stage.
        if self.gemini_thinking_level == "high" and self.llm_timeout_seconds_gemini < 60:
            raise ValueError(
                "gemini_thinking_level='high' needs llm_timeout_seconds_gemini >= 60 "
                "(PLAN D30: the timeout and the thinking level are one setting in "
                "two fields)"
            )
        # PLAN D27 / Q10 — fails closed. `unknown` means the classification
        # failed; a notification on it would be the pipeline emailing about
        # itself, and a trigger list is exactly where that mistake gets made.
        allowed = {"critical", "high", "medium", "low"}
        unknown = [s for s in self.notify_severities if s not in allowed]
        if unknown:
            raise ValueError(
                f"notify_severities contains {unknown!r}; allowed values are "
                f"{sorted(allowed)} (PLAN D27: `unknown` sits outside the "
                "severity order and never triggers a notification)"
            )
        if self.notifications_enabled:
            # PLAN §8.4 — fail closed. A feature switched on without the
            # credentials it needs must refuse at startup, not discover it on
            # the first critical alert.
            missing = [
                name
                for name, value in (
                    ("smtp_host", self.smtp_host),
                    ("smtp_from", self.smtp_from),
                )
                if not value
            ]
            if missing:
                raise ValueError(
                    f"notifications_enabled=True requires {', '.join(missing)} "
                    "(PLAN §8.4: the feature fails closed without credentials)"
                )
            if bool(self.smtp_username) != bool(self.smtp_password):
                raise ValueError(
                    "smtp_username and smtp_password must be set together "
                    "(PLAN §8.4)"
                )
            if self.smtp_use_tls and self.smtp_start_tls:
                raise ValueError(
                    "smtp_use_tls (implicit TLS, port 465) and smtp_start_tls "
                    "(STARTTLS, port 587) are mutually exclusive"
                )
        if self.live_ingest_enabled:
            # PLAN §4.4a / §9 — fails closed, the same rule notifications
            # follow. A live ingest route mounted without a service token is an
            # unauthenticated write endpoint on the one path that accepts
            # unsolicited external input, and it must refuse at startup rather
            # than be discovered by whoever finds it first.
            if len(self.ingest_service_token) < 32:
                raise ValueError(
                    "live_ingest_enabled=True requires ingest_service_token of at "
                    "least 32 characters (PLAN §4.4a: the only externally-fed "
                    "endpoint fails closed without its own credential, and it is "
                    "never a user JWT)"
                )
        if self.stats_bucket_seconds > self.stats_window_minutes * 60:
            raise ValueError(
                "stats_bucket_seconds cannot exceed the whole stats window"
            )
        # A whole-graph budget shorter than a single provider call cannot ever
        # let that call finish, so the stage would be dead on arrival.
        longest_call = max(self.llm_timeout_seconds_groq, self.llm_timeout_seconds_gemini)
        if self.graph_budget_seconds < longest_call:
            raise ValueError(
                f"graph_budget_seconds ({self.graph_budget_seconds}) is below the "
                f"longest provider timeout ({longest_call}); no LLM stage could "
                "ever complete"
            )


@lru_cache
def get_settings() -> Settings:
    return Settings()
