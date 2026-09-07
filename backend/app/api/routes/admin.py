from typing import Annotated, Any

from fastapi import APIRouter, Depends, Path, Query, Request, status
from sqlalchemy import select

from app.api.deps import CurrentUser, SessionDep, require_role
from app.api.envelope import enveloped_response
from app.api.errors import AppError
from app.api.routes.auth import user_payload
from app.store.models import JobRun, User, as_utc
from app.workers.scheduler import JOBS, run_job

router = APIRouter(prefix="/admin", tags=["admin"])


@router.get("/users", dependencies=[Depends(require_role("admin"))])
async def list_users(request: Request, session: SessionDep) -> Any:
    """Admin-only.

    PLAN §9 / I8: the prior codebase's own suite asserted that a viewer *could*
    list users. tests/integration/test_rbac.py asserts the opposite.
    """
    rows = (await session.execute(select(User).order_by(User.id))).scalars().all()
    return enveloped_response({"users": [user_payload(u) for u in rows]}, request)


def job_to_dict(row: JobRun) -> dict[str, Any]:
    return {
        "id": row.id,
        "job": row.job,
        "status": row.status,
        "trigger": row.trigger,
        "duration_ms": row.duration_ms,
        "result": row.result,
        "error": row.error,
        "started_at": as_utc(row.started_at).isoformat(),
    }


@router.get("/jobs", dependencies=[Depends(require_role("admin"))])
async def list_jobs(
    request: Request,
    session: SessionDep,
    limit: Annotated[int, Query(ge=1, le=200)] = 25,
) -> Any:
    """Job receipts. PLAN T14 — what each run actually computed.

    This is how "the scheduler is running" becomes a checkable claim: every run
    left a row naming the job, the duration and the counts it wrote, and a run
    that raised kept its exception text.
    """
    rows = list(
        (
            await session.execute(
                select(JobRun).order_by(JobRun.started_at.desc(), JobRun.id.desc()).limit(limit)
            )
        )
        .scalars()
        .all()
    )
    return enveloped_response(
        {"jobs": [job_to_dict(row) for row in rows], "known_jobs": sorted(JOBS)},
        request,
    )


@router.post("/jobs/{job}/run", dependencies=[Depends(require_role("admin"))])
async def trigger_job(
    job: Annotated[str, Path(min_length=1, max_length=48)],
    request: Request,
    user: CurrentUser,
) -> Any:
    """Run a scheduled job now. PLAN §4.1 — job triggers are audited.

    A manual trigger carries the operator's id into the audit row; a scheduled
    run does not, which is what distinguishes "somebody asked for this" from
    "the timer fired".
    """
    if job not in JOBS:
        raise AppError(
            "not_found",
            f"Unknown job {job!r}. Known jobs: {', '.join(sorted(JOBS))}.",
            status.HTTP_404_NOT_FOUND,
        )
    record = await run_job(job, trigger="manual", actor_id=user.id)
    return enveloped_response(job_to_dict(record), request)
