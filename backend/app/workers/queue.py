"""Bounded queues.

PLAN §4.1: bounded, drop-newest with a counter, QueueFullError surfacing as an
honest 503 `rate_limited`. An unbounded queue turns backpressure into memory
growth and then into a crash, which reads as a hang rather than a limit.

Drop-NEWEST rather than drop-oldest: alerts already queued are further through
the pipeline, and discarding them to make room wastes work already done. Every
drop is counted and exposed, never silent (PLAN T13).
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Generic, TypeVar

T = TypeVar("T")

TRIAGE_QUEUE_SIZE = 1000
ENRICH_QUEUE_SIZE = 500


class QueueFullError(RuntimeError):
    """The queue is at capacity. Surfaces as 503 `rate_limited`."""

    def __init__(self, name: str, maxsize: int) -> None:
        super().__init__(f"{name} queue is full ({maxsize})")
        self.name = name
        self.maxsize = maxsize


@dataclass(frozen=True)
class QueueStats:
    name: str
    maxsize: int
    depth: int
    accepted: int
    dropped: int


class BoundedQueue(Generic[T]):
    def __init__(self, name: str, maxsize: int) -> None:
        self.name = name
        self.maxsize = maxsize
        self._queue: asyncio.Queue[T] = asyncio.Queue(maxsize=maxsize)
        self._accepted = 0
        self._dropped = 0

    def put_nowait(self, item: T) -> None:
        """Accept or raise. Never blocks, never grows past maxsize."""
        try:
            self._queue.put_nowait(item)
        except asyncio.QueueFull as exc:
            self._dropped += 1
            raise QueueFullError(self.name, self.maxsize) from exc
        self._accepted += 1

    async def get(self) -> T:
        return await self._queue.get()

    def get_nowait(self) -> T:
        return self._queue.get_nowait()

    def release(self) -> None:
        """Give the slot back after the item has been processed.

        `put_nowait` reserves a slot and this returns it, so `depth` is the
        number of items IN FLIGHT. Without it the queue only ever fills: nothing
        consumes it, `qsize()` climbs to `maxsize`, and from that point every
        further item is dropped. That is the shape of the bug this method
        exists to prevent — a feed that silently stops after exactly `maxsize`
        alerts, which on a long rehearsal reads as the stream having died.
        """
        try:
            self._queue.get_nowait()
        except asyncio.QueueEmpty:
            return
        self._queue.task_done()

    def task_done(self) -> None:
        self._queue.task_done()

    def qsize(self) -> int:
        return self._queue.qsize()

    @property
    def dropped(self) -> int:
        return self._dropped

    @property
    def accepted(self) -> int:
        return self._accepted

    def stats(self) -> QueueStats:
        return QueueStats(
            name=self.name,
            maxsize=self.maxsize,
            depth=self._queue.qsize(),
            accepted=self._accepted,
            dropped=self._dropped,
        )
