"""Single-threaded protocol time for in-memory Session unit tests only.

The real transport's deadline/prompt logic runs unchanged. No process-global
clock is replaced, and real socket/GUI tests must not use this helper.
"""
from __future__ import annotations

import heapq
import itertools
import math
from typing import Callable


class ProtocolClock:
    def __init__(self):
        self._nanoseconds = 0
        self._sequence = itertools.count()
        self._callbacks: list[tuple[int, int, Callable[[], None]]] = []

    @staticmethod
    def _duration(seconds: float) -> int:
        if not math.isfinite(seconds) or seconds < 0:
            raise ValueError('Protocol clock requires a finite nonnegative duration')
        return round(seconds * 1_000_000_000)

    def monotonic(self) -> float:
        return self._nanoseconds / 1_000_000_000

    def call_later(self, seconds: float, callback: Callable[[], None]) -> None:
        when = self._nanoseconds + self._duration(seconds)
        heapq.heappush(self._callbacks, (when, next(self._sequence), callback))

    def advance(self, seconds: float) -> None:
        end = self._nanoseconds + self._duration(seconds)
        while self._callbacks and self._callbacks[0][0] <= end:
            when, _, callback = heapq.heappop(self._callbacks)
            self._nanoseconds = when
            callback()
        self._nanoseconds = end


class ProtocolEvent:
    """Event subset used by Session; finite waits advance protocol time."""
    def __init__(self, clock: ProtocolClock):
        self.clock = clock
        self._set = False
        self._waits = 0

    def is_set(self) -> bool:
        return self._set

    def set(self) -> None:
        self._set = True

    def clear(self) -> None:
        self._set = False

    def wait(self, timeout: float | None = None) -> bool:
        if self._set:
            return True
        if timeout is None:
            raise AssertionError('In-memory transport tests must use bounded waits')
        self._waits += 1
        if self._waits > 100_000:
            raise AssertionError('Protocol wait budget exhausted; check deadline regression')
        self.clock.advance(timeout)
        return self._set
