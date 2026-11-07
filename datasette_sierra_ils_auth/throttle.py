"""In-memory failed sign-in counter: a cap per username and per address."""

import time
from collections import defaultdict, deque


class Throttle:
    def __init__(self, limit: int = 5, window_s: int = 900, clock=time.monotonic):
        self.limit = limit
        self.window_s = window_s
        self.clock = clock
        self._failures = defaultdict(deque)

    def _count(self, key) -> int:
        q = self._failures.get(key)
        if not q:
            return 0
        cutoff = self.clock() - self.window_s
        while q and q[0] <= cutoff:
            q.popleft()
        if not q:
            del self._failures[key]
            return 0
        return len(q)

    def blocked(self, username: str, addr: str) -> bool:
        return (
            self._count(("u", username.casefold())) >= self.limit
            or self._count(("a", addr)) >= self.limit
        )

    def record_failure(self, username: str, addr: str) -> None:
        now = self.clock()
        self._failures[("u", username.casefold())].append(now)
        self._failures[("a", addr)].append(now)
