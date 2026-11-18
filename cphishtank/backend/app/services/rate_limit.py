from collections import defaultdict, deque
from threading import Lock
from time import monotonic


class MemoryRateLimiter:
    """Process-local sliding-window limiter; use shared storage for multi-worker deployments."""

    def __init__(self) -> None:
        self._events: dict[str, deque[float]] = defaultdict(deque)
        self._lock = Lock()

    def allow(self, keys: tuple[str, ...], limit: int, window_seconds: int) -> bool:
        now = monotonic()
        with self._lock:
            for key in keys:
                events = self._events[key]
                while events and now - events[0] >= window_seconds:
                    events.popleft()
            if any(len(self._events[key]) >= limit for key in keys):
                return False
            for key in keys:
                self._events[key].append(now)
            return True

    def reset(self) -> None:
        with self._lock:
            self._events.clear()


limiter = MemoryRateLimiter()
