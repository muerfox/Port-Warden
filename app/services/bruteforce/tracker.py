from __future__ import annotations

import threading
from collections import deque
from datetime import datetime, timedelta


class FailureTracker:
    def __init__(self) -> None:
        self._hits: dict[str, deque[datetime]] = {}
        self._lock = threading.Lock()

    def add(self, ip: str, now: datetime, window_seconds: int) -> int:
        cutoff = now - timedelta(seconds=window_seconds)
        with self._lock:
            bucket = self._hits.setdefault(ip, deque())
            bucket.append(now)
            while bucket and bucket[0] < cutoff:
                bucket.popleft()
            return len(bucket)

    def clear(self, ip: str) -> None:
        with self._lock:
            self._hits.pop(ip, None)
