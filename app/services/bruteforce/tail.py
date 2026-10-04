from __future__ import annotations

import os
import threading
import time
from collections.abc import Callable
from pathlib import Path


class LogTailer:
    """Follow a log file across rotation. Malformed lines are the callback's problem."""

    def __init__(self, path: Path, on_line: Callable[[str], None], poll: float = 1.0) -> None:
        self.path = path
        self.on_line = on_line
        self.poll = poll
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        self._thread = threading.Thread(target=self._run, name="port-warden-auth-log", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=5)

    def _run(self) -> None:
        while not self._stop.is_set():
            if not self.path.exists():
                self._stop.wait(self.poll)
                continue
            try:
                with self.path.open("r", encoding="utf-8", errors="replace") as handle:
                    inode = self.path.stat().st_ino
                    handle.seek(0, os.SEEK_END)
                    while not self._stop.is_set():
                        line = handle.readline()
                        if not line:
                            try:
                                if not self.path.exists() or self.path.stat().st_ino != inode:
                                    break
                            except OSError:
                                break
                            self._stop.wait(self.poll)
                            continue
                        try:
                            self.on_line(line.rstrip("\n"))
                        except Exception:
                            continue
            except OSError:
                self._stop.wait(self.poll)
                continue
