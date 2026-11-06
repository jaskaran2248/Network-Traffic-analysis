"""Running traffic statistics."""

import time
from collections import Counter, deque
from typing import List, Optional, Tuple

from .parser import PacketRecord


class TrafficStats:
    """Aggregates totals, protocol mix, top talkers and a per-second history."""

    HISTORY_SECONDS = 60

    def __init__(self):
        self.reset()

    def reset(self):
        self.total_packets = 0
        self.total_bytes = 0
        self.protocols: Counter = Counter()
        self.protocol_bytes: Counter = Counter()
        self.talkers: Counter = Counter()
        self.start_time: Optional[float] = None
        self._window: deque = deque()          # (arrival_time, length) for rate calc
        self._pps_history: deque = deque(maxlen=self.HISTORY_SECONDS)
        self._bps_history: deque = deque(maxlen=self.HISTORY_SECONDS)
        self._bucket_second = int(time.time())
        self._bucket_packets = 0
        self._bucket_bytes = 0

    def add(self, rec: PacketRecord, now: Optional[float] = None):
        now = now if now is not None else time.time()
        if self.start_time is None:
            self.start_time = now
        self.total_packets += 1
        self.total_bytes += rec.length
        self.protocols[rec.protocol] += 1
        self.protocol_bytes[rec.protocol] += rec.length
        if rec.src and rec.src != "-":
            self.talkers[rec.src] += rec.length
        self._window.append((now, rec.length))
        self._roll(now)
        self._bucket_packets += 1
        self._bucket_bytes += rec.length

    def _roll(self, now: float):
        """Close finished one-second buckets so the history stays continuous."""
        sec = int(now)
        while self._bucket_second < sec:
            self._pps_history.append(self._bucket_packets)
            self._bps_history.append(self._bucket_bytes)
            self._bucket_packets = 0
            self._bucket_bytes = 0
            self._bucket_second += 1

    def tick(self, now: Optional[float] = None):
        """Call periodically (even with no traffic) to advance the history."""
        self._roll(now if now is not None else time.time())

    def current_rate(self, now: Optional[float] = None) -> Tuple[float, float]:
        """(packets/sec, bytes/sec) over the last second."""
        now = now if now is not None else time.time()
        while self._window and now - self._window[0][0] > 1.0:
            self._window.popleft()
        return float(len(self._window)), float(sum(l for _, l in self._window))

    def pps_history(self) -> List[int]:
        data = list(self._pps_history)
        return [0] * (self.HISTORY_SECONDS - len(data)) + data

    def top_talkers(self, n: int = 5):
        return self.talkers.most_common(n)

    def elapsed(self) -> float:
        return 0.0 if self.start_time is None else time.time() - self.start_time


def human_bytes(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} GB"
