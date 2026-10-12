"""An uptime that keeps counting, for engines that report one.

Redis `INFO`, MongoDB `serverStatus` and the like reported a fixed 84231 s however long the sensor
had been up, so two scans an hour apart showed the same uptime: a decoy tell that nmap's
`mongodb-info` and `redis-info` print. A real server's uptime grows by the second.
"""

from __future__ import annotations

import time

_STARTED = time.monotonic()
BASE_UPTIME_SECONDS = 84_231  # about a day: a server that has been up a while, not just started


def uptime_seconds(base: int = BASE_UPTIME_SECONDS) -> int:
    """`base` plus the real time this process has been running."""
    return base + int(time.monotonic() - _STARTED)
