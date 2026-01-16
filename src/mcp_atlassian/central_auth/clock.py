"""Clock abstraction for testable time handling in central OAuth logic.

This module defines a `Clock` protocol representing callables that return the
current UNIX timestamp as ``float``.  All time-based decisions inside the
central_auth package MUST depend on an injected ``Clock`` instance rather than
calling ``time.time()`` or ``datetime.now()`` directly.

Example
-------
>>> from mcp_atlassian.central_auth.clock import default_clock
>>> now = default_clock()
>>> isinstance(now, float)
True
"""

from __future__ import annotations

import time
from typing import Protocol, runtime_checkable


@runtime_checkable
class Clock(Protocol):
    """Callable protocol returning *seconds* since the UNIX epoch."""

    def __call__(self) -> float: ...


def default_clock() -> float:
    """Default implementation that delegates to ``time.time()``.

    Returns
    -------
    float
        Seconds since the UNIX epoch.
    """
    return time.time()
