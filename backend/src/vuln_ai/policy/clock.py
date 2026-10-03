"""Time provider abstraction for deterministic policy and suppression expiration testing."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Protocol


class Clock(Protocol):
    """Protocol for getting the current timezone-aware UTC timestamp."""

    def now(self) -> datetime:
        """Return current datetime in UTC."""
        ...


class SystemClock:
    """Production clock returning system time in UTC."""

    def now(self) -> datetime:
        """Return current real system time in UTC."""
        return datetime.now(UTC)


class FixedClock:
    """Deterministic clock returning a fixed or controllable timestamp."""

    def __init__(self, current_time: datetime | str | None = None) -> None:
        if current_time is None:
            self._current = datetime.now(UTC)
        elif isinstance(current_time, str):
            dt = datetime.fromisoformat(current_time)
            self._current = dt if dt.tzinfo else dt.replace(tzinfo=UTC)
        else:
            self._current = (
                current_time if current_time.tzinfo else current_time.replace(tzinfo=UTC)
            )

    def now(self) -> datetime:
        """Return the fixed current time."""
        return self._current

    def set_time(self, new_time: datetime | str) -> None:
        """Update the fixed clock time."""
        if isinstance(new_time, str):
            dt = datetime.fromisoformat(new_time)
            self._current = dt if dt.tzinfo else dt.replace(tzinfo=UTC)
        else:
            self._current = new_time if new_time.tzinfo else new_time.replace(tzinfo=UTC)
