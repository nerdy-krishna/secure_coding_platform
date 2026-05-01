"""V02.3.4 — optimistic-locking primitives.

Used by repos that mutate rows with a `version` column. The repo
writes a conditional UPDATE matching the caller-supplied
`expected_version`; if `rowcount == 0` the row was modified by
another transaction in the meantime and we raise
`OptimisticLockError(current_version=...)`. Routers translate this
to HTTP 409 with the new version in the body so the frontend can
refetch + retry.
"""

from __future__ import annotations


class OptimisticLockError(Exception):
    """Raised when a versioned UPDATE finds the row was modified concurrently.

    Attributes:
        current_version: the row's current version after the failed update,
            so the client can refetch + retry without an extra round-trip.
    """

    def __init__(self, current_version: int) -> None:
        super().__init__(
            f"Row was modified concurrently; current version is {current_version}."
        )
        self.current_version = current_version
