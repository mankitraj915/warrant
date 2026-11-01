"""Single-writer run lock (DESIGN §10, Gate 3 review #1).

One run at a time per database. A run takes the lock before ``recover()`` and
holds it until its final audit row is written. Another run, in this process or
another, is refused at once with ``RunLocked``; nothing waits, so a run started
from inside a run (re-entry) cannot deadlock.

Within a process the lock is a registry of held databases (a file database by
path, an in-memory one by connection). Across processes it is an exclusive
transaction on a side file, ``<database>.runlock``, which the operating system
releases if the holding process dies, so a crash never leaves a stale lock.
"""

import sqlite3
import threading
from collections.abc import Iterator
from contextlib import closing, contextmanager

_guard = threading.Lock()
_held: set[str | int] = set()


class RunLocked(Exception):
    """Another run holds this database's run lock."""


def _path(db: sqlite3.Connection) -> str:
    """The main database's file, or "" for an in-memory database."""
    for _, name, file in db.execute("PRAGMA database_list").fetchall():
        if name == "main":
            return str(file or "")
    return ""


@contextmanager
def run_lock(db: sqlite3.Connection) -> Iterator[None]:
    path = _path(db)
    key: str | int = path or id(db)
    with _guard:
        if key in _held:
            raise RunLocked("another run holds this database's run lock")
        _held.add(key)
    try:
        if not path:
            yield
            return
        with closing(sqlite3.connect(path + ".runlock", timeout=0, isolation_level=None)) as lock:
            try:
                lock.execute("BEGIN EXCLUSIVE")
            except sqlite3.OperationalError as exc:
                raise RunLocked("another process holds this database's run lock") from exc
            yield
    finally:
        with _guard:
            _held.discard(key)
