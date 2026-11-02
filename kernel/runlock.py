"""Single-writer run lock (DESIGN §10, Gate 3 review #1, Gate 3 fix re-review #1).

One run at a time per database. A run takes the lock before ``recover()`` and
holds it until its final audit row is written. Another run, in this process or
another, is refused at once with ``RunLocked``; nothing waits, so a run started
from inside a run (re-entry) cannot deadlock.

The lock must name the database the kernel writes, not the connection or the
file name used to reach it:
- **A file database** is locked by its resolved path. Within a process, a
  registry of held paths; across processes, an exclusive transaction on a side
  file, ``<database>.runlock``, which the operating system releases if the holding
  process dies, so a crash never leaves a stale lock. A file with more than one
  hard link has more than one path, so it is refused (``UnlockableDatabase``).
- **An in-memory database** may be shared between connections (shared cache), so
  its lock is a row in the database itself, which every such connection sees. A
  crash cannot leave it stale: the memory goes with the process.
- **An attached database** could hold the kernel's tables under another name, so a
  connection with any database attached besides ``main`` and ``temp`` is refused.
"""

import os
import sqlite3
import threading
from collections.abc import Iterator
from contextlib import closing, contextmanager

_guard = threading.Lock()
_held: set[str | int] = set()


class RunLocked(Exception):
    """Another run holds this database's run lock."""


class UnlockableDatabase(Exception):
    """The run lock cannot identify the database behind this connection."""


def _main_file(db: sqlite3.Connection) -> str:
    """The main database's resolved file path, or "" for an in-memory database.
    Refuses connections with other databases attached."""
    main = ""
    for _, name, file in db.execute("PRAGMA database_list").fetchall():
        if name == "main":
            main = str(file or "")
        elif name != "temp":
            raise UnlockableDatabase(f"database {name!r} is attached; the kernel needs main only")
    if not main:
        return ""
    if os.stat(main).st_nlink > 1:
        raise UnlockableDatabase(f"{main} has more than one hard link")
    return os.path.normcase(os.path.realpath(main))


@contextmanager
def _row_lock(db: sqlite3.Connection) -> Iterator[None]:
    """The in-memory lock: a row every connection to this database sees."""
    opened = not db.in_transaction
    try:
        db.execute("CREATE TABLE IF NOT EXISTS run_lock (id INTEGER PRIMARY KEY CHECK (id = 1))")
        db.execute("INSERT INTO run_lock (id) VALUES (1)")
    except (sqlite3.IntegrityError, sqlite3.OperationalError) as exc:
        if opened:  # undo only the transaction this attempt opened
            db.rollback()
        raise RunLocked("another connection holds this database's run lock") from exc
    db.commit()
    try:
        yield
    finally:
        # The run has committed its final audit row; this commits only the release.
        db.execute("DELETE FROM run_lock")
        db.commit()


@contextmanager
def _file_lock(path: str) -> Iterator[None]:
    with closing(sqlite3.connect(path + ".runlock", timeout=0, isolation_level=None)) as lock:
        try:
            lock.execute("BEGIN EXCLUSIVE")
        except sqlite3.OperationalError as exc:
            raise RunLocked("another process holds this database's run lock") from exc
        yield


@contextmanager
def run_lock(db: sqlite3.Connection) -> Iterator[None]:
    path = _main_file(db)
    key: str | int = path or id(db)
    with _guard:
        if key in _held:
            raise RunLocked("another run holds this database's run lock")
        _held.add(key)
    try:
        with _file_lock(path) if path else _row_lock(db):
            yield
    finally:
        with _guard:
            _held.discard(key)
