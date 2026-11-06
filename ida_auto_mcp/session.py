"""Multi-binary session management for headless IDA analysis.

Each session represents an opened binary with its own IDA database.
Only one database can be active at a time in idalib; switching
sessions closes the current DB and reopens the target.

IDA's auto-analysis runs in bounded steps (see analysis.py): open_binary
waits for it up to analysis_wait seconds, and background_step() continues it
while the server has no request to handle. Analysis that is still pending
when a session is switched away from is saved with the database and resumes
when the session becomes active again.
"""

import re
import time
import uuid
import logging
from pathlib import Path
from typing import Optional
from dataclasses import dataclass, field
from datetime import datetime

from . import analysis, idb_files

logger = logging.getLogger(__name__)

# Background analysis that could not go on is tried again after this long
_STALLED_RETRY_SECONDS = 60.0


@dataclass
class Session:
    """Represents an open IDA database session."""

    session_id: str
    input_path: Path
    created_at: datetime = field(default_factory=datetime.now)
    # Analyze in the background while this session is active
    auto_analysis: bool = True
    # Whether IDA's analysis queues were empty when last checked
    analysis_complete: bool = False
    # When analysis last stopped with work queued that IDA would not process
    analysis_stalled_at: Optional[float] = None
    # Something the agent should know about how the database was opened
    note: Optional[str] = None

    def analysis_state(self, active: bool) -> str:
        """complete; running (in the background); paused (resumes when this
        session is active again); or off (auto_analysis is false)."""
        if self.analysis_complete:
            return "complete"
        if not self.auto_analysis:
            return "off"
        return "running" if active else "paused"

    def to_dict(self, active: bool = False) -> dict:
        state = self.analysis_state(active)
        result = {
            "session_id": self.session_id,
            "input_path": str(self.input_path),
            "filename": self.input_path.name,
            "created_at": self.created_at.isoformat(),
            "analysis": state,
            "is_analyzing": state == "running",
        }
        if self.note:
            result["note"] = self.note
        return result


@dataclass(frozen=True)
class LoadOptions:
    """IDA loader switches for a new database, e.g. for a raw firmware blob.

    IDA ignores them when the file already has a database.
    """

    processor: str = ""  # -p: processor module, e.g. "arm" or "metapc"
    file_type: str = ""  # -T: start of a loader's file type, e.g. "Binary file"
    base_address: Optional[int] = None  # -b: load address, 16-byte aligned
    entry_point: Optional[int] = None  # -i: program entry point

    def __post_init__(self):
        # Strict character sets keep a value from smuggling in other switches
        if self.processor and not re.fullmatch(
            r"[A-Za-z0-9_][A-Za-z0-9_.:+-]*", self.processor
        ):
            raise ValueError(f"Invalid processor name: {self.processor!r}")
        if self.file_type and (
            not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_ .:()+-]*", self.file_type)
            # The value is quoted, but nothing in it should read as a switch
            or re.search(r"\s-", self.file_type)
        ):
            raise ValueError(f"Invalid file type: {self.file_type!r}")
        if self.base_address is not None and (
            self.base_address < 0 or self.base_address % 16
        ):
            raise ValueError("base_address must be a non-negative multiple of 16")
        if self.entry_point is not None and self.entry_point < 0:
            raise ValueError("entry_point must not be negative")

    def __bool__(self) -> bool:
        return bool(
            self.processor
            or self.file_type
            or self.base_address is not None
            or self.entry_point is not None
        )

    def switches(self) -> str:
        """The switches as one string, the form idapro.open_database() takes."""
        parts = []
        if self.processor:
            parts.append(f"-p{self.processor}")
        if self.file_type:
            # IDA's argument splitter keeps the switch letter outside quotes
            parts.append(
                f'-T"{self.file_type}"' if " " in self.file_type else f"-T{self.file_type}"
            )
        if self.base_address is not None:
            parts.append(f"-b{self.base_address // 16:X}")  # in 16-byte paragraphs
        if self.entry_point is not None:
            parts.append(f"-i{self.entry_point:X}")
        return " ".join(parts)


class SessionManager:
    """Manages multiple IDA database sessions via idalib.

    Only one database can be active at a time. Switching involves
    closing the current DB and reopening the target (IDB files
    persist analysis results across switches).
    """

    def __init__(self):
        self._sessions: dict[str, Session] = {}
        self._active_id: Optional[str] = None
        # Bumped whenever a database is opened or closed, so that state
        # holding IDA objects (run_script's variables) can be dropped
        self.generation = 0
        # Bumped whenever analysis may have changed the open database, so
        # that results derived from it (pseudocode, strings) are refreshed
        self.analysis_epoch = 0
        # Seconds open_binary waits for analysis before it returns
        self.analysis_wait = 30.0

    def open_binary(
        self,
        path: str | Path,
        auto_analysis: bool = True,
        session_id: str | None = None,
        options: Optional[LoadOptions] = None,
        wait_seconds: Optional[float] = None,
    ) -> Session:
        """Open a binary file and create a new session.

        If the file is already tracked, switches to it instead. With
        auto_analysis, waits up to wait_seconds (default: analysis_wait) for
        IDA's analysis; the rest runs in background_step(). The flag also
        applies to a tracked file, as the latest request for it.
        """
        path = Path(path).resolve()
        wait = self.analysis_wait if wait_seconds is None else wait_seconds

        if not path.exists():
            raise FileNotFoundError(f"File not found: {path}")

        # Reuse existing session for same file
        for sid, session in self._sessions.items():
            if session.input_path.resolve() == path:
                logger.info("Binary already tracked in session %s, switching", sid)
                self._activate(sid)
                session.auto_analysis = auto_analysis
                if auto_analysis and wait > 0:
                    self.advance_analysis(wait)
                return session

        if session_id is None:
            session_id = str(uuid.uuid4())[:8]
        elif session_id in self._sessions:
            raise ValueError(f"Session ID already in use: {session_id}")

        import idapro

        # Check before closing the current DB, so a refusal keeps it open
        note = self._check_database_files(path)
        self._close_active()

        logger.info("Opening database: %s (session: %s)", path.name, session_id)
        args = options.switches() if options else None
        # Never let idalib analyze here: it would block until the whole
        # analysis is done, which can take hours
        rc = idapro.open_database(str(path), run_auto_analysis=False, args=args or None)
        self.generation += 1
        if rc:
            raise RuntimeError(
                f"Failed to open database: {path} (error code: {rc})"
            )

        session = Session(
            session_id=session_id,
            input_path=path,
            auto_analysis=auto_analysis,
            analysis_complete=analysis.is_complete(),
            note=note,
        )
        self._sessions[session_id] = session
        self._active_id = session_id

        if auto_analysis and wait > 0:
            self.advance_analysis(wait)
        return session

    def advance_analysis(self, seconds: float) -> bool:
        """Advance the active database's analysis for about `seconds`.

        Returns True once nothing is left to process.
        """
        session = self.get_current()
        if session is None:
            raise RuntimeError("No active session. Use open_binary() to open a file first.")
        if analysis.is_complete():
            session.analysis_complete = True
            return True
        # Bumped first: a step may change the database even if the call is
        # interrupted before it returns
        self.analysis_epoch += 1
        session.analysis_complete = False
        finished = analysis.advance(seconds)
        if not finished:
            session.analysis_stalled_at = None
        elif analysis.is_complete():
            session.analysis_complete = True
            session.analysis_stalled_at = None
            logger.info("Analysis of %s finished", session.input_path.name)
        else:
            if session.analysis_stalled_at is None:
                logger.warning(
                    "IDA does not process the analysis left for %s",
                    session.input_path.name,
                )
            session.analysis_stalled_at = time.monotonic()
        return finished

    def background_step(self) -> bool:
        """One slice of background analysis; returns whether more remains.

        The server calls this whenever no request is waiting. It works on
        the active session only, and only if that has auto_analysis. Tool
        calls that queue more analysis (defining code, for example) make it
        resume. Analysis that IDA would not continue is retried once a minute.
        """
        session = self.get_current()
        if session is None or not session.auto_analysis:
            return False
        if analysis.is_complete():
            session.analysis_complete = True
            return False
        stalled_at = session.analysis_stalled_at
        if stalled_at is not None and time.monotonic() - stalled_at < _STALLED_RETRY_SECONDS:
            return False
        return not self.advance_analysis(analysis.SLICE_SECONDS)

    def close_session(self, session_id: str) -> bool:
        """Close a session. Returns True if found and closed."""
        if session_id not in self._sessions:
            return False

        session = self._sessions[session_id]
        logger.info("Closing session %s (%s)", session_id, session.input_path.name)

        if self._active_id == session_id:
            self._close_active()

        del self._sessions[session_id]
        return True

    def switch_session(self, session_id: str) -> Session:
        """Switch to a different session."""
        if session_id not in self._sessions:
            raise ValueError(f"Session not found: {session_id}")
        if self._active_id == session_id:
            return self._sessions[session_id]

        self._activate(session_id)
        return self._sessions[session_id]

    def _activate(self, session_id: str):
        """Activate a session's database in the idalib process."""
        if self._active_id == session_id:
            return

        import idapro

        session = self._sessions[session_id]
        note = self._check_database_files(session.input_path)
        self._close_active()

        rc = idapro.open_database(str(session.input_path), run_auto_analysis=False)
        self.generation += 1
        if rc:
            raise RuntimeError(
                f"Failed to reopen database: {session.input_path} (error: {rc})"
            )
        self._active_id = session_id
        # Analysis left pending was saved with the database and resumes
        session.analysis_complete = analysis.is_complete()
        if note:
            session.note = note
        logger.info("Activated session %s (%s)", session_id, session.input_path.name)

    def _close_active(self):
        """Close (and save) the active database, if any."""
        if self._active_id is not None:
            import idapro

            idapro.close_database()
            self._active_id = None
            self.generation += 1

    def _check_database_files(self, path: Path) -> Optional[str]:
        """Refuse a database that another IDA has open, and copy what a crash
        left behind before IDA discards it. Returns a note for the agent."""
        files = idb_files.probe(path)
        if files.state == "in_use":
            raise RuntimeError(
                f"The database of {path.name} is open in another IDA instance "
                f"({files.idb.name} is in use). Close it there, then try again."
            )
        if files.state == "unknown":
            logger.warning("Cannot inspect the database of %s: %s", path, files.detail)
        if files.state != "crashed":
            return None
        if files.idb.is_file():
            backup = idb_files.back_up_unpacked(files)
            logger.warning("Copied crash leftovers of %s to %s", files.idb, backup)
            return (
                "IDA did not close this database last time. It reopened the last "
                "saved copy; the files left behind, which may hold later changes, "
                f"were copied to {backup}."
            )
        return (
            "IDA did not close this database last time. It reopened the files "
            "left behind, which may lack the last changes."
        )

    def list_sessions(self) -> list[dict]:
        """List all sessions with active status."""
        return [
            {**s.to_dict(active=sid == self._active_id), "is_active": sid == self._active_id}
            for sid, s in self._sessions.items()
        ]

    def get_current(self) -> Optional[Session]:
        """Get the currently active session."""
        if self._active_id is None:
            return None
        return self._sessions.get(self._active_id)

    def close_all(self):
        """Close all sessions and databases."""
        self._close_active()
        self._sessions.clear()
        logger.info("All sessions closed")


# Global singleton
_manager: Optional[SessionManager] = None


def get_manager() -> SessionManager:
    global _manager
    if _manager is None:
        _manager = SessionManager()
    return _manager
