"""Multi-binary session management for headless IDA analysis.

Each session represents an opened binary with its own IDA database.
Only one database can be active at a time in idalib; switching
sessions closes the current DB and reopens the target.
"""

import uuid
import logging
from pathlib import Path
from typing import Optional
from dataclasses import dataclass, field
from datetime import datetime

logger = logging.getLogger(__name__)


@dataclass
class Session:
    """Represents an open IDA database session."""

    session_id: str
    input_path: Path
    created_at: datetime = field(default_factory=datetime.now)
    is_analyzing: bool = False

    def to_dict(self) -> dict:
        return {
            "session_id": self.session_id,
            "input_path": str(self.input_path),
            "filename": self.input_path.name,
            "created_at": self.created_at.isoformat(),
            "is_analyzing": self.is_analyzing,
        }


class SessionManager:
    """Manages multiple IDA database sessions via idalib.

    Only one database can be active at a time. Switching involves
    closing the current DB and reopening the target (IDB files
    persist analysis results across switches).
    """

    def __init__(self):
        self._sessions: dict[str, Session] = {}
        self._active_id: Optional[str] = None

    def open_binary(
        self,
        path: str | Path,
        auto_analysis: bool = True,
        session_id: str | None = None,
    ) -> Session:
        """Open a binary file and create a new session.

        If the file is already tracked, switches to it instead.
        """
        path = Path(path).resolve()

        if not path.exists():
            raise FileNotFoundError(f"File not found: {path}")

        # Reuse existing session for same file
        for sid, session in self._sessions.items():
            if session.input_path.resolve() == path:
                logger.info("Binary already tracked in session %s, switching", sid)
                self._activate(sid)
                return session

        if session_id is None:
            session_id = str(uuid.uuid4())[:8]
        elif session_id in self._sessions:
            raise ValueError(f"Session ID already in use: {session_id}")

        import idapro
        import ida_auto

        # Close current DB before opening new one
        if self._active_id is not None:
            logger.debug("Closing active DB before opening %s", path.name)
            idapro.close_database()
            self._active_id = None

        logger.info("Opening database: %s (session: %s)", path.name, session_id)
        rc = idapro.open_database(str(path), run_auto_analysis=auto_analysis)
        if rc:
            raise RuntimeError(
                f"Failed to open database: {path} (error code: {rc})"
            )

        session = Session(
            session_id=session_id,
            input_path=path,
            is_analyzing=auto_analysis,
        )
        self._sessions[session_id] = session
        self._active_id = session_id

        if auto_analysis:
            logger.info("Waiting for auto-analysis to complete...")
            ida_auto.auto_wait()
            session.is_analyzing = False
            logger.info("Auto-analysis completed for %s", path.name)

        return session

    def close_session(self, session_id: str) -> bool:
        """Close a session. Returns True if found and closed."""
        if session_id not in self._sessions:
            return False

        session = self._sessions[session_id]
        logger.info("Closing session %s (%s)", session_id, session.input_path.name)

        if self._active_id == session_id:
            import idapro

            idapro.close_database()
            self._active_id = None

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

        if self._active_id is not None:
            idapro.close_database()

        rc = idapro.open_database(str(session.input_path), run_auto_analysis=False)
        if rc:
            self._active_id = None
            raise RuntimeError(
                f"Failed to reopen database: {session.input_path} (error: {rc})"
            )
        self._active_id = session_id
        logger.info("Activated session %s (%s)", session_id, session.input_path.name)

    def list_sessions(self) -> list[dict]:
        """List all sessions with active status."""
        return [
            {**s.to_dict(), "is_active": sid == self._active_id}
            for sid, s in self._sessions.items()
        ]

    def get_current(self) -> Optional[Session]:
        """Get the currently active session."""
        if self._active_id is None:
            return None
        return self._sessions.get(self._active_id)

    def close_all(self):
        """Close all sessions and databases."""
        if self._active_id is not None:
            import idapro

            idapro.close_database()
            self._active_id = None
        self._sessions.clear()
        logger.info("All sessions closed")


# Global singleton
_manager: Optional[SessionManager] = None


def get_manager() -> SessionManager:
    global _manager
    if _manager is None:
        _manager = SessionManager()
    return _manager
