"""Replay control (S3). Phase 1 ships the no-op store; Phase 3 adds the
per-(aud, jti) first-seen-session store."""


class NoopNonceStore:
    def check(self, audience: str | None, jti: str, session_id: str | None) -> bool:
        return True
