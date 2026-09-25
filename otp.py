"""Small, in-memory email OTP service for a local SMTP test."""

from __future__ import annotations

import hashlib
import hmac
import secrets
import time
from dataclasses import dataclass
from typing import Callable


CODE_LIFETIME_SECONDS = 300
SEND_COOLDOWN_SECONDS = 30
MAX_ATTEMPTS = 5


@dataclass
class Challenge:
    digest: bytes
    salt: bytes
    expires_at: float
    attempts_left: int = MAX_ATTEMPTS


class OTPService:
    def __init__(
        self,
        send_email: Callable[[str], None],
        clock: Callable[[], float] = time.monotonic,
        make_code: Callable[[], str] | None = None,
    ) -> None:
        self.send_email = send_email
        self.clock = clock
        self.make_code = make_code or (lambda: f"{secrets.randbelow(1_000_000):06d}")
        self.challenges: dict[str, Challenge] = {}
        self.last_sent_at: float | None = None

    def send_code(self, session_id: str) -> tuple[bool, str]:
        now = self.clock()
        if self.last_sent_at is not None and now - self.last_sent_at < SEND_COOLDOWN_SECONDS:
            remaining = int(SEND_COOLDOWN_SECONDS - (now - self.last_sent_at) + 0.999)
            return False, f"Wait {remaining} seconds before sending another code."

        code = self.make_code()
        if len(code) != 6 or not code.isascii() or not code.isdigit():
            raise ValueError("Code generator must return six ASCII digits")

        # A failed SMTP send leaves any existing, previously delivered code intact.
        self.send_email(code)
        salt = secrets.token_bytes(16)
        digest = hashlib.sha256(salt + code.encode("ascii")).digest()
        self.challenges[session_id] = Challenge(digest, salt, self.clock() + CODE_LIFETIME_SECONDS)
        self.last_sent_at = self.clock()
        return True, "Code sent. Check your inbox and enter it below."

    def verify_code(self, session_id: str, code: str) -> tuple[bool, str]:
        challenge = self.challenges.get(session_id)
        if challenge is None:
            return False, "Send a code first."
        if self.clock() >= challenge.expires_at:
            del self.challenges[session_id]
            return False, "Code expired. Send a new one."
        if len(code) != 6 or not code.isascii() or not code.isdigit():
            return False, "Enter the six-digit code."

        candidate = hashlib.sha256(challenge.salt + code.encode("ascii")).digest()
        if hmac.compare_digest(candidate, challenge.digest):
            del self.challenges[session_id]
            return True, "Verified. The email 2FA test passed."

        challenge.attempts_left -= 1
        if challenge.attempts_left == 0:
            del self.challenges[session_id]
            return False, "Too many attempts. Send a new code."
        return False, f"Incorrect code. {challenge.attempts_left} attempts left."

    def has_active_code(self, session_id: str) -> bool:
        challenge = self.challenges.get(session_id)
        return challenge is not None and self.clock() < challenge.expires_at
