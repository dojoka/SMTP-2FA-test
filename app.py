"""Local browser test for email OTP delivery through Brevo SMTP."""

from __future__ import annotations

import html
import os
import re
import secrets
import smtplib
import ssl
import time
from dataclasses import dataclass
from email.message import EmailMessage
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from otp import OTPService


HERE = Path(__file__).resolve().parent
SESSION_LIFETIME_SECONDS = 3600
EMAIL_PATTERN = re.compile(r"^[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+$")


def load_env_file(path: Path) -> None:
    """Read simple KEY=value lines, without overwriting exported variables."""
    if not path.exists():
        return
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        if not re.fullmatch(r"[A-Z][A-Z0-9_]*", key):
            continue
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        os.environ.setdefault(key, value)


@dataclass(frozen=True)
class Config:
    host: str
    login: str
    key: str
    sender: str
    recipient: str
    port: int
    app_port: int

    @classmethod
    def from_env(cls) -> "Config":
        try:
            port = int(os.getenv("BREVO_SMTP_PORT", "587"))
            app_port = int(os.getenv("APP_PORT", "8000"))
        except ValueError as exc:
            raise ValueError("BREVO_SMTP_PORT and APP_PORT must be integers") from exc
        if port not in (465, 587, 2525):
            raise ValueError("BREVO_SMTP_PORT must be 465, 587, or 2525")
        if not 1 <= app_port <= 65535:
            raise ValueError("APP_PORT must be between 1 and 65535")
        host = os.getenv("BREVO_SMTP_HOST", "smtp-relay.brevo.com").strip()
        if host != "smtp-relay.brevo.com":
            raise ValueError("BREVO_SMTP_HOST must be smtp-relay.brevo.com")
        return cls(
            host=host,
            login=os.getenv("BREVO_SMTP_LOGIN", "").strip(),
            key=os.getenv("BREVO_SMTP_KEY", "").strip(),
            sender=os.getenv("MAIL_FROM", "").strip(),
            recipient=os.getenv("TEST_RECIPIENT", "").strip(),
            port=port,
            app_port=app_port,
        )

    def missing_or_invalid(self) -> list[str]:
        problems = []
        if not self.login:
            problems.append("BREVO_SMTP_LOGIN")
        if not self.key:
            problems.append("BREVO_SMTP_KEY")
        if not EMAIL_PATTERN.fullmatch(self.sender):
            problems.append("MAIL_FROM")
        if not EMAIL_PATTERN.fullmatch(self.recipient):
            problems.append("TEST_RECIPIENT")
        return problems


def send_brevo_email(config: Config, code: str) -> None:
    message = EmailMessage()
    message["From"] = config.sender
    message["To"] = config.recipient
    message["Subject"] = "Your email 2FA test code"
    message.set_content(
        f"Your test verification code is {code}.\n\n"
        "It expires in 5 minutes and can be used once.\n"
        "If you did not request this test, you can ignore this message.\n"
    )
    context = ssl.create_default_context()
    if config.port == 465:
        with smtplib.SMTP_SSL(config.host, config.port, timeout=15, context=context) as smtp:
            smtp.login(config.login, config.key)
            smtp.send_message(message)
    else:
        with smtplib.SMTP(config.host, config.port, timeout=15) as smtp:
            smtp.ehlo()
            smtp.starttls(context=context)
            smtp.ehlo()
            smtp.login(config.login, config.key)
            smtp.send_message(message)


def safe_smtp_error(exc: Exception) -> str:
    if isinstance(exc, smtplib.SMTPAuthenticationError):
        if exc.smtp_code == 525:
            return (
                "Brevo blocked this machine's IP address (SMTP 525). "
                "In Brevo, open Settings > Security > Authorized IPs and authorize the blocked IP."
            )
        return f"SMTP authentication failed ({exc.smtp_code}). Check the SMTP login and key."
    if isinstance(exc, smtplib.SMTPResponseException):
        return f"Brevo rejected the message (SMTP {exc.smtp_code}). Check the sender and account status."
    if isinstance(exc, (OSError, smtplib.SMTPException)):
        return "Could not send through Brevo. Check the network, port, and SMTP settings."
    return "Could not send the code. Check the server terminal for the error type."


@dataclass
class BrowserSession:
    csrf: str
    last_seen: float
    flash: str = ""
    flash_ok: bool = False


def make_handler(config: Config, otp: OTPService):
    sessions: dict[str, BrowserSession] = {}

    class Handler(BaseHTTPRequestHandler):
        def _cookie_session(self) -> tuple[str | None, BrowserSession | None]:
            jar = SimpleCookie()
            try:
                jar.load(self.headers.get("Cookie", ""))
            except Exception:
                return None, None
            morsel = jar.get("brevo_test_session")
            if morsel is None:
                return None, None
            sid = morsel.value
            session = sessions.get(sid)
            if session is None or time.monotonic() - session.last_seen >= SESSION_LIFETIME_SECONDS:
                sessions.pop(sid, None)
                otp.challenges.pop(sid, None)
                return None, None
            session.last_seen = time.monotonic()
            return sid, session

        def _send_html(self, body: str, cookie: str | None = None, status: HTTPStatus = HTTPStatus.OK) -> None:
            encoded = body.encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(encoded)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'")
            if cookie:
                self.send_header("Set-Cookie", f"brevo_test_session={cookie}; HttpOnly; SameSite=Strict; Path=/")
            self.end_headers()
            self.wfile.write(encoded)

        def do_GET(self) -> None:
            if urlsplit(self.path).path != "/":
                self.send_error(HTTPStatus.NOT_FOUND)
                return
            sid, session = self._cookie_session()
            new_cookie = None
            if session is None:
                sid = secrets.token_urlsafe(32)
                session = BrowserSession(secrets.token_urlsafe(32), time.monotonic())
                sessions[sid] = session
                new_cookie = sid
            assert sid is not None

            problems = config.missing_or_invalid()
            ready = not problems
            flash = session.flash
            flash_ok = session.flash_ok
            session.flash = ""
            recipient = html.escape(config.recipient or "Not configured")
            sender = html.escape(config.sender or "Not configured")
            status_html = ""
            if flash:
                tone = "success" if flash_ok else "error"
                status_html = f'<div class="notice {tone}" role="status">{html.escape(flash)}</div>'
            missing_html = ""
            if problems:
                missing_html = (
                    '<div class="notice error" role="status">Set these values in .env: '
                    + html.escape(", ".join(problems)) + "</div>"
                )
            pending = otp.has_active_code(sid)
            code_hint = "A code is awaiting verification." if pending else "No active code. Send one to begin."
            disabled = "" if ready else " disabled"
            csrf = html.escape(session.csrf, quote=True)
            body = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Brevo email 2FA test</title>
<style>
:root {{ color-scheme: light; font-family: system-ui, sans-serif; background: #f5f7fa; color: #17202a; }}
* {{ box-sizing: border-box; }} body {{ margin: 0; padding: 32px 16px; }}
main {{ max-width: 600px; margin: auto; }} h1 {{ margin-bottom: 8px; font-size: 2rem; }}
p {{ line-height: 1.5; }} .muted {{ color: #526173; }}
.card {{ background: white; border: 1px solid #d8e0e8; border-radius: 14px; padding: 24px; margin-top: 20px; box-shadow: 0 5px 18px #15283d0a; }}
.step {{ color: #315ac9; font-size: .8rem; font-weight: 750; text-transform: uppercase; letter-spacing: .07em; }}
label {{ display: block; font-weight: 650; margin: 18px 0 8px; }}
input {{ width: 100%; font: inherit; padding: 12px; border: 1px solid #aab6c4; border-radius: 8px; letter-spacing: .2em; }}
button {{ margin-top: 18px; border: 0; border-radius: 8px; background: #315ac9; color: white; font: inherit; font-weight: 650; padding: 12px 18px; cursor: pointer; }}
button:disabled {{ opacity: .5; cursor: not-allowed; }} .notice {{ border-radius: 8px; padding: 12px 14px; margin-top: 20px; }}
.notice.success {{ background: #e6f7ee; color: #145c36; }} .notice.error {{ background: #fff0ed; color: #8e261d; }}
.details {{ display: grid; grid-template-columns: 100px 1fr; gap: 8px; overflow-wrap: anywhere; }}
.details dt {{ color: #526173; }} .details dd {{ margin: 0; }}
</style></head><body><main>
<h1>Brevo email 2FA test</h1>
<p class="muted">Send a six-digit code through Brevo SMTP, then verify that it arrived and works once.</p>
{status_html}{missing_html}
<section class="card"><div class="step">Step 1 · Send</div><h2>Send a code</h2>
<dl class="details"><dt>SMTP</dt><dd>{html.escape(config.host)}:{config.port}</dd>
<dt>From</dt><dd>{sender}</dd><dt>To</dt><dd>{recipient}</dd></dl>
<form action="/send" method="post"><input type="hidden" name="csrf" value="{csrf}">
<button type="submit"{disabled}>Send test code</button></form></section>
<section class="card"><div class="step">Step 2 · Verify</div><h2>Enter the code</h2>
<p class="muted">{html.escape(code_hint)} Codes expire after 5 minutes. You have 5 attempts.</p>
<form action="/verify" method="post"><input type="hidden" name="csrf" value="{csrf}">
<label for="code">Six-digit code</label><input id="code" name="code" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9]{{6}}" maxlength="6" required>
<button type="submit">Verify code</button></form></section>
<p class="muted">This local test holds codes in memory. Restarting the app clears them.</p>
</main></body></html>"""
            self._send_html(body, new_cookie)

        def do_POST(self) -> None:
            path = urlsplit(self.path).path
            if path not in ("/send", "/verify"):
                self.send_error(HTTPStatus.NOT_FOUND)
                return
            sid, session = self._cookie_session()
            if session is None or sid is None:
                self.send_error(HTTPStatus.FORBIDDEN, "Open the test page first")
                return
            if self.headers.get("Content-Type", "").split(";", 1)[0] != "application/x-www-form-urlencoded":
                self.send_error(HTTPStatus.UNSUPPORTED_MEDIA_TYPE)
                return
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                self.send_error(HTTPStatus.BAD_REQUEST)
                return
            if not 0 < length <= 4096:
                self.send_error(HTTPStatus.REQUEST_ENTITY_TOO_LARGE)
                return
            form = parse_qs(self.rfile.read(length).decode("utf-8", errors="replace"), keep_blank_values=True)
            if form.get("csrf") != [session.csrf]:
                self.send_error(HTTPStatus.FORBIDDEN, "Invalid form token")
                return

            if path == "/send":
                problems = config.missing_or_invalid()
                if problems:
                    session.flash = "SMTP settings are incomplete. Fill in .env and restart the app."
                    session.flash_ok = False
                else:
                    try:
                        session.flash_ok, session.flash = otp.send_code(sid)
                    except Exception as exc:
                        # Never expose the SMTP key, server reply, or email content in the page or logs.
                        session.flash_ok = False
                        session.flash = safe_smtp_error(exc)
                        print(f"SMTP send failed: {type(exc).__name__}")
            else:
                code = form.get("code", [""])[0]
                session.flash_ok, session.flash = otp.verify_code(sid, code)
            self.send_response(HTTPStatus.SEE_OTHER)
            self.send_header("Location", "/")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, format: str, *args: object) -> None:
            # Avoid logging paths, headers, and submitted codes.
            return

    return Handler


def main() -> None:
    load_env_file(HERE / ".env")
    try:
        config = Config.from_env()
    except ValueError as exc:
        raise SystemExit(f"Configuration error: {exc}") from exc
    otp = OTPService(lambda code: send_brevo_email(config, code))
    server = HTTPServer(("127.0.0.1", config.app_port), make_handler(config, otp))
    print(f"Open http://127.0.0.1:{config.app_port}/")
    print("Press Ctrl+C to stop. SMTP credentials are never printed.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
