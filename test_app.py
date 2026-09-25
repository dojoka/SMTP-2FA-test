import unittest
from unittest.mock import patch

from app import Config, safe_smtp_error, send_brevo_email


class FakeSMTP:
    def __init__(self):
        self.calls = []

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return None

    def ehlo(self):
        self.calls.append("ehlo")

    def starttls(self, **kwargs):
        self.calls.append("starttls")

    def login(self, user, password):
        self.calls.append(("login", user, password))

    def send_message(self, message):
        self.calls.append(("send", message))


class SMTPTransportTests(unittest.TestCase):
    def config(self, port):
        return Config("smtp-relay.brevo.com", "smtp-user@example.com", "secret", "sender@example.com", "test@example.com", port, 8000)

    @patch("app.smtplib.SMTP")
    def test_starttls_before_auth_and_fixed_recipient(self, smtp_class):
        fake = FakeSMTP()
        smtp_class.return_value = fake
        send_brevo_email(self.config(587), "123456")
        self.assertEqual(fake.calls[:3], ["ehlo", "starttls", "ehlo"])
        self.assertEqual(fake.calls[3], ("login", "smtp-user@example.com", "secret"))
        self.assertEqual(fake.calls[4][1]["To"], "test@example.com")
        self.assertIn("123456", fake.calls[4][1].get_content())
        smtp_class.assert_called_once_with("smtp-relay.brevo.com", 587, timeout=15)

    @patch("app.smtplib.SMTP_SSL")
    def test_port_465_uses_implicit_tls(self, smtp_class):
        fake = FakeSMTP()
        smtp_class.return_value = fake
        send_brevo_email(self.config(465), "123456")
        self.assertEqual(fake.calls[0], ("login", "smtp-user@example.com", "secret"))
        self.assertEqual(fake.calls[1][0], "send")
        self.assertEqual(smtp_class.call_args.args, ("smtp-relay.brevo.com", 465))

    def test_unauthorized_ip_has_actionable_error(self):
        import smtplib

        message = safe_smtp_error(smtplib.SMTPAuthenticationError(525, b"5.7.1 Unauthorized IP address"))
        self.assertIn("Authorized IPs", message)
        self.assertNotIn("key", message)


if __name__ == "__main__":
    unittest.main()
