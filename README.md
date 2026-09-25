# Brevo email 2FA test

A local, dependency-free browser app that sends a six-digit one-time code through Brevo SMTP and verifies it. It is intended to test SMTP setup and code delivery, not to act as a production login system.

## Set up

1. Copy `.env.example` to `.env`.
2. Fill in your **SMTP login** and the **SMTP key** you already generated. The SMTP login may differ from your Brevo account email. Use an address configured for your Brevo account as `MAIL_FROM`, and set `TEST_RECIPIENT` to an inbox you can access.
3. Keep `.env` private. It is ignored by Git. On a shared machine, run `chmod 600 .env`.
4. Run `python3 app.py`, then open the printed `http://127.0.0.1:8000/` address.
5. Click **Send test code**, check the recipient inbox, and enter the code on the page.

The app binds to localhost and sends only to the recipient in `.env`. The key stays server-side. Codes expire after five minutes, allow five attempts, and work once. There is a 30-second send cooldown shared across browser sessions. Codes and sessions are cleared when the app stops.

The example config uses port 465 with implicit TLS because ports 587 and 2525 timed out on this machine. The app also supports 587 and 2525 with STARTTLS through `BREVO_SMTP_PORT`; its fallback is 587 if the variable is omitted. `BREVO_SMTP_HOST` is set to Brevo's relay host, `smtp-relay.brevo.com`.

## Test without sending mail

Run `python3 -m unittest -v` in this folder. The tests use a fake email sender and never contact Brevo.

## Troubleshooting

- **SMTP authentication failed (535):** Check that `BREVO_SMTP_LOGIN` is the SMTP login shown in Brevo's SMTP settings, and `BREVO_SMTP_KEY` is an SMTP key rather than an API key.
- **SMTP 525:** Brevo blocked the SMTP connection's IP address. In Brevo, go to **Settings > Security > Authorized IPs** and authorize the blocked IP shown in the Unauthorized IP addresses list.
- **Message rejected:** Confirm `MAIL_FROM` is configured for sending and your Brevo transactional SMTP account is active.
- **Connection error:** Check outbound access to the configured SMTP port. Port 465 worked from this machine; ports 587 and 2525 timed out here.
- **No message in inbox:** Check spam and Brevo's transactional email logs. SMTP acceptance confirms submission, not inbox delivery.

Brevo references: [SMTP relay settings](https://help.brevo.com/hc/en-us/articles/7924908994450-Send-transactional-emails-using-Brevo-SMTP), [SMTP key management](https://help.brevo.com/hc/en-us/articles/7959631848850-Create-and-manage-your-SMTP-keys), [SMTP integration guide](https://developers.brevo.com/docs/smtp-integration).
