#!/usr/bin/env python3
"""
mailflow_monitor.py

- Leverer testmail direkte til MX (port 25) for MON_TO (ingen relay/login).
- Checker via IMAP på MON_IMAP_* at mailen dukker op (søger Message-ID eller X-Mon-Token).
- Logger handlinger til stdout (INFO level).
- Kalder WEBHOOK_OK eller WEBHOOK_FAIL (POST JSON) ved henholdsvis succes / fejl.
- Exit codes:
    0 = success (mail fundet)
    1 = config error (mangler env)
    2 = smtp send error
    3 = imap connection/search error
    4 = mail not found within timeout
"""

import os
import sys
import time
import uuid
import logging
import socket
import smtplib
import ssl
import imaplib
from email.message import EmailMessage
from urllib3.util import Retry

try:
    import dns.resolver
    import requests
    from requests import Session
    from requests.adapters import HTTPAdapter
except Exception as e:
    print("Missing dependency:", e)
    print("Install: pip install dnspython requests")
    sys.exit(1)


# -------- Config from env --------
TO_ADDR = os.getenv("MON_TO") 
FROM_ADDR = os.getenv("MON_FROM", "probe@external-test.local")

# IMAP (where we check arrival)
IMAP_HOST = os.getenv("MON_IMAP_HOST")
IMAP_PORT = int(os.getenv("MON_IMAP_PORT", "993"))
IMAP_USER = os.getenv("MON_IMAP_USER")
IMAP_PASS = os.getenv("MON_IMAP_PASS")
IMAP_FOLDER = os.getenv("MON_IMAP_FOLDER", "INBOX")

# Webhooks
WEBHOOK_OK = os.getenv("WEBHOOK_OK")
WEBHOOK_FAIL = os.getenv("WEBHOOK_FAIL")

# Timing
SMTP_TIMEOUT = int(os.getenv("SMTP_TIMEOUT", "30"))        # socket timeout for SMTP connection
CHECK_TIMEOUT = int(os.getenv("MON_CHECK_TIMEOUT", "90"))  # seconds to wait for mail arrival
POLL_INTERVAL = int(os.getenv("MON_POLL_INTERVAL", "5"))   # seconds between IMAP polls

# Logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("mailflow_monitor")


# -------- Helpers --------
def bad_config(msg=None):
    if msg:
        log.error("Config error: %s", msg)
    else:
        log.error("Config error: missing required environment variables.")
    return 1


def call_webhook(url, payload):
    if not url:
        log.info("No webhook configured for this event (would call with payload: %s)", payload)
        return
    try:
        s = Session()
        retries = Retry(
            total=3,
            backoff_factor=0.1,
        )
        s.mount("http://", HTTPAdapter(max_retries=retries))
        s.mount("https://", HTTPAdapter(max_retries=retries))
        r = s.post(url, json=payload, timeout=10)
        log.info("Webhook POST %s -> status %s", url, r.status_code)
    except Exception as e:
        log.error("Failed to call webhook %s: %s", url, e)


def resolve_mx_for_domain(domain):
    try:
        answers = dns.resolver.resolve(domain, "MX")
        mx_records = sorted([(r.preference, str(r.exchange).rstrip(".")) for r in answers])
        mx = mx_records[0][1]
        log.info("Resolved MX for %s -> %s", domain, mx)
        return mx
    except Exception as e:
        log.error("MX lookup failed for %s: %s", domain, e)
        return None


# -------- Core logic --------
def send_direct(mx_host, message_id, token):
    """
    Send a simple test mail directly to mx_host:25 (no login).
    """
    msg = EmailMessage()
    msg["From"] = FROM_ADDR
    msg["To"] = TO_ADDR
    msg["Subject"] = f"monitor-check {message_id}"
    # use explicit Message-ID so we can search for it
    msg["Message-ID"] = f"<{message_id}@monitor.check>"
    msg["X-Mon-Token"] = token
    msg.set_content(f"Monitor token: {token}\nHost: {socket.gethostname()}")

    try:
        log.info("Connecting to %s:25 (timeout=%s)", mx_host, SMTP_TIMEOUT)
        with smtplib.SMTP(mx_host, 25, timeout=SMTP_TIMEOUT) as smtp:
            smtp.set_debuglevel(0)
            # try STARTTLS if server supports it
            try:
                smtp.ehlo_or_helo_if_needed()
                if smtp.has_extn("STARTTLS"):
                    ctx = ssl.create_default_context()
                    smtp.starttls(context=ctx)
                    smtp.ehlo()
                    log.info("STARTTLS negotiated with %s", mx_host)
                else:
                    log.info("No STARTTLS offered by %s, proceeding unencrypted", mx_host)
            except Exception as e:
                log.warning("Error during STARTTLS probe: %s -- continuing unencrypted", e)

            smtp.send_message(msg)
        log.info("SMTP send completed (direct to MX).")
        return True
    except (smtplib.SMTPException, OSError, socket.timeout) as e:
        log.error("SMTP send failed: %s", e)
        return False


def imap_search_for_message(message_id, token):
    """
    Connect to IMAP and search for the message. Return:
      True  -> found
      False -> not found within timeout
      None  -> IMAP error
    """

    def safe_select(M, folder):
        # Sørger for korrekt quoting hvis folder-navnet indeholder mellemrum, (), \ eller "
        if any(c in folder for c in (' ', '"', "'", '(', ')', '\\')):
            quoted = f'"{folder}"'
        else:
            quoted = folder
        typ, data = M.select(quoted)
        if typ != "OK":
            raise imaplib.IMAP4.error(f"SELECT {folder} failed: {data}")
        return typ, data

    try:
        log.info("Connecting to IMAP %s:%d", IMAP_HOST, IMAP_PORT)
        ctx = ssl.create_default_context()
        with imaplib.IMAP4_SSL(IMAP_HOST, IMAP_PORT, ssl_context=ctx) as M:
            M.login(IMAP_USER, IMAP_PASS)
            safe_select(M, IMAP_FOLDER)

            deadline = time.time() + CHECK_TIMEOUT
            log.info("Polling IMAP folder '%s' (timeout %ds)", IMAP_FOLDER, CHECK_TIMEOUT)

            while time.time() < deadline:
                for query in [
                    f'HEADER Message-ID "<{message_id}@monitor.check>"',
                    f'HEADER X-Mon-Token "{token}"',
                    f'SUBJECT "monitor-check {message_id}"'
                ]:
                    typ, data = M.search(None, query)
                    if typ == "OK" and data and data[0]:
                        if data[0].strip():
                            log.info("Mail fundet med query: %s", query)
                            return True
                time.sleep(POLL_INTERVAL)

            log.warning("Mail ikke fundet inden for timeout.")
            return False

    except Exception as e:
        log.error("IMAP error: %s", e)
        return None



def main():
    # basic config check
    if not (TO_ADDR and FROM_ADDR):
        sys.exit(bad_config("MON_TO and MON_FROM required"))
    if not (IMAP_HOST and IMAP_USER and IMAP_PASS):
        sys.exit(bad_config("MON_IMAP_HOST, MON_IMAP_USER, MON_IMAP_PASS required"))

    message_id = uuid.uuid4().hex
    token = uuid.uuid4().hex
    payload_base = {"id": message_id, "to": TO_ADDR, "from": FROM_ADDR}

    domain = TO_ADDR.split("@", 1)[1]
    mx_host = resolve_mx_for_domain(domain)
    if not mx_host:
        call_webhook(WEBHOOK_FAIL, {**payload_base, "status": "error", "reason": "mx_lookup_failed"})
        sys.exit(1)

    sent = send_direct(mx_host, message_id, token)
    if not sent:
        call_webhook(WEBHOOK_FAIL, {**payload_base, "status": "error", "reason": "smtp_send_failed"})
        sys.exit(2)

    # Poll IMAP for the message
    found = imap_search_for_message(message_id, token)
    if found is True:
        call_webhook(WEBHOOK_OK, {**payload_base, "status": "ok"})
        log.info("Finished: success")
        sys.exit(0)
    elif found is False:
        call_webhook(WEBHOOK_FAIL, {**payload_base, "status": "error", "reason": "not_received"})
        log.info("Finished: not received")
        sys.exit(4)
    else:
        # IMAP error
        call_webhook(WEBHOOK_FAIL, {**payload_base, "status": "error", "reason": "imap_error"})
        log.info("Finished: imap error")
        sys.exit(3)


if __name__ == "__main__":
    main()

