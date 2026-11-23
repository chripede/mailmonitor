#!/usr/bin/env python3
"""
mailflow_monitor.py (JMAP-version, til Stalwart)

- Leverer testmail direkte til MX (port 25) for MON_TO (ingen relay/login).
- Checker via JMAP (RFC 8620/8621) at mailen dukker op i modtagerkontoen. Der søges ikke i
  tekstindekset; de seneste mails hentes og matches på emne/Message-ID i scriptet.
- Sletter testmailen igen, og rydder gamle testmails op (kan slås fra).
- Kalder WEBHOOK_OK ved succes og WEBHOOK_FAIL ved fejl (POST JSON).
- Logger til stdout (INFO level).

Exit codes:
    0 = success (mail fundet)
    1 = config error (mangler/ugyldige env-variabler)
    2 = smtp send error
    3 = jmap connection/auth/search error
    4 = mail not found within timeout
    5 = MX lookup failed
   99 = uventet fejl

Miljøvariabler:
  Påkrævet:
    MON_TO                  modtageradresse (kontoen JMAP logger ind på)
    MON_JMAP_URL            fx https://mail.example.dk/.well-known/jmap
    MON_JMAP_USER + MON_JMAP_PASS   (Basic auth)  ELLER  MON_JMAP_TOKEN (Bearer)
  Valgfri:
    MON_FROM                afsenderadresse (default probe@external-test.local)
    MON_MX_HOST             tving en bestemt MX i stedet for DNS-opslag
    MON_SMTP_REQUIRE_TLS    1 = fejl hvis STARTTLS ikke kan forhandles med gyldigt cert (default 0)
    Relay-tilstand (aktiveres ved at sætte MON_SMTP_RELAY_HOST; så springes MX-opslag over og mailen
    indleveres hos relayet, som leverer videre til din MX):
    MON_SMTP_RELAY_HOST     fx smtp-relay.eksempel.com
    MON_SMTP_RELAY_PORT     default 587
    MON_SMTP_RELAY_SECURITY starttls (default for 587) | ssl (default for 465) | none (kun uden login)
    MON_SMTP_RELAY_USER, MON_SMTP_RELAY_PASS   login til relayet (verificeret TLS er påkrævet)
    MON_FROM                SKAL sættes i relay-tilstand: en adresse på et domæne, relayet har verificeret,
                            og som IKKE er det domæne Stalwart modtager for
    Bemærk: relays omskriver ofte Message-ID. Scriptet matcher derfor også på emnet, som bevares.
    MON_JMAP_MAILBOX        mappe at søge i: rolle ("inbox", "junk", "trash") eller præcist navn
                            ("Junk Mail"). Default: hele kontoen
    MON_JMAP_RECENT_LIMIT   hvor mange af de seneste mails der tjekkes pr. poll (default 30)
    MON_DEBUG               1 = log pr. poll hvad scriptet ser (scan vs. emne-filter), og de 5 seneste
                            mails i kontoen hvis testmailen ikke findes (default 1). Sæt til 0 i drift
    MON_JMAP_DELETE         1 = slet testmail efter fund + ryd gamle op (default 1)
    MON_JMAP_CLEANUP_AGE    sekunder før en gammel testmail ryddes op (default 3600)
    WEBHOOK_OK, WEBHOOK_FAIL
    SMTP_TIMEOUT (30), MON_CHECK_TIMEOUT (90), MON_POLL_INTERVAL (5), MON_JMAP_TIMEOUT (15)
"""

import os
import sys
import time
import uuid
import logging
import socket
import smtplib
import ssl
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage

try:
    import dns.resolver
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util import Retry
except Exception as e:
    print("Missing dependency:", e)
    print("Install: pip install dnspython requests")
    sys.exit(1)


# -------- Exit codes --------
EXIT_OK = 0
EXIT_CONFIG = 1
EXIT_SMTP = 2
EXIT_JMAP = 3
EXIT_NOT_FOUND = 4
EXIT_MX = 5
EXIT_UNEXPECTED = 99


# -------- Config from env --------
def env_bool(name, default):
    v = os.getenv(name)
    if v is None:
        return default
    return v.strip().lower() in ("1", "true", "yes", "on")


TO_ADDR = os.getenv("MON_TO")
FROM_ADDR = os.getenv("MON_FROM", "probe@external-test.local")
MX_OVERRIDE = os.getenv("MON_MX_HOST")
SMTP_REQUIRE_TLS = env_bool("MON_SMTP_REQUIRE_TLS", False)

RELAY_HOST = os.getenv("MON_SMTP_RELAY_HOST", "").strip()
RELAY_PORT = int(os.getenv("MON_SMTP_RELAY_PORT", "587"))
RELAY_SECURITY = os.getenv("MON_SMTP_RELAY_SECURITY", "ssl" if RELAY_PORT == 465 else "starttls").strip().lower()
RELAY_USER = os.getenv("MON_SMTP_RELAY_USER")
RELAY_PASS = os.getenv("MON_SMTP_RELAY_PASS")

JMAP_URL = os.getenv("MON_JMAP_URL")
JMAP_USER = os.getenv("MON_JMAP_USER")
JMAP_PASS = os.getenv("MON_JMAP_PASS")
JMAP_TOKEN = os.getenv("MON_JMAP_TOKEN")
JMAP_MAILBOX = os.getenv("MON_JMAP_MAILBOX", "").strip()
JMAP_DELETE = env_bool("MON_JMAP_DELETE", True)
CLEANUP_AGE = int(os.getenv("MON_JMAP_CLEANUP_AGE", "3600"))
RECENT_LIMIT = int(os.getenv("MON_JMAP_RECENT_LIMIT", "30"))
DEBUG = env_bool("MON_DEBUG", True)  # log seneste mails i kontoen hvis testmailen ikke findes

WEBHOOK_OK = os.getenv("WEBHOOK_OK")
WEBHOOK_FAIL = os.getenv("WEBHOOK_FAIL")

SMTP_TIMEOUT = int(os.getenv("SMTP_TIMEOUT", "30"))
CHECK_TIMEOUT = int(os.getenv("MON_CHECK_TIMEOUT", "300" if RELAY_HOST else "90"))  # relay: længere default
POLL_INTERVAL = int(os.getenv("MON_POLL_INTERVAL", "5"))
JMAP_TIMEOUT = int(os.getenv("MON_JMAP_TIMEOUT", "15"))

CAP_CORE = "urn:ietf:params:jmap:core"
CAP_MAIL = "urn:ietf:params:jmap:mail"
SUBJECT_PREFIX = "monitor-check"
MAX_POLL_ERRORS = 3  # antal fejl i træk under polling før vi giver op

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("mailflow_monitor")


class MonitorError(Exception):
    def __init__(self, code, reason, detail=""):
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.code = code
        self.reason = reason
        self.detail = detail


# -------- Helpers --------
def check_config():
    problems = []
    if not TO_ADDR or "@" not in TO_ADDR:
        problems.append("MON_TO mangler eller er ikke en gyldig adresse")
    if not JMAP_URL:
        problems.append("MON_JMAP_URL mangler")
    if not JMAP_TOKEN and not (JMAP_USER and JMAP_PASS):
        problems.append("MON_JMAP_TOKEN eller MON_JMAP_USER + MON_JMAP_PASS mangler")
    if RELAY_HOST:
        if not os.getenv("MON_FROM"):
            problems.append("MON_FROM skal sættes eksplicit i relay-tilstand (afsender på et domæne, relayet har verificeret)")
        if RELAY_SECURITY not in ("starttls", "ssl", "none"):
            problems.append("MON_SMTP_RELAY_SECURITY skal være starttls, ssl eller none")
        if bool(RELAY_USER) != bool(RELAY_PASS):
            problems.append("MON_SMTP_RELAY_USER og MON_SMTP_RELAY_PASS skal sættes sammen")
        if RELAY_USER and RELAY_SECURITY == "none":
            problems.append("Login uden TLS afvises: brug starttls eller ssl sammen med MON_SMTP_RELAY_USER")
    return problems


def call_webhook(url, payload):
    if not url:
        log.info("Ingen webhook sat for denne event (payload: %s)", payload)
        return
    try:
        s = requests.Session()
        retries = Retry(
            total=3,
            backoff_factor=0.5,
            status_forcelist=(502, 503, 504),
            allowed_methods=frozenset({"POST"}),
        )
        s.mount("http://", HTTPAdapter(max_retries=retries))
        s.mount("https://", HTTPAdapter(max_retries=retries))
        r = s.post(url, json=payload, timeout=10)
        log.info("Webhook POST %s -> status %s", url, r.status_code)
    except Exception as e:
        log.error("Webhook-kald til %s fejlede: %s", url, e)


def resolve_mx(domain):
    if MX_OVERRIDE:
        log.info("Bruger MX fra MON_MX_HOST: %s", MX_OVERRIDE)
        return MX_OVERRIDE
    try:
        answers = dns.resolver.resolve(domain, "MX")
    except dns.resolver.NoAnswer:
        log.warning("Ingen MX-records for %s, bruger domænet selv (implicit MX)", domain)
        return domain
    except Exception as e:
        raise MonitorError(EXIT_MX, "mx_lookup_failed", f"{domain}: {e}")

    records = sorted((r.preference, str(r.exchange).rstrip(".")) for r in answers)
    host = records[0][1]
    if not host:
        raise MonitorError(EXIT_MX, "mx_lookup_failed", f"{domain} har null-MX")
    log.info("Resolved MX for %s -> %s (pref %s)", domain, host, records[0][0])
    return host


# -------- SMTP --------
class _TlsError(Exception):
    """STARTTLS kunne ikke forhandles i den aktuelle tilstand."""


def _smtp_attempt(mx_host, msg, tls_mode):
    """tls_mode: 'verify' (gyldigt cert), 'noverify' (opportunistisk TLS) eller 'none'."""
    log.info("Forbinder til %s:25 (timeout=%s, tls=%s)", mx_host, SMTP_TIMEOUT, tls_mode)
    with smtplib.SMTP(mx_host, 25, timeout=SMTP_TIMEOUT) as smtp:
        smtp.ehlo_or_helo_if_needed()
        if tls_mode != "none":
            if not smtp.has_extn("starttls"):
                if SMTP_REQUIRE_TLS:
                    raise _TlsError("STARTTLS ikke tilbudt")
                log.warning("STARTTLS ikke tilbudt af %s, sender ukrypteret", mx_host)
            else:
                ctx = ssl.create_default_context()
                if tls_mode == "noverify":
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                try:
                    smtp.starttls(context=ctx)
                    smtp.ehlo()
                    log.info("STARTTLS forhandlet med %s", mx_host)
                except (ssl.SSLError, smtplib.SMTPException) as e:
                    raise _TlsError(f"STARTTLS fejlede: {e}") from e
        smtp.send_message(msg)


def build_message(message_id, token):
    msg = EmailMessage()
    msg["From"] = FROM_ADDR
    msg["To"] = TO_ADDR
    msg["Subject"] = f"{SUBJECT_PREFIX} {message_id}"
    msg["Message-ID"] = f"<{message_id}@monitor.check>"
    msg["X-Mon-Token"] = token
    msg.set_content(f"Monitor token: {token}\nHost: {socket.gethostname()}")
    return msg


def send_via_relay(message_id, token):
    """Indlever mailen hos et SMTP-relay (login + verificeret TLS). Relayet leverer videre til MX."""
    msg = build_message(message_id, token)
    log.info("Indleverer via relay %s:%d (sikkerhed=%s, login=%s)",
             RELAY_HOST, RELAY_PORT, RELAY_SECURITY, "ja" if RELAY_USER else "nej")
    ctx = ssl.create_default_context()
    try:
        if RELAY_SECURITY == "ssl":
            smtp = smtplib.SMTP_SSL(RELAY_HOST, RELAY_PORT, timeout=SMTP_TIMEOUT, context=ctx)
        else:
            smtp = smtplib.SMTP(RELAY_HOST, RELAY_PORT, timeout=SMTP_TIMEOUT)
        with smtp:
            smtp.ehlo()
            if RELAY_SECURITY == "starttls":
                smtp.starttls(context=ctx)
                smtp.ehlo()
            if RELAY_USER:
                smtp.login(RELAY_USER, RELAY_PASS)
            smtp.send_message(msg)
    except smtplib.SMTPAuthenticationError as e:
        raise MonitorError(EXIT_SMTP, "relay_auth_failed", str(e))
    except (smtplib.SMTPSenderRefused, smtplib.SMTPRecipientsRefused, smtplib.SMTPDataError) as e:
        raise MonitorError(EXIT_SMTP, "relay_rejected", str(e))
    except ssl.SSLError as e:
        raise MonitorError(EXIT_SMTP, "relay_tls_failed", str(e))
    except (smtplib.SMTPException, OSError) as e:
        raise MonitorError(EXIT_SMTP, "relay_send_failed", str(e))
    log.info("Relay har accepteret mailen til videre levering")


def send_direct(mx_host, message_id, token):
    msg = build_message(message_id, token)

    modes = ["verify"] if SMTP_REQUIRE_TLS else ["verify", "noverify", "none"]
    last_tls_error = None
    for mode in modes:
        try:
            _smtp_attempt(mx_host, msg, mode)
        except _TlsError as e:
            last_tls_error = e
            log.warning("%s (tls=%s)", e, mode)
            continue
        except (smtplib.SMTPException, OSError) as e:
            raise MonitorError(EXIT_SMTP, "smtp_send_failed", str(e))
        if mode != "verify":
            log.warning("Mail leveret, men uden verificeret TLS (tls=%s) - tjek certifikatet på %s", mode, mx_host)
        log.info("SMTP send completed (direkte til MX).")
        return
    raise MonitorError(EXIT_SMTP, "smtp_tls_failed", str(last_tls_error))


# -------- JMAP --------
class Jmap:
    def __init__(self):
        self.http = requests.Session()
        if JMAP_TOKEN:
            self.http.headers["Authorization"] = f"Bearer {JMAP_TOKEN}"
        else:
            self.http.auth = (JMAP_USER, JMAP_PASS)
        self.api = None
        self.account = None

    def connect(self):
        try:
            r = self.http.get(JMAP_URL, timeout=JMAP_TIMEOUT)
            if r.status_code in (401, 403):
                raise MonitorError(EXIT_JMAP, "jmap_auth_failed", f"HTTP {r.status_code}")
            r.raise_for_status()
            session = r.json()
            if CAP_MAIL not in session.get("capabilities", {}):
                raise MonitorError(EXIT_JMAP, "jmap_no_mail_capability", "serveren annoncerer ikke urn:ietf:params:jmap:mail")
            self.api = session["apiUrl"]
            self.account = session["primaryAccounts"][CAP_MAIL]
        except MonitorError:
            raise
        except (requests.RequestException, KeyError, ValueError) as e:
            raise MonitorError(EXIT_JMAP, "jmap_session_failed", str(e))
        log.info("JMAP-session OK (account %s)", self.account)

    def call(self, method_calls):
        """Returnerer {callId: [name, args, callId]}. Kaster requests/ValueError ved transportfejl."""
        body = {"using": [CAP_CORE, CAP_MAIL], "methodCalls": method_calls}
        r = self.http.post(self.api, json=body, timeout=JMAP_TIMEOUT)
        r.raise_for_status()
        return {resp[2]: resp for resp in r.json()["methodResponses"]}

    def mailbox_id(self, ref):
        """Finder mailbox-id ud fra rolle (inbox, junk, trash ...) eller ellers præcist navn."""
        try:
            # 1) rolle
            resp = self.call([["Mailbox/query", {"accountId": self.account, "filter": {"role": ref.lower()}}, "m"]])
            name, res, _ = resp["m"]
            if name != "error" and res.get("ids"):
                return res["ids"][0]

            # 2) navn (JMAP's name-filter er 'contains', så vi finder præcis match via Mailbox/get)
            resp = self.call([
                ["Mailbox/query", {"accountId": self.account, "filter": {"name": ref}}, "m"],
                ["Mailbox/get", {
                    "accountId": self.account,
                    "#ids": {"resultOf": "m", "name": "Mailbox/query", "path": "/ids"},
                    "properties": ["name"],
                }, "g"],
            ])
            name, res, _ = resp["g"]
            if name != "error":
                for mb in res.get("list", []):
                    if mb.get("name", "").lower() == ref.lower():
                        return mb["id"]
        except (requests.RequestException, KeyError, ValueError) as e:
            raise MonitorError(EXIT_JMAP, "jmap_mailbox_lookup_failed", str(e))
        raise MonitorError(EXIT_JMAP, "jmap_mailbox_not_found", f"hverken rolle eller navn matcher '{ref}'")

    def recent_emails(self, mailbox_id=None, limit=30, before=None):
        """Seneste mails sorteret efter modtagelsestidspunkt. Bruger ikke tekstindekset (FTS)."""
        flt = {}
        if mailbox_id:
            flt["inMailbox"] = mailbox_id
        if before:
            flt["before"] = before
        args = {
            "accountId": self.account,
            "sort": [{"property": "receivedAt", "isAscending": False}],
            "limit": limit,
        }
        if flt:
            args["filter"] = flt
        resp = self.call([
            ["Email/query", args, "q"],
            ["Email/get", {
                "accountId": self.account,
                "#ids": {"resultOf": "q", "name": "Email/query", "path": "/ids"},
                "properties": ["subject", "messageId", "receivedAt"],
            }, "g"],
        ])
        for cid in ("q", "g"):
            if resp[cid][0] == "error":
                raise MonitorError(EXIT_JMAP, "jmap_query_error", str(resp[cid][1]))
        return resp["g"][1].get("list", [])

    def destroy(self, ids):
        """Returnerer (ok, svar)."""
        resp = self.call([["Email/set", {"accountId": self.account, "destroy": list(ids)}, "d"]])
        name, res, _ = resp["d"]
        if name == "error":
            return False, res
        return not res.get("notDestroyed"), res


def dump_recent(jmap, n=5):
    """Diagnostik: log de seneste mails i kontoen, så man kan se om testmailen er landet, og hvor."""
    try:
        resp = jmap.call([
            ["Email/query", {
                "accountId": jmap.account,
                "sort": [{"property": "receivedAt", "isAscending": False}],
                "limit": n,
            }, "rq"],
            ["Email/get", {
                "accountId": jmap.account,
                "#ids": {"resultOf": "rq", "name": "Email/query", "path": "/ids"},
                "properties": ["subject", "receivedAt", "mailboxIds"],
            }, "rg"],
            ["Mailbox/get", {"accountId": jmap.account, "properties": ["name", "role"]}, "mb"],
        ])
        if resp["rg"][0] == "error" or resp["mb"][0] == "error":
            log.warning("Diagnostik: JMAP afviste forespørgslen: %s", resp["rg"][1] if resp["rg"][0] == "error" else resp["mb"][1])
            return
        boxes = {m["id"]: (m.get("role") or m.get("name")) for m in resp["mb"][1].get("list", [])}
        emails = resp["rg"][1].get("list", [])
        if not emails:
            log.warning("Diagnostik: kontoen indeholder ingen mails. Leveres %s til en anden konto end JMAP-brugeren?", TO_ADDR)
        for e in emails:
            where = ", ".join(str(boxes.get(i, i)) for i in e.get("mailboxIds", {}))
            log.warning("Diagnostik: %s | %s | %s", e.get("receivedAt"), where, e.get("subject"))
    except Exception as ex:
        log.warning("Diagnostik fejlede: %s", ex)


def wait_for_message(jmap, message_id, mailbox_id):
    """Poller de seneste mails og matcher testmailen i Python (emne eller Message-ID).
    Sletter den bagefter hvis JMAP_DELETE."""
    wanted_mid = f"{message_id}@monitor.check"
    errors = 0
    deadline = time.monotonic() + CHECK_TIMEOUT
    log.info("Poller JMAP (timeout %ds, interval %ds)", CHECK_TIMEOUT, POLL_INTERVAL)

    while True:
        emails = None
        try:
            emails = jmap.recent_emails(mailbox_id, RECENT_LIMIT)
            errors = 0
        except (requests.RequestException, KeyError, ValueError) as e:
            errors += 1
            log.warning("JMAP-kald fejlede (%d/%d): %s", errors, MAX_POLL_ERRORS, e)
            if errors >= MAX_POLL_ERRORS:
                raise MonitorError(EXIT_JMAP, "jmap_error", str(e))

        if DEBUG and emails is not None:
            # Sammenlign de to metoder: scan af seneste mails vs. server-side emne-filter (tekstindeks)
            newest = max((e.get("receivedAt") or "" for e in emails), default="-") or "-"
            try:
                r = jmap.call([["Email/query", {
                    "accountId": jmap.account,
                    "filter": {"subject": f"{SUBJECT_PREFIX} {message_id}"},
                    "limit": 1,
                }, "f"]])
                if r["f"][0] == "error":
                    via_filter = "fejl"
                else:
                    via_filter = "ja" if r["f"][1].get("ids") else "nej"
            except Exception:
                via_filter = "fejl"
            in_scan = any(
                wanted_mid in [m.strip("<>") for m in (e.get("messageId") or [])]
                or message_id in (e.get("subject") or "")
                for e in emails
            )
            log.info("Poll: %d mails set (nyeste modtaget %s) | scan finder testmail: %s | emne-filter finder: %s",
                     len(emails), newest, "ja" if in_scan else "nej", via_filter)

        for e in emails or []:
            mids = [m.strip("<>") for m in (e.get("messageId") or [])]
            if wanted_mid in mids or message_id in (e.get("subject") or ""):
                log.info("Mail fundet via JMAP")
                if JMAP_DELETE:
                    ok, res = jmap.destroy([e["id"]])
                    if ok:
                        log.info("Testmail slettet")
                    else:
                        log.warning("Kunne ikke slette testmail: %s", res)
                return

        if time.monotonic() >= deadline:
            if DEBUG:
                dump_recent(jmap)
            raise MonitorError(EXIT_NOT_FOUND, "not_received", f"ikke fundet inden for {CHECK_TIMEOUT}s")
        time.sleep(POLL_INTERVAL)


def cleanup_old(jmap):
    """Best effort: slet gamle testmails i hele kontoen (fx mails der kom for sent til en tidligere kørsel)."""
    cutoff = (datetime.now(timezone.utc) - timedelta(seconds=CLEANUP_AGE)).strftime("%Y-%m-%dT%H:%M:%SZ")
    try:
        emails = jmap.recent_emails(None, 100, before=cutoff)
        ids = [e["id"] for e in emails if (e.get("subject") or "").startswith(SUBJECT_PREFIX)]
        if not ids:
            return
        ok, res = jmap.destroy(ids)
        if ok:
            log.info("Oprydning: %d gamle testmail(s) ældre end %ds slettet", len(ids), CLEANUP_AGE)
        else:
            log.warning("Oprydning: kunne ikke slette alle: %s", res)
    except Exception as e:
        log.warning("Oprydning fejlede (ignoreres): %s", e)


# -------- Main --------
def main():
    problems = check_config()
    if problems:
        for p in problems:
            log.error("Config error: %s", p)
        sys.exit(EXIT_CONFIG)

    message_id = uuid.uuid4().hex
    token = uuid.uuid4().hex
    payload_base = {"id": message_id, "to": TO_ADDR, "from": FROM_ADDR, "mode": "relay" if RELAY_HOST else "direct"}
    jmap = Jmap()

    try:
        # Valider JMAP først, så vi ikke sender en testmail vi ikke kan lede efter
        jmap.connect()
        mailbox_id = jmap.mailbox_id(JMAP_MAILBOX) if JMAP_MAILBOX else None

        if RELAY_HOST:
            send_via_relay(message_id, token)
        else:
            mx_host = resolve_mx(TO_ADDR.rsplit("@", 1)[1])
            send_direct(mx_host, message_id, token)
        t_sent = time.monotonic()

        wait_for_message(jmap, message_id, mailbox_id)
        delivery = round(time.monotonic() - t_sent, 1)

    except MonitorError as e:
        log.error("Fejl (%s): %s", e.reason, e.detail or e)
        call_webhook(WEBHOOK_FAIL, {**payload_base, "status": "error", "reason": e.reason, "detail": e.detail})
        sys.exit(e.code)
    except Exception as e:
        log.exception("Uventet fejl")
        call_webhook(WEBHOOK_FAIL, {**payload_base, "status": "error", "reason": "unexpected", "detail": str(e)})
        sys.exit(EXIT_UNEXPECTED)

    log.info("Finished: success (leveret på ca. %.1fs)", delivery)
    call_webhook(WEBHOOK_OK, {**payload_base, "status": "ok", "delivery_seconds": delivery})
    if JMAP_DELETE:
        cleanup_old(jmap)
    sys.exit(EXIT_OK)


if __name__ == "__main__":
    main()
