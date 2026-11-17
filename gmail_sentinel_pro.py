#!/usr/bin/env python3
"""
Gmail Sentinel Pro v3.0
A secure, modern command-line utility for sending email via Gmail SMTP.

Usage:
    python gmail_sentinel_pro.py                 # interactive menu
    python gmail_sentinel_pro.py test            # test login
    python gmail_sentinel_pro.py send -t a@b.com -s "Hi" -b "Hello"
    python gmail_sentinel_pro.py send -t a@b.com -s "Report" \
        --body-file msg.txt --attach report.pdf --yes

Credentials (optional, avoids prompts):
    GMAIL_ADDRESS, GMAIL_APP_PASSWORD   (never stored on disk by this tool)
"""

from __future__ import annotations

import argparse
import logging
import mimetypes
import os
import re
import smtplib
import socket
import ssl
import sys
import time
from dataclasses import dataclass, field
from email.message import EmailMessage
from email.utils import formatdate, make_msgid
from getpass import getpass
from pathlib import Path
from typing import Iterable, Optional

# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------

APP_NAME = "Gmail Sentinel Pro"
VERSION = "3.0"

SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 587
TIMEOUT = 20
MAX_RETRIES = 3
MAX_ATTACHMENT_MB = 25  # Gmail's limit

EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")

log = logging.getLogger("gmail_sentinel")


# --------------------------------------------------------------------------
# Terminal UI
# --------------------------------------------------------------------------

class Style:
    """ANSI styling that disables itself when output is not a terminal."""

    def __init__(self) -> None:
        enabled = sys.stdout.isatty() and "NO_COLOR" not in os.environ
        if enabled and os.name == "nt":
            os.system("")  # enable ANSI escape handling on Windows
        self.enabled = enabled

    def _wrap(self, code: str, text: str) -> str:
        return f"\033[{code}m{text}\033[0m" if self.enabled else text

    def bold(self, t: str) -> str: return self._wrap("1", t)
    def dim(self, t: str) -> str: return self._wrap("2", t)
    def red(self, t: str) -> str: return self._wrap("91", t)
    def green(self, t: str) -> str: return self._wrap("92", t)
    def yellow(self, t: str) -> str: return self._wrap("93", t)
    def cyan(self, t: str) -> str: return self._wrap("96", t)


S = Style()
WIDTH = 60


def info(msg: str) -> None: print(f"{S.cyan('ℹ')}  {msg}")
def ok(msg: str) -> None: print(f"{S.green('✔')}  {msg}")
def warn(msg: str) -> None: print(f"{S.yellow('⚠')}  {msg}")
def fail(msg: str) -> None: print(f"{S.red('✖')}  {msg}")


def rule(title: str = "") -> None:
    if title:
        line = f"─ {title} "
        print(S.dim(line + "─" * (WIDTH - len(line))))
    else:
        print(S.dim("─" * WIDTH))


def banner() -> None:
    print()
    print(S.bold(S.cyan(f"  ✉  {APP_NAME}")) + S.dim(f"  v{VERSION}"))
    print(S.dim(f"  Secure Gmail delivery · {SMTP_HOST}:{SMTP_PORT} · STARTTLS"))
    rule()


def ask(prompt: str, default: str = "") -> str:
    suffix = f" [{default}]" if default else ""
    value = input(f"{S.bold(prompt)}{suffix}: ").strip()
    return value or default


# --------------------------------------------------------------------------
# Data models
# --------------------------------------------------------------------------

@dataclass
class Credentials:
    address: str
    app_password: str = field(repr=False)  # never printed in logs/tracebacks


@dataclass
class Mail:
    to: list[str]
    subject: str
    body: str
    cc: list[str] = field(default_factory=list)
    bcc: list[str] = field(default_factory=list)
    html: bool = False
    attachments: list[Path] = field(default_factory=list)

    @property
    def recipients(self) -> list[str]:
        return [*self.to, *self.cc, *self.bcc]


class ValidationError(ValueError):
    pass


# --------------------------------------------------------------------------
# Validation helpers
# --------------------------------------------------------------------------

def is_valid_email(address: str) -> bool:
    return bool(EMAIL_RE.fullmatch(address))


def parse_addresses(raw: str | Iterable[str]) -> list[str]:
    """Accept 'a@x.com, b@y.com' (or a list) and return a validated list."""
    items = re.split(r"[,\s;]+", raw) if isinstance(raw, str) else list(raw)
    result: list[str] = []
    for item in filter(None, (i.strip() for i in items)):
        if not is_valid_email(item):
            raise ValidationError(f"Invalid email address: {item}")
        if item.lower() not in (r.lower() for r in result):
            result.append(item)
    return result


def validate_attachments(paths: Iterable[str]) -> list[Path]:
    files: list[Path] = []
    total = 0
    for p in paths:
        path = Path(p).expanduser()
        if not path.is_file():
            raise ValidationError(f"Attachment not found: {path}")
        total += path.stat().st_size
        files.append(path)
    if total > MAX_ATTACHMENT_MB * 1024 * 1024:
        raise ValidationError(f"Attachments exceed {MAX_ATTACHMENT_MB} MB.")
    return files


# --------------------------------------------------------------------------
# Message construction
# --------------------------------------------------------------------------

def build_message(sender: str, mail: Mail) -> EmailMessage:
    msg = EmailMessage()
    msg["From"] = sender
    msg["To"] = ", ".join(mail.to)
    if mail.cc:
        msg["Cc"] = ", ".join(mail.cc)
    msg["Subject"] = mail.subject
    msg["Date"] = formatdate(localtime=True)
    msg["Message-ID"] = make_msgid(domain="gmail.com")

    if mail.html:
        msg.set_content("This message requires an HTML-capable email client.")
        msg.add_alternative(mail.body, subtype="html")
    else:
        msg.set_content(mail.body)

    for path in mail.attachments:
        ctype, encoding = mimetypes.guess_type(path.name)
        if ctype is None or encoding is not None:
            ctype = "application/octet-stream"
        maintype, subtype = ctype.split("/", 1)
        msg.add_attachment(
            path.read_bytes(),
            maintype=maintype,
            subtype=subtype,
            filename=path.name,
        )
    return msg


# --------------------------------------------------------------------------
# Gmail client
# --------------------------------------------------------------------------

class GmailClient:
    """Context-managed SMTP session with TLS verification and retry logic."""

    def __init__(self, creds: Credentials) -> None:
        self.creds = creds
        self._server: Optional[smtplib.SMTP] = None

    def __enter__(self) -> "GmailClient":
        self.connect()
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def connect(self) -> None:
        context = ssl.create_default_context()  # verifies server certificate
        server = smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=TIMEOUT)
        try:
            server.ehlo()
            server.starttls(context=context)
            server.ehlo()
            server.login(self.creds.address, self.creds.app_password)
        except Exception:
            server.close()
            raise
        self._server = server

    def close(self) -> None:
        if self._server:
            try:
                self._server.quit()
            except smtplib.SMTPException:
                pass
            self._server = None

    def send(self, msg: EmailMessage, recipients: list[str]) -> None:
        if not self._server:
            raise RuntimeError("Not connected.")
        self._server.send_message(
            msg, from_addr=self.creds.address, to_addrs=recipients
        )


def with_retries(creds: Credentials, action) -> None:
    """Run action(client); retry only on transient network errors."""
    transient = (
        smtplib.SMTPServerDisconnected,
        smtplib.SMTPConnectError,
        socket.timeout,
        ConnectionError,
    )
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            with GmailClient(creds) as client:
                action(client)
            return
        except transient as exc:
            if attempt == MAX_RETRIES:
                raise
            delay = 2 ** attempt
            warn(f"Network issue ({exc.__class__.__name__}). "
                 f"Retrying in {delay}s… ({attempt}/{MAX_RETRIES})")
            time.sleep(delay)


def explain_error(exc: Exception) -> str:
    if isinstance(exc, smtplib.SMTPAuthenticationError):
        return ("Authentication failed. Use a 16-character Google App Password "
                "(2-Step Verification must be enabled), not your normal password.")
    if isinstance(exc, smtplib.SMTPRecipientsRefused):
        return "One or more recipients were rejected by Gmail."
    if isinstance(exc, smtplib.SMTPSenderRefused):
        return "The sender address was refused by Gmail."
    if isinstance(exc, smtplib.SMTPDataError):
        return "Gmail rejected the message content or size."
    if isinstance(exc, (socket.timeout, TimeoutError)):
        return "Connection timed out. Check your internet connection."
    if isinstance(exc, (socket.gaierror, ConnectionError)):
        return "Could not reach smtp.gmail.com. Check your network/firewall."
    if isinstance(exc, ssl.SSLError):
        return f"TLS/SSL error: {exc}"
    return f"{exc.__class__.__name__}: {exc}"


# --------------------------------------------------------------------------
# Credentials
# --------------------------------------------------------------------------

def get_credentials(address: Optional[str] = None) -> Optional[Credentials]:
    address = (address or os.environ.get("GMAIL_ADDRESS")
               or ask("Your Gmail")).strip()
    if not is_valid_email(address) or not address.lower().endswith(
            ("@gmail.com", "@googlemail.com")):
        fail("Please use a valid @gmail.com address.")
        return None

    password = os.environ.get("GMAIL_APP_PASSWORD") or getpass(
        "Google App Password (hidden): ")
    password = password.replace(" ", "").strip()  # Google shows it in groups
    if not password:
        fail("App Password cannot be empty.")
        return None
    return Credentials(address, password)


# --------------------------------------------------------------------------
# Actions
# --------------------------------------------------------------------------

def action_test(address: Optional[str] = None) -> int:
    rule("Connection test")
    creds = get_credentials(address)
    if not creds:
        return 1
    try:
        info("Connecting to Gmail…")
        with_retries(creds, lambda client: None)
        ok("TLS connection established.")
        ok(f"Authenticated as {creds.address}.")
        return 0
    except Exception as exc:  # noqa: BLE001
        fail(explain_error(exc))
        log.debug("Details", exc_info=True)
        return 1


def read_body_interactive() -> str:
    print(S.dim("Write your message. Type END on its own line to finish."))
    lines: list[str] = []
    while True:
        line = input()
        if line.strip() == "END":
            break
        lines.append(line)
    return "\n".join(lines)


def preview(sender: str, mail: Mail) -> None:
    rule("Preview")
    print(f"{S.bold('From    ')}: {sender}")
    print(f"{S.bold('To      ')}: {', '.join(mail.to)}")
    if mail.cc:
        print(f"{S.bold('Cc      ')}: {', '.join(mail.cc)}")
    if mail.bcc:
        print(f"{S.bold('Bcc     ')}: {len(mail.bcc)} hidden recipient(s)")
    print(f"{S.bold('Subject ')}: {mail.subject}")
    if mail.attachments:
        names = ", ".join(p.name for p in mail.attachments)
        print(f"{S.bold('Attach  ')}: {names}")
    print(f"{S.bold('Format  ')}: {'HTML' if mail.html else 'Plain text'}")
    rule()
    body = mail.body
    print(body if len(body) <= 600 else body[:600] + S.dim("\n… (truncated)"))
    rule()


def deliver(creds: Credentials, mail: Mail, assume_yes: bool) -> int:
    preview(creds.address, mail)
    if not assume_yes:
        if ask("Send this email? (y/n)", "n").lower() != "y":
            warn("Sending cancelled.")
            return 0
    try:
        msg = build_message(creds.address, mail)
        info("Sending…")
        with_retries(creds, lambda c: c.send(msg, mail.recipients))
        ok(f"Email sent to {len(mail.recipients)} recipient(s).")
        return 0
    except Exception as exc:  # noqa: BLE001
        fail(explain_error(exc))
        log.debug("Details", exc_info=True)
        return 1


def action_send_interactive() -> int:
    rule("Compose")
    creds = get_credentials()
    if not creds:
        return 1
    try:
        to = parse_addresses(ask("To (comma-separated)"))
        cc = parse_addresses(ask("Cc (optional)"))
        bcc = parse_addresses(ask("Bcc (optional)"))
        if not to:
            raise ValidationError("At least one recipient is required.")
        subject = ask("Subject")
        if not subject:
            raise ValidationError("Subject cannot be empty.")
        attach_raw = ask("Attachment paths (comma-separated, optional)")
        attachments = validate_attachments(
            [p.strip() for p in attach_raw.split(",") if p.strip()])
        html = ask("HTML message? (y/n)", "n").lower() == "y"
        body = read_body_interactive()
        if not body.strip():
            raise ValidationError("Message cannot be empty.")
    except ValidationError as exc:
        fail(str(exc))
        return 1

    mail = Mail(to, subject, body, cc, bcc, html, attachments)
    return deliver(creds, mail, assume_yes=False)


def action_send_cli(args: argparse.Namespace) -> int:
    creds = get_credentials(args.sender)
    if not creds:
        return 1
    try:
        to = parse_addresses(args.to)
        cc = parse_addresses(args.cc or [])
        bcc = parse_addresses(args.bcc or [])
        if args.body_file:
            body = (sys.stdin.read() if args.body_file == "-"
                    else Path(args.body_file).expanduser().read_text("utf-8"))
        else:
            body = args.body or ""
        if not args.subject.strip():
            raise ValidationError("Subject cannot be empty.")
        if not body.strip():
            raise ValidationError("Message cannot be empty (use -b or --body-file).")
        attachments = validate_attachments(args.attach or [])
    except (ValidationError, OSError) as exc:
        fail(str(exc))
        return 1

    mail = Mail(to, args.subject, body, cc, bcc, args.html, attachments)
    return deliver(creds, mail, assume_yes=args.yes)


# --------------------------------------------------------------------------
# Menu & entry point
# --------------------------------------------------------------------------

def interactive_menu() -> int:
    while True:
        banner()
        print(f"  {S.bold('1')}  Send email")
        print(f"  {S.bold('2')}  Test connection")
        print(f"  {S.bold('3')}  Exit\n")
        choice = ask("Select option")
        if choice == "1":
            action_send_interactive()
        elif choice == "2":
            action_test()
        elif choice == "3":
            ok("Goodbye.")
            return 0
        else:
            fail("Invalid selection.")
        input(S.dim("\nPress ENTER to continue…"))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="gmail_sentinel_pro",
        description=f"{APP_NAME} v{VERSION} — secure Gmail SMTP sender.",
    )
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="enable debug logging")
    parser.add_argument("--version", action="version",
                        version=f"{APP_NAME} {VERSION}")
    sub = parser.add_subparsers(dest="command")

    t = sub.add_parser("test", help="test SMTP authentication")
    t.add_argument("--from", dest="sender", help="Gmail address")

    s = sub.add_parser("send", help="send an email non-interactively")
    s.add_argument("--from", dest="sender", help="Gmail address")
    s.add_argument("-t", "--to", required=True, help="recipient(s), comma-separated")
    s.add_argument("--cc", help="Cc recipient(s)")
    s.add_argument("--bcc", help="Bcc recipient(s)")
    s.add_argument("-s", "--subject", required=True)
    s.add_argument("-b", "--body", help="message text")
    s.add_argument("--body-file", help="read message from file ('-' for stdin)")
    s.add_argument("--html", action="store_true", help="body is HTML")
    s.add_argument("-a", "--attach", action="append", metavar="FILE",
                   help="attach a file (repeatable)")
    s.add_argument("-y", "--yes", action="store_true",
                   help="skip the confirmation prompt")
    return parser


def main(argv: Optional[list[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="%(levelname)s: %(message)s",
    )
    if args.command == "test":
        return action_test(args.sender)
    if args.command == "send":
        return action_send_cli(args)
    return interactive_menu()


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (KeyboardInterrupt, EOFError):
        print()
        warn("Interrupted.")
        sys.exit(130)
