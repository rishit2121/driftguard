"""Trust boundaries: SSRF-safe fetching of allowlisted sources and quarantine of instruction-like text.

Everything fetched from the web (and every README/comment in scanned repos) is untrusted EVIDENCE. It is
stored and displayed, never interpreted as instructions to an agent or tool.
"""
import ipaddress
import re
import socket
from urllib.parse import urljoin, urlparse

import httpx

from .config import ALLOWED_SOURCE_HOSTS

USER_AGENT = "DriftGuard/0.1 (+https://github.com/rishit2121/driftguard)"


class UnsafeURL(ValueError):
    pass


def check_url(url: str) -> None:
    parsed = urlparse(url)
    if parsed.scheme != "https":
        raise UnsafeURL(f"only https is allowed: {url}")
    host = (parsed.hostname or "").lower()
    if host not in ALLOWED_SOURCE_HOSTS:
        raise UnsafeURL(f"host not in source allowlist: {host}")
    for info in socket.getaddrinfo(host, parsed.port or 443, proto=socket.IPPROTO_TCP):
        ip = ipaddress.ip_address(info[4][0])
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
            raise UnsafeURL(f"{host} resolves to non-public address {ip}")


def safe_request(method: str, url: str, *, json=None, timeout: float = 20.0, max_redirects: int = 3) -> httpx.Response:
    """Fetch an allowlisted URL, re-validating every redirect hop (no redirect to private IPs/other hosts)."""
    with httpx.Client(timeout=timeout, follow_redirects=False, headers={"User-Agent": USER_AGENT}) as client:
        for _ in range(max_redirects + 1):
            check_url(url)
            resp = client.request(method, url, json=json)
            if resp.is_redirect:
                url = urljoin(url, resp.headers["location"])
                continue
            return resp
    raise UnsafeURL(f"too many redirects for {url}")


INSTRUCTION_PATTERNS = [
    r"ignore (all )?(previous|prior|above) instructions",
    r"\b(you are|act as) (an? )?(ai|assistant|agent)\b",
    r"note to (ai|llm|agents?)",
    r"\b(approve|merge) (and merge )?(every|all|this) (open )?pull requests?",
    r"\b(secret|token|api[_ ]key)s?\b.*\b(pr|pull request|description|comment)\b",
    r"<\s*/?\s*(system|assistant)\s*>",
]


def detect_instruction_like(text: str) -> list[str]:
    """Return instruction-like spans found in untrusted text (for quarantine + display only)."""
    hits = []
    for pat in INSTRUCTION_PATTERNS:
        for m in re.finditer(pat, text, flags=re.I):
            start = max(0, m.start() - 40)
            hits.append(text[start : m.end() + 40].replace("\n", " ").strip())
    return hits
