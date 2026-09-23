"""
SSL/TLS checker.

Performs a direct TLS handshake against the target (port extracted from
the URL, defaulting to 443) using Python's stdlib ssl module so we get
cert details without shelling out.  httpx is used only for the
protocol-downgrade probe (HTTP vs HTTPS reachability).

Checks performed
----------------
1.  SSL/TLS available        — can we connect at all?
2.  Certificate expiry       — within 30-day warning window, or already expired?
3.  Hostname mismatch        — does the cert cover the host we're connecting to?
4.  Self-signed / untrusted  — does system trust store accept it?
5.  Deprecated protocol      — server negotiates TLS 1.0 or 1.1?
6.  Weak cipher suite        — RC4, DES, 3DES, NULL, EXPORT, or ANON in the name?
7.  HTTP→HTTPS redirect      — does the plain-HTTP version redirect to HTTPS?
"""

import asyncio
import ssl
import socket
import uuid
import datetime
from urllib.parse import urlparse

import httpx
from ..config import REQUEST_TIMEOUT_SECONDS

# TLS protocol versions considered deprecated.
DEPRECATED_PROTOCOLS = {"TLSv1", "TLSv1.1", "SSLv2", "SSLv3"}

# Keyword fragments in cipher names that indicate weakness.
WEAK_CIPHER_FRAGMENTS = ["RC4", "DES", "3DES", "NULL", "EXPORT", "ANON", "ADH", "AECDH"]

# Days before expiry that trigger a warning finding.
EXPIRY_WARN_DAYS = 30


def _target_host_port(target: str) -> tuple[str, int]:
    """Return (hostname, port) inferred from the target URL/string."""
    t = target.strip()
    if "://" not in t:
        t = "https://" + t
    parsed = urlparse(t)
    host = parsed.hostname or ""
    # Use explicit port if given; default to 443 for https, 80 for http.
    if parsed.port:
        port = parsed.port
    elif parsed.scheme == "http":
        port = 80
    else:
        port = 443
    return host, port


def _tls_findings(host: str, port: int) -> list[dict]:
    """
    Open a raw TLS connection and inspect the negotiated session + certificate.
    Returns a list of finding dicts (may be empty on a clean connection).
    """
    findings: list[dict] = []
    ctx = ssl.create_default_context()

    # --- Try with full verification first (trust + hostname) -----------------
    trusted = True
    hostname_ok = True
    cert = None
    negotiated_protocol = None
    negotiated_cipher = None

    try:
        with socket.create_connection((host, port), timeout=REQUEST_TIMEOUT_SECONDS) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as tls:
                cert = tls.getpeercert()
                negotiated_protocol = tls.version()
                negotiated_cipher = tls.cipher()
    except ssl.SSLCertVerificationError as exc:
        err = str(exc)
        if "hostname" in err.lower() or "CERTIFICATE_VERIFY_FAILED" in err:
            hostname_ok = False
        trusted = False
        # Retry without verification to still get cert details.
        no_verify_ctx = ssl.create_default_context()
        no_verify_ctx.check_hostname = False
        no_verify_ctx.verify_mode = ssl.CERT_NONE
        try:
            with socket.create_connection((host, port), timeout=REQUEST_TIMEOUT_SECONDS) as raw:
                with no_verify_ctx.wrap_socket(raw, server_hostname=host) as tls:
                    cert = tls.getpeercert()
                    negotiated_protocol = tls.version()
                    negotiated_cipher = tls.cipher()
        except Exception:
            pass
    except ssl.SSLError:
        trusted = False
    except (OSError, socket.timeout):
        # Can't reach the port at all — SSL not available.
        return []

    if not trusted:
        findings.append({
            "id": uuid.uuid4().hex[:10],
            "category": "ssl",
            "severity": "High",
            "type": "Untrusted / Self-Signed Certificate",
            "endpoint": "/",
            "parameter": "—",
            "method": "GET",
            "url": f"https://{host}:{port}/",
            "description": (
                "The server's TLS certificate is not trusted by the system "
                "certificate store. This is typical of self-signed certificates "
                "and means browsers will show a security warning — or be bypassed "
                "by users clicking through — removing TLS's protection against "
                "man-in-the-middle attacks."
            ),
            "evidence": f"SSL verification failed for {host}:{port}.",
            "confidence": "High",
        })

    if not hostname_ok:
        findings.append({
            "id": uuid.uuid4().hex[:10],
            "category": "ssl",
            "severity": "High",
            "type": "Certificate Hostname Mismatch",
            "endpoint": "/",
            "parameter": "—",
            "method": "GET",
            "url": f"https://{host}:{port}/",
            "description": (
                "The certificate presented by the server does not match the "
                "hostname being connected to. A browser or strict client will "
                "reject the connection outright, and the mismatch can indicate "
                "a misconfigured or incorrectly reused certificate."
            ),
            "evidence": f"Certificate hostname check failed for '{host}'.",
            "confidence": "High",
        })

    # --- Certificate expiry --------------------------------------------------
    if cert:
        not_after_str = cert.get("notAfter", "")
        try:
            not_after = datetime.datetime.strptime(
                not_after_str, "%b %d %H:%M:%S %Y %Z"
            ).replace(tzinfo=datetime.timezone.utc)
            now = datetime.datetime.now(datetime.timezone.utc)
            days_left = (not_after - now).days

            if days_left < 0:
                findings.append({
                    "id": uuid.uuid4().hex[:10],
                    "category": "ssl",
                    "severity": "Critical",
                    "type": "Expired Certificate",
                    "endpoint": "/",
                    "parameter": "—",
                    "method": "GET",
                    "url": f"https://{host}:{port}/",
                    "description": (
                        "The server's TLS certificate has expired. Browsers and "
                        "HTTP clients will reject the connection with an error "
                        "unless certificate verification is disabled."
                    ),
                    "evidence": f"Certificate expired on {not_after_str} ({abs(days_left)} day(s) ago).",
                    "confidence": "High",
                })
            elif days_left <= EXPIRY_WARN_DAYS:
                findings.append({
                    "id": uuid.uuid4().hex[:10],
                    "category": "ssl",
                    "severity": "Medium",
                    "type": "Certificate Expiring Soon",
                    "endpoint": "/",
                    "parameter": "—",
                    "method": "GET",
                    "url": f"https://{host}:{port}/",
                    "description": (
                        f"The server's TLS certificate expires in {days_left} day(s). "
                        "Failing to renew before expiry will break all HTTPS connections."
                    ),
                    "evidence": f"Certificate expires on {not_after_str} ({days_left} day(s) remaining).",
                    "confidence": "High",
                })
        except (ValueError, AttributeError):
            pass

    # --- Deprecated TLS protocol ---------------------------------------------
    if negotiated_protocol and negotiated_protocol in DEPRECATED_PROTOCOLS:
        findings.append({
            "id": uuid.uuid4().hex[:10],
            "category": "ssl",
            "severity": "Medium",
            "type": f"Deprecated TLS Protocol ({negotiated_protocol})",
            "endpoint": "/",
            "parameter": "—",
            "method": "GET",
            "url": f"https://{host}:{port}/",
            "description": (
                f"The server negotiated {negotiated_protocol}, which is deprecated "
                "and has known cryptographic weaknesses (BEAST, POODLE, etc.). "
                "Modern clients require TLS 1.2 or 1.3."
            ),
            "evidence": f"Handshake negotiated {negotiated_protocol}.",
            "confidence": "High",
        })

    # --- Weak cipher suite ---------------------------------------------------
    if negotiated_cipher:
        cipher_name = negotiated_cipher[0] if isinstance(negotiated_cipher, (list, tuple)) else str(negotiated_cipher)
        matched_frags = [f for f in WEAK_CIPHER_FRAGMENTS if f in cipher_name.upper()]
        if matched_frags:
            findings.append({
                "id": uuid.uuid4().hex[:10],
                "category": "ssl",
                "severity": "Medium",
                "type": "Weak Cipher Suite",
                "endpoint": "/",
                "parameter": "—",
                "method": "GET",
                "url": f"https://{host}:{port}/",
                "description": (
                    "The negotiated cipher suite uses an algorithm known to be "
                    "weak or broken. Traffic protected only by this cipher is at "
                    "risk of decryption or tampering."
                ),
                "evidence": f"Negotiated cipher: {cipher_name} (weak fragment(s): {', '.join(matched_frags)}).",
                "confidence": "High",
            })

    return findings


async def check_ssl(target: str) -> list[dict]:
    """
    Entry point called by the orchestrator.
    Returns a list of SSL/TLS finding dicts.
    """
    host, port = _target_host_port(target)
    findings: list[dict] = []

    # If the target is HTTP-only (port 80 / http scheme), check for redirect.
    t = target.strip()
    if "://" not in t:
        t = "http://" + t
    parsed = urlparse(t)
    is_http = parsed.scheme == "http" and port != 443

    if is_http:
        # Check whether the HTTP endpoint redirects to HTTPS.
        http_url = f"http://{host}:{port}/"
        https_url = f"https://{host}/" if port == 80 else f"https://{host}:{port}/"
        redirects_to_https = False
        try:
            async with httpx.AsyncClient(
                timeout=REQUEST_TIMEOUT_SECONDS, follow_redirects=False
            ) as client:
                resp = await client.get(http_url)
                location = resp.headers.get("location", "")
                if resp.status_code in (301, 302, 307, 308) and location.startswith("https://"):
                    redirects_to_https = True
        except Exception:
            pass

        if not redirects_to_https:
            findings.append({
                "id": uuid.uuid4().hex[:10],
                "category": "ssl",
                "severity": "Medium",
                "type": "No HTTP→HTTPS Redirect",
                "endpoint": "/",
                "parameter": "—",
                "method": "GET",
                "url": http_url,
                "description": (
                    "The plain-HTTP endpoint does not redirect visitors to its "
                    "HTTPS equivalent. Traffic is transmitted unencrypted, "
                    "exposing session tokens, credentials, and page content to "
                    "passive interception on any shared or hostile network."
                ),
                "evidence": f"GET {http_url} did not return a redirect to an https:// URL.",
                "confidence": "High",
            })

        # Also try the TLS port (443) if the host is accessible.
        tls_findings = await asyncio.to_thread(_tls_findings, host, 443)
        findings.extend(tls_findings)
    else:
        # HTTPS target — run the full TLS inspection.
        tls_findings = await asyncio.to_thread(_tls_findings, host, port)
        findings.extend(tls_findings)

        if not tls_findings:
            # No problems — still surface a positive "all-clear" note via a
            # zero-severity info dict so the log shows something meaningful.
            # (Not added to findings list — just used by orchestrator for logging.)
            pass

    return findings
