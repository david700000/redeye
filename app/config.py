"""
Runtime configuration.

This is a lab / authorized-pentesting tool. Every scan and every
exploitation step is checked against an explicit scope list before it
runs. There is no "scan the internet" mode by design.
"""

# Hosts that are authorized by default. The frontend's Settings > Lab
# scope screen manages this list at runtime via /scope; this is just
# the seed value used on startup.
DEFAULT_LAB_SCOPE = ["localhost", "127.0.0.1", "testphp.vulnweb.com"]

# Crawl limits — keep discovery bounded and polite.
CRAWL_MAX_PAGES = 40
CRAWL_MAX_DEPTH = 3
REQUEST_TIMEOUT_SECONDS = 8.0

# Marker used to detect reflected XSS without needing a real browser.
XSS_MARKER = "redsenseXSSchk9f2"

# Files we look for during traversal checks. Kept to well-known,
# non-destructive read targets appropriate for local lab boxes
# (DVWA, Juice Shop, WebGoat, etc.) — this never writes or deletes.
TRAVERSAL_TARGETS = [
    {
        "payload": "../" * 6 + "etc/passwd",
        "signature": "root:x:0:0:",
        "label": "/etc/passwd",
    },
    {
        "payload": "..\\" * 6 + "windows\\win.ini",
        "signature": "[fonts]",
        "label": "windows\\win.ini",
    },
]

REQUIRED_HEADERS = [
    {
        "header": "content-security-policy",
        "name": "Content-Security-Policy",
        "recommended": "Content-Security-Policy: default-src 'self'",
        "description": (
            "The response does not include a Content-Security-Policy header, "
            "leaving the application without a browser-enforced layer of "
            "injection defense."
        ),
    },
    {
        "header": "x-frame-options",
        "name": "X-Frame-Options",
        "recommended": "X-Frame-Options: DENY",
        "description": (
            "Without X-Frame-Options (or a frame-ancestors CSP directive), the "
            "page can be embedded in an iframe on another site, enabling "
            "clickjacking."
        ),
    },
    {
        "header": "strict-transport-security",
        "name": "Strict-Transport-Security",
        "recommended": "Strict-Transport-Security: max-age=31536000; includeSubDomains",
        "description": (
            "HSTS is not enforced, so browsers may downgrade future "
            "connections to plain HTTP, exposing sessions to interception."
        ),
    },
    {
        "header": "x-content-type-options",
        "name": "X-Content-Type-Options",
        "recommended": "X-Content-Type-Options: nosniff",
        "description": (
            "Without this header, browsers may MIME-sniff responses, which "
            "can lead to content being interpreted in unintended ways."
        ),
    },
]

# Step ids/labels — index-for-index match to the frontend's
# SCAN_STEP_DEFS so progress events line up with the UI checklist.
SCAN_STEPS = [
    {"id": "crawl", "label": "Reconnaissance: crawling target"},
    {"id": "discover", "label": "Discovery: enumerating endpoints"},
    {"id": "params", "label": "Discovery: mapping parameters"},
    {"id": "headers", "label": "Auditing security headers"},
    {"id": "ssl", "label": "Auditing SSL/TLS configuration"},
    {"id": "xss", "label": "Testing for XSS"},
    {"id": "sqli", "label": "Testing for SQL Injection"},
    {"id": "traversal", "label": "Testing for directory traversal"},
]
