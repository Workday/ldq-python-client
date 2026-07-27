# Copyright 2024-2026 Workday, Inc. Licensed under the Apache 2.0 http://www.apache.org/licenses/LICENSE-2.0

"""Local callback server for OAuth 2.0 Authorization Code Grant (RFC 6749 §4.1.2)."""

import datetime as dt
import ipaddress
import os
import ssl
import tempfile
import threading
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, HTTPServer
from importlib_resources import files
from typing import Dict, Optional
from urllib.parse import parse_qs, urlparse

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from .constants import HTTPHeader

# Package name for resource loading
PACKAGE_NAME = __package__ or 'workday_ldq'

# Encoding for HTTP responses
ENCODING_UTF8 = 'utf-8'

# Content-Type header values for HTTP responses
CONTENT_TYPE_HTML = "text/html; charset=utf-8"
CONTENT_TYPE_TEXT = "text/plain; charset=utf-8"

# ---------------------------------------------------------------------------
# Self-signed SSL context (process-singleton — avoids repeated cert warnings)
# ---------------------------------------------------------------------------

_ssl_context_lock = threading.Lock()
_ssl_context_cache: Optional[ssl.SSLContext] = None
_ssl_context_expiry: Optional[dt.datetime] = None

_SSL_CERT_VALIDITY_HOURS = 24
_SSL_CERT_REFRESH_BUFFER_SECONDS = 300  # recreate 5 min before expiry


def get_ssl_context() -> ssl.SSLContext:
    """Return the process-wide self-signed SSL context, recreating if near expiry."""
    global _ssl_context_cache, _ssl_context_expiry
    now = dt.datetime.now(dt.timezone.utc)
    if _ssl_context_cache is not None and _ssl_context_expiry is not None:
        if now < _ssl_context_expiry - dt.timedelta(seconds=_SSL_CERT_REFRESH_BUFFER_SECONDS):
            return _ssl_context_cache
    with _ssl_context_lock:
        if _ssl_context_cache is None or _ssl_context_expiry is None or \
                now >= _ssl_context_expiry - dt.timedelta(seconds=_SSL_CERT_REFRESH_BUFFER_SECONDS):
            _ssl_context_cache, _ssl_context_expiry = _create_ssl_context()
    return _ssl_context_cache


def _create_ssl_context() -> tuple[ssl.SSLContext, dt.datetime]:
    """Generate an RSA-2048 self-signed cert for the localhost callback server."""
    expiry = dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=_SSL_CERT_VALIDITY_HOURS)
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(dt.datetime.now(dt.timezone.utc))
        .not_valid_after(expiry)
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
                x509.IPAddress(ipaddress.IPv6Address("::1")),
            ]),
            critical=False,
        )
        .sign(private_key, hashes.SHA256())
    )

    cert_pem = cert.public_bytes(serialization.Encoding.PEM)
    key_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )

    # Write to temp files (ssl.SSLContext.load_cert_chain requires file paths)
    # Using context managers ensures proper cleanup even if exceptions occur
    with tempfile.NamedTemporaryFile(mode='wb', suffix=".pem", delete=False) as cert_file:
        cert_file.write(cert_pem)
        cert_path = cert_file.name

    with tempfile.NamedTemporaryFile(mode='wb', suffix=".pem", delete=False) as key_file:
        key_file.write(key_pem)
        key_path = key_file.name

    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert_path, key_path)
    finally:
        # Clean up temp files
        os.unlink(cert_path)
        os.unlink(key_path)

    return ctx, expiry


# ---------------------------------------------------------------------------
# Local callback HTTP server
# ---------------------------------------------------------------------------

def make_callback_handler(
        expected_state: str,
        expected_path: str,
        result_event: threading.Event,
        result: Dict[str, str],
) -> type:
    """Return a BaseHTTPRequestHandler subclass bound to the given state/result dict.

    Args:
        expected_state: The OAuth state parameter (for CSRF protection)
        expected_path: The expected callback path (e.g., '/callback')
        result_event: Threading event to signal completion
        result: Dictionary to store authorization code or error

    Returns:
        BaseHTTPRequestHandler subclass configured for OAuth callback
    """

    class _CallbackHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            parsed = urlparse(self.path)

            if parsed.path != expected_path:
                self._respond(
                    HTTPStatus.OK,
                    f"OAuth callback server is running. Waiting for authorization at {expected_path}...",
                    is_success=False
                )
                return

            # Path matches - process OAuth callback
            params = parse_qs(parsed.query)
            received_state = params.get("state", [None])[0]
            code = params.get("code", [None])[0]
            error = params.get("error", [None])[0]
            error_description = params.get("error_description", [None])[0]

            if received_state != expected_state:
                self._respond(HTTPStatus.BAD_REQUEST, "State mismatch — possible CSRF attack, authorization rejected.", is_success=False)
                result["error"] = "state_mismatch"
            elif error:
                self._respond(HTTPStatus.BAD_REQUEST, f"Authorization error: {error}", is_success=False)
                result["error"] = error
                if error_description:
                    result["error_description"] = error_description
            elif code:
                self._respond(HTTPStatus.OK, "Authorization successful", is_success=True)
                result["code"] = code
            else:
                self._respond(HTTPStatus.BAD_REQUEST, "Missing authorization code in callback.", is_success=False)
                result["error"] = "missing_code"

            result_event.set()

        def _respond(self, status: HTTPStatus, message: str, is_success: bool = False) -> None:
            if is_success:
                try:
                    # Read bundled HTML success page from package resources
                    html_content = files(PACKAGE_NAME).joinpath('oauth_success.html').read_text(
                        encoding=ENCODING_UTF8)
                    body = html_content.encode(ENCODING_UTF8)
                    content_type = CONTENT_TYPE_HTML
                except Exception:
                    body = message.encode(ENCODING_UTF8)
                    content_type = CONTENT_TYPE_TEXT
            else:
                body = message.encode(ENCODING_UTF8)
                content_type = CONTENT_TYPE_TEXT

            self.send_response(status)
            self.send_header(HTTPHeader.CONTENT_TYPE, content_type)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, fmt: str, *args: object) -> None:
            pass  # Suppress access logs

    return _CallbackHandler


def _is_localhost(hostname: Optional[str]) -> bool:
    """Check if hostname is localhost (similar to Java OAuth2CallbackServer.isLocalhost).

    Args:
        hostname: The hostname to check

    Returns:
        True if hostname is localhost/127.0.0.1/::1, False otherwise
    """
    if hostname is None:
        return False

    # Normalize: lowercase and remove IPv6 brackets
    normalized = hostname.lower().replace("[", "").replace("]", "")

    return normalized in {
        "localhost",
        "127.0.0.1",
        "::1",  # IPv6 loopback
        "0:0:0:0:0:0:0:1",  # IPv6 loopback (expanded)
    }


def _validate_redirect_url(parsed_url) -> None:
    """Validate redirect URL for OAuth callback server (similar to Java OAuth2CallbackServer.validateRedirectUri).

    Ensures the redirect URL:
    - Has localhost as hostname (security requirement - prevents binding to public interfaces)
    - Has a valid port in range 1024-65535 (non-privileged ports)
    - Has a non-empty path that is not just "/" (security requirement)
    - Uses http or https scheme

    Args:
        parsed_url: Parsed URL result from urlparse()

    Raises:
        ValueError: If any validation check fails
    """
    hostname = parsed_url.hostname
    port = parsed_url.port
    scheme = parsed_url.scheme
    path = parsed_url.path

    if hostname is None:
        raise ValueError(
            f"Invalid redirect URL: missing hostname. "
            f"Expected format: http://localhost:port/path or https://localhost:port/path, got: {parsed_url.geturl()}"
        )

    if not _is_localhost(hostname):
        raise ValueError(
            f"Redirect URI host must be localhost (or 127.0.0.1 or ::1). "
            f"Got: {hostname}"
        )

    if scheme.lower() not in ("http", "https"):
        raise ValueError(
            f"Redirect URI scheme must be 'http' or 'https'. "
            f"Got scheme: {scheme}"
        )

    if port is None:
        raise ValueError(
            f"Invalid redirect URL: missing port. "
            f"Expected format: http://localhost:port/path or https://localhost:port/path, got: {parsed_url.geturl()}"
        )

    if port < 1024 or port > 65535:
        raise ValueError(
            f"Redirect URI port must be in range 1024-65535. "
            f"Got: {port}"
        )

    if not path or not path.strip():
        raise ValueError(
            f"Redirect URI must include a path (e.g., /callback). "
            f"Got: {parsed_url.geturl()}"
        )

    if path == "/":
        raise ValueError(
            f"Redirect URI path cannot be just '/' - must include a specific path (e.g., /callback). "
            f"Got: {parsed_url.geturl()}"
        )


def start_callback_server(
        redirect_url: str,
        expected_state: str,
        result_event: threading.Event,
        result: Dict[str, str],
) -> HTTPServer:
    """Start a callback server for OAuth 2.0 authorization code flow.

    Supports both HTTP and HTTPS schemes:
    - For HTTPS URLs: Creates an HTTPS server with a self-signed certificate
    - For HTTP URLs: Creates a plain HTTP server without SSL

    Similar to Java OAuth2CallbackServer.startHttpsServer(), this function:
    - Parses and validates the redirect URL
    - Extracts the callback path and binds the handler to that specific path
    - Creates a server (HTTP or HTTPS based on scheme)

    Args:
        redirect_url: The OAuth redirect URL (e.g., https://localhost:8080/callback or http://localhost:8080/callback)
        expected_state: The OAuth state parameter (for CSRF protection)
        result_event: Threading event to signal when callback is received
        result: Dictionary to store authorization code or error

    Returns:
        Configured HTTPServer instance (with or without SSL/TLS based on URL scheme)

    Raises:
        ValueError: If redirect_url validation fails (not localhost, invalid scheme, invalid port, invalid path, etc.)
    """

    parsed_url = urlparse(redirect_url)
    _validate_redirect_url(parsed_url)

    hostname = parsed_url.hostname
    port = parsed_url.port
    path = parsed_url.path
    scheme = parsed_url.scheme

    handler_class = make_callback_handler(expected_state, path, result_event, result)
    server = HTTPServer((hostname, port), handler_class)

    # Only wrap with SSL if the scheme is HTTPS
    if scheme.lower() == "https":
        ssl_ctx = get_ssl_context()
        server.socket = ssl_ctx.wrap_socket(server.socket, server_side=True)

    return server
