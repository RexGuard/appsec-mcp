"""Passive website check: GET only, headers, cookies and TLS. For sites the user owns."""

import logging
import socket
import ssl
from collections.abc import Callable
from datetime import UTC, datetime
from urllib.parse import urljoin

import httpx

from appsec_mcp.config import WEB_MAX_REDIRECTS, WEB_TIMEOUT_S
from appsec_mcp.errors import ErrorCode, WebCheckError
from appsec_mcp.models.web_check import CookieCheck, HeaderCheck, TlsInfo, WebCheckResult
from appsec_mcp.security.ssrf import Resolver, Target, check_target, parse_target, system_resolver

logger = logging.getLogger(__name__)

TlsProbe = Callable[[Target, str], TlsInfo]
ClientFactory = Callable[[], httpx.Client]

_REDIRECT_CODES = frozenset({301, 302, 303, 307, 308})
_HSTS_MIN_AGE = 15_552_000
_PENALTY_MISSING = 12
_PENALTY_WEAK = 5
_PENALTY_COOKIE = 5
_PENALTY_TLS = 30
_USER_AGENT = "appsec-mcp passive check (+https://github.com/RexGuard)"

_EXPLAIN: dict[str, tuple[str, str]] = {
    "strict-transport-security": (
        "Tells browsers to always use HTTPS for your site.",
        "Without it, the first visit can be downgraded to plain HTTP and intercepted.",
    ),
    "content-security-policy": (
        "Limits which scripts and resources the page may load.",
        "Without it, any injected script runs freely, which makes XSS much worse.",
    ),
    "x-content-type-options": (
        "Stops browsers from guessing file types.",
        "Without nosniff, an uploaded file can be run as a script.",
    ),
    "x-frame-options": (
        "Stops other sites from showing your pages in a frame.",
        "Without it, attackers can trick users into clicking hidden buttons (clickjacking).",
    ),
    "referrer-policy": (
        "Controls how much of your URLs are shared with other sites.",
        "Without it, private URLs (with tokens or ids) can leak to third parties.",
    ),
    "permissions-policy": (
        "Turns off browser features (camera, location) you don't use.",
        "Without it, injected or embedded content can ask for those features.",
    ),
}


def default_client() -> httpx.Client:
    """An httpx client that never follows redirects by itself."""
    return httpx.Client(
        timeout=WEB_TIMEOUT_S, follow_redirects=False, headers={"User-Agent": _USER_AGENT}
    )


def default_tls_probe(target: Target, address: str) -> TlsInfo:
    """Handshake with the already-checked IP and read the certificate."""
    context = ssl.create_default_context()
    try:
        with (
            socket.create_connection((address, target.port), timeout=WEB_TIMEOUT_S) as sock,
            context.wrap_socket(sock, server_hostname=target.host) as tls,
        ):
            cert = tls.getpeercert() or {}
            protocol = tls.version()
    except ssl.SSLError as exc:
        return TlsInfo(valid=False, error=f"Certificate problem: {exc.reason or exc}")
    except OSError as exc:
        return TlsInfo(valid=False, error=f"Could not connect for the TLS check: {exc}")
    not_after = cert.get("notAfter")
    expires = None
    days_left = None
    if isinstance(not_after, str):
        expiry = datetime.fromtimestamp(ssl.cert_time_to_seconds(not_after), UTC)
        expires = expiry.isoformat(timespec="seconds")
        days_left = (expiry - datetime.now(UTC)).days
    return TlsInfo(valid=True, expires=expires, days_left=days_left, protocol=protocol)


class WebCheckService:
    """Runs check_website. The client, resolver and TLS probe are injectable for tests."""

    def __init__(
        self,
        client_factory: ClientFactory = default_client,
        resolver: Resolver = system_resolver,
        tls_probe: TlsProbe = default_tls_probe,
    ) -> None:
        self._client_factory = client_factory
        self._resolver = resolver
        self._tls_probe = tls_probe

    def check(self, url: str, allow_private: bool = False) -> WebCheckResult:
        """Fetch the page with GET (following up to 5 checked redirects) and grade it."""
        target = parse_target(url)
        with self._client_factory() as client:
            response, target, address = self._fetch(client, target, allow_private)
        headers = _grade_headers(response.headers, target.scheme == "https")
        cookies = _grade_cookies(response.headers.get_list("set-cookie"))
        tls = self._tls_probe(target, address) if target.scheme == "https" else None
        return WebCheckResult(
            url=url,
            final_url=target.url,
            status_code=response.status_code,
            tls=tls,
            headers=headers,
            cookies=cookies,
            score=_score(headers, cookies, tls),
        )

    def _fetch(
        self, client: httpx.Client, target: Target, allow_private: bool
    ) -> tuple[httpx.Response, Target, str]:
        for _ in range(WEB_MAX_REDIRECTS + 1):
            addresses = check_target(target, allow_private, self._resolver)
            response = _get(client, target.url)
            location = response.headers.get("location")
            if response.status_code not in _REDIRECT_CODES or not location:
                return response, target, addresses[0]
            target = parse_target(urljoin(target.url, location))
        raise WebCheckError(
            ErrorCode.URL_INVALID, f"The site redirected more than {WEB_MAX_REDIRECTS} times."
        )


def _get(client: httpx.Client, url: str) -> httpx.Response:
    try:
        with client.stream("GET", url) as response:
            response.close()
            return response
    except httpx.TimeoutException as exc:
        raise WebCheckError(
            ErrorCode.TIMEOUT, f"{url} did not answer within {WEB_TIMEOUT_S:.0f} seconds."
        ) from exc
    except httpx.ConnectError as exc:
        if "CERTIFICATE" in str(exc).upper() or "SSL" in str(exc).upper():
            raise WebCheckError(
                ErrorCode.TLS_ERROR, f"The HTTPS certificate of {url} is not valid: {exc}"
            ) from exc
        raise WebCheckError(ErrorCode.URL_INVALID, f"Could not connect to {url}: {exc}") from exc
    except httpx.HTTPError as exc:
        raise WebCheckError(ErrorCode.URL_INVALID, f"Request to {url} failed: {exc}") from exc


def _grade_headers(headers: httpx.Headers, is_https: bool) -> list[HeaderCheck]:
    results = []
    for name, (what, risk) in _EXPLAIN.items():
        if name == "strict-transport-security" and not is_https:
            continue
        value = headers.get(name)
        verdict = "missing" if value is None else _verdict(name, value, headers)
        if (
            name == "x-frame-options"
            and value is None
            and "frame-ancestors" in (headers.get("content-security-policy") or "")
        ):
            verdict = "good"
        explanation = what if verdict == "good" else f"{what} {risk}"
        if verdict == "weak":
            explanation = f"{what} It is set, but with a weak value."
        results.append(
            HeaderCheck(
                name=name,
                present=value is not None,
                value=value,
                verdict=verdict,
                plain_explanation=explanation,
            )
        )
    return results


def _verdict(name: str, value: str, headers: httpx.Headers) -> str:
    lowered = value.lower()
    if name == "strict-transport-security":
        try:
            age = int(lowered.split("max-age=")[1].split(";")[0].strip())
        except (IndexError, ValueError):
            return "weak"
        return "good" if age >= _HSTS_MIN_AGE else "weak"
    if name == "content-security-policy":
        return "weak" if "'unsafe-inline'" in lowered or "*" in lowered.split() else "good"
    if name == "x-content-type-options":
        return "good" if lowered.strip() == "nosniff" else "weak"
    if name == "x-frame-options":
        return "good" if lowered.strip() in ("deny", "sameorigin") else "weak"
    if name == "referrer-policy":
        return "weak" if lowered.strip() in ("unsafe-url", "no-referrer-when-downgrade") else "good"
    return "good"


def _grade_cookies(raw_cookies: list[str]) -> list[CookieCheck]:
    cookies = []
    for raw in raw_cookies:
        name = raw.split("=", 1)[0].strip()
        attributes = [a.strip().lower() for a in raw.split(";")[1:]]
        samesite = next((a.split("=", 1)[1] for a in attributes if a.startswith("samesite=")), None)
        cookies.append(
            CookieCheck(
                name=name,
                secure="secure" in attributes,
                httponly="httponly" in attributes,
                samesite=samesite,
            )
        )
    return cookies


def _score(headers: list[HeaderCheck], cookies: list[CookieCheck], tls: TlsInfo | None) -> int:
    penalty = sum(
        _PENALTY_MISSING if h.verdict == "missing" else _PENALTY_WEAK if h.verdict == "weak" else 0
        for h in headers
    )
    penalty += sum(_PENALTY_COOKIE for c in cookies if not (c.secure and c.httponly))
    if tls is not None and not tls.valid:
        penalty += _PENALTY_TLS
    return max(0, 100 - penalty)
