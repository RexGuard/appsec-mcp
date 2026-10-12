"""Website check with a mocked network: GET only, redirects re-checked, errors mapped."""

import httpx
import pytest
import respx

from appsec_mcp.errors import AppSecError, ErrorCode
from appsec_mcp.models.web_check import TlsInfo
from appsec_mcp.security.ssrf import Target
from appsec_mcp.services.web_check_service import WebCheckService, default_client

PUBLIC = "93.184.216.34"


def _resolver(mapping: dict[str, str]):  # type: ignore[no-untyped-def]
    return lambda host, port: [mapping.get(host, PUBLIC)]


def _tls(target: Target, address: str) -> TlsInfo:
    return TlsInfo(
        valid=True, expires="2099-01-01T00:00:00+00:00", days_left=999, protocol="TLSv1.3"
    )


def _service(mapping: dict[str, str] | None = None) -> WebCheckService:
    return WebCheckService(default_client, _resolver(mapping or {}), _tls)


@respx.mock
def test_good_site_scores_high() -> None:
    route = respx.get("https://good.example/").mock(
        return_value=httpx.Response(
            200,
            headers={
                "strict-transport-security": "max-age=31536000; includeSubDomains",
                "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
                "x-content-type-options": "nosniff",
                "referrer-policy": "no-referrer",
                "permissions-policy": "camera=()",
                "set-cookie": "sid=1; Secure; HttpOnly; SameSite=Lax",
            },
        )
    )
    result = _service().check("https://good.example/")
    assert route.called and result.score == 100
    assert all(h.verdict == "good" for h in result.headers)
    assert result.cookies[0].secure and result.cookies[0].samesite == "lax"
    assert result.tls is not None and result.tls.valid


@respx.mock
def test_bad_site_explains_missing_headers() -> None:
    respx.get("https://bad.example/").mock(
        return_value=httpx.Response(200, headers={"set-cookie": "sid=1"})
    )
    result = _service().check("https://bad.example/")
    assert result.score < 50
    missing = {h.name for h in result.headers if h.verdict == "missing"}
    assert "content-security-policy" in missing
    assert all(h.plain_explanation for h in result.headers)
    assert not result.cookies[0].secure


@respx.mock
def test_only_get_requests_are_sent() -> None:
    respx.get("http://site.example/").mock(
        return_value=httpx.Response(301, headers={"location": "https://site.example/"})
    )
    respx.get("https://site.example/").mock(return_value=httpx.Response(200))
    result = _service().check("http://site.example/")
    assert result.final_url == "https://site.example/"
    assert {call.request.method for call in respx.calls} == {"GET"}


@respx.mock
def test_redirect_to_private_address_is_blocked() -> None:
    respx.get("https://public.example/").mock(
        return_value=httpx.Response(302, headers={"location": "http://metadata.internal/latest"})
    )
    service = _service({"metadata.internal": "169.254.169.254"})
    with pytest.raises(AppSecError) as exc:
        service.check("https://public.example/")
    assert exc.value.code == ErrorCode.URL_PRIVATE_BLOCKED


def test_private_target_blocked_before_any_request() -> None:
    with respx.mock(assert_all_called=False) as mock:
        with pytest.raises(AppSecError) as exc:
            _service({"localhost": "127.0.0.1"}).check("http://localhost:8080/")
        assert exc.value.code == ErrorCode.URL_PRIVATE_BLOCKED
        assert not mock.calls


@respx.mock
def test_timeout_and_tls_errors_are_mapped() -> None:
    respx.get("https://slow.example/").mock(side_effect=httpx.ReadTimeout("slow"))
    with pytest.raises(AppSecError) as timeout:
        _service().check("https://slow.example/")
    assert timeout.value.code == ErrorCode.TIMEOUT
    respx.get("https://badcert.example/").mock(
        side_effect=httpx.ConnectError("[SSL: CERTIFICATE_VERIFY_FAILED] certificate expired")
    )
    with pytest.raises(AppSecError) as tls:
        _service().check("https://badcert.example/")
    assert tls.value.code == ErrorCode.TLS_ERROR


@respx.mock
def test_redirect_loop_is_capped() -> None:
    respx.get("https://loop.example/").mock(
        return_value=httpx.Response(302, headers={"location": "https://loop.example/"})
    )
    with pytest.raises(AppSecError) as exc:
        _service().check("https://loop.example/")
    assert exc.value.code == ErrorCode.URL_INVALID
