"""Passive website check models."""

from typing import Literal

from pydantic import Field

from appsec_mcp.models.base import StrictModel

Verdict = Literal["good", "weak", "missing"]


class TlsInfo(StrictModel):
    """TLS certificate facts."""

    valid: bool
    expires: str | None = None
    days_left: int | None = None
    protocol: str | None = None
    error: str | None = None


class HeaderCheck(StrictModel):
    """One security header and what its value means."""

    name: str
    present: bool
    value: str | None = None
    verdict: Verdict
    plain_explanation: str


class CookieCheck(StrictModel):
    """Security flags of one cookie."""

    name: str
    secure: bool
    httponly: bool
    samesite: str | None = None


class WebCheckResult(StrictModel):
    """Response of check_website."""

    url: str
    final_url: str
    status_code: int
    tls: TlsInfo | None
    headers: list[HeaderCheck]
    cookies: list[CookieCheck]
    score: int = Field(ge=0, le=100)
