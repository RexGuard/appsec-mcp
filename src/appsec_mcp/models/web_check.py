"""check_website: passive TLS, header and cookie check of a site the user owns."""

from __future__ import annotations

from typing import Literal

from pydantic import Field, field_validator

from appsec_mcp.models.common import StrictModel


class CheckWebsiteRequest(StrictModel):
    url: str = Field(min_length=1, max_length=2048)
    allow_private: bool = False

    @field_validator("url")
    @classmethod
    def _http_only(cls, v: str) -> str:
        if not v.lower().startswith(("http://", "https://")):
            raise ValueError("url must start with http:// or https://")
        return v


class TlsInfo(StrictModel):
    valid: bool
    expires: str | None = None
    protocol: str | None = None


class HeaderCheck(StrictModel):
    name: str = Field(min_length=1)
    present: bool
    value: str | None = None
    verdict: Literal["good", "weak", "missing"]
    plain_explanation: str = Field(min_length=1)


class CookieCheck(StrictModel):
    name: str = Field(min_length=1)
    secure: bool
    httponly: bool
    samesite: Literal["strict", "lax", "none"] | None = None


class WebsiteReport(StrictModel):
    url: str
    final_url: str
    tls: TlsInfo | None = None
    headers: list[HeaderCheck]
    cookies: list[CookieCheck]
    score: int = Field(ge=0, le=100)
