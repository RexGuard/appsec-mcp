"""Path confinement, secret redaction and the SSRF guard."""

from pathlib import Path

import pytest

from appsec_mcp.errors import AppSecError, ErrorCode
from appsec_mcp.security.paths import confine, resolve_scan_root
from appsec_mcp.security.redact import mask_secret, redact_text
from appsec_mcp.security.ssrf import check_target, is_blocked_ip, parse_target


def test_resolve_scan_root_errors(tmp_path: Path) -> None:
    with pytest.raises(AppSecError) as missing:
        resolve_scan_root(str(tmp_path / "nope"))
    assert missing.value.code == ErrorCode.PATH_NOT_FOUND
    file = tmp_path / "f.txt"
    file.write_text("x")
    with pytest.raises(AppSecError) as not_dir:
        resolve_scan_root(str(file))
    assert not_dir.value.code == ErrorCode.PATH_NOT_DIRECTORY
    for forbidden in (str(Path.home()), Path.home().anchor):
        with pytest.raises(AppSecError) as exc:
            resolve_scan_root(forbidden)
        assert exc.value.code == ErrorCode.PATH_FORBIDDEN
    assert resolve_scan_root(str(tmp_path)) == tmp_path.resolve()


def test_confine_blocks_escape(tmp_path: Path) -> None:
    assert confine(tmp_path, "a/b.txt") == (tmp_path / "a" / "b.txt").resolve()
    with pytest.raises(AppSecError) as exc:
        confine(tmp_path, "../escape.txt")
    assert exc.value.code == ErrorCode.PATH_OUTSIDE_ROOT


def test_mask_secret_keeps_prefix_and_suffix() -> None:
    assert mask_secret("sk_live_51FAKEFAKEFAKEFAKE00000abcd") == "sk_live_****abcd"
    assert mask_secret("short") == "****"


@pytest.mark.parametrize(
    "line",
    [
        'const STRIPE_KEY = "sk_live_51FAKEFAKEFAKEFAKE00000abcd";',
        "AWS_ACCESS_KEY_ID=AKIAABCDEFGHIJKLMNOP",
        'password = "hunter2hunter2"',
        'const MAPS_API_KEY = "AIzaSyFAKEfakeFAKEfakeFAKEfakeFAKEfake12";',
    ],
)
def test_redact_removes_raw_secret(line: str) -> None:
    redacted = redact_text(line)
    assert "****" in redacted
    for secret in (
        "51FAKEFAKEFAKEFAKE00000",
        "ABCDEFGHIJKLMNOP",
        "hunter2hunter2",
        "SyFAKEfakeFAKEfake",
    ):
        assert secret not in redacted


def test_redact_leaves_env_lookups_alone() -> None:
    line = "const key = process.env.STRIPE_KEY;"
    assert redact_text(line) == line


@pytest.mark.parametrize(
    ("ip", "blocked"),
    [
        ("127.0.0.1", True),
        ("10.1.2.3", True),
        ("192.168.1.1", True),
        ("169.254.169.254", True),
        ("::1", True),
        ("::ffff:127.0.0.1", True),
        ("fe80::1", True),
        ("0.0.0.0", True),
        ("8.8.8.8", False),
        ("2606:4700:4700::1111", False),
    ],
)
def test_is_blocked_ip(ip: str, blocked: bool) -> None:
    assert is_blocked_ip(ip) is blocked


def test_check_target_blocks_private_unless_allowed() -> None:
    target = parse_target("https://intranet.example")
    with pytest.raises(AppSecError) as exc:
        check_target(target, False, lambda host, port: ["10.0.0.5"])
    assert exc.value.code == ErrorCode.URL_PRIVATE_BLOCKED
    assert check_target(target, True, lambda host, port: ["10.0.0.5"]) == ["10.0.0.5"]


@pytest.mark.parametrize(
    "url",
    [
        "ftp://x.com",
        "javascript:alert(1)",
        "https://",
        "x.com",
        "https://user:pw@x.com",
        "https://x.com:99999",
    ],
)
def test_parse_target_rejects_bad_urls(url: str) -> None:
    with pytest.raises(AppSecError) as exc:
        parse_target(url)
    assert exc.value.code == ErrorCode.URL_INVALID
