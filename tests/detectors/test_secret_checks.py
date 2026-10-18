"""Value checks on PPE's own secret rules: placeholders for `KEY=value`, and the HTTP authorization
schemes (Basic, Bearer, NTLM/Negotiate). Fake credentials are assembled at run time."""

from __future__ import annotations

import base64

import pytest

from prompt_privacy.core.types import EntityType as T
from prompt_privacy.detectors.base import detect
from prompt_privacy.detectors.secrets import basic_credentials, is_placeholder, token_like


def secrets(text: str) -> list[tuple[str, str]]:
    return [(f.subtype, f.value) for f in detect(text) if f.type is T.SECRET]


@pytest.mark.parametrize(
    ("value", "quoted"),
    [
        ("changeme123", True),  # placeholder word
        ("your-api-key-here", True),
        ("xxxxxxxxxxxx", True),  # also three or fewer distinct characters
        ("********", False),
        ("${DB_PASSWORD}", True),
        ("${DEPLOY_KEY_X1}", True),  # templates (no other check applies), quoted or not
        ("{{vault.db.value}}", True),
        ("<value-goes-here>", False),
        ("$DEPLOY_KEY_X1", False),
        ("%APPDATA_KEY%", False),
        ("os.environ[", False),  # code, when not quoted
        ("get_token(request)", False),
        ("getenv(", False),
        ("access_token_here", True),  # names a kind of credential
        ("settings.SECRET_KEY", False),
    ],
)
def test_placeholders_and_references(value: str, quoted: bool) -> None:
    assert is_placeholder(value, quoted)


@pytest.mark.parametrize(
    ("value", "quoted"),
    [
        ("account123x", True),  # a programming word in a real password: kept (Gitleaks' list drops it)
        ("Summer2024!", True),
        ("Pa(ss)w0rd99", True),  # brackets in a quoted literal are part of the password
        ("Kx9(mP2#q", True),  # brackets in a quoted password; unquoted it would count as code
        ("abcd1234efgh5678", False),
        ("p4ss.w0rd.x", False),
        ("@Wq8z!pa55", False),  # a leading symbol is not a template
    ],
)
def test_real_looking_values_are_kept(value: str, quoted: bool) -> None:
    assert not is_placeholder(value, quoted)


def test_assignment_in_detect_uses_the_checks() -> None:
    text = (
        "export API_KEY=changeme123\n"
        "API_KEY = os.environ['API_KEY']\n"
        'DB_PASSWORD="Pa(ss)w0rd99"\n'
        "export API_KEY=abcd1234efgh5678\n"
    )
    assert secrets(text) == [("assignment", "Pa(ss)w0rd99"), ("assignment", "abcd1234efgh5678")]


def test_basic_credentials() -> None:
    good = base64.b64encode(b"alice:" + b"Wq8z!pa55").decode()
    assert basic_credentials(good) and basic_credentials(good.rstrip("="))
    assert not basic_credentials(base64.b64encode(b"no colon here").decode())
    assert not basic_credentials(base64.b64encode(b":password").decode())  # empty user
    assert not basic_credentials(base64.b64encode(b"user:\x00\x01").decode())  # not printable
    assert not basic_credentials("understanding")
    assert not basic_credentials("abc$%^&*")


def test_basic_auth_rule() -> None:
    cred = base64.b64encode(b"svc-deploy:" + b"k9Lw2!qz").decode()
    assert secrets(f'curl -H "Authorization: Basic {cred}" https://x.test') == [("basic_auth", cred)]
    assert secrets(f"  - Basic {cred}\n") == [("basic_auth", cred)]
    assert secrets("Basic arithmetic and a basic understanding of it.") == []
    assert secrets("Authorization: Basic xxxxxxxxxxxxxxxx") == []  # decodes to no user:password


def test_bearer_token_rule() -> None:
    token = "ya29" + "-a0Af" + "H6SMB" + "x7Kq2" + "pL9vR"
    assert secrets(f"Authorization: Bearer {token}") == [("bearer_token", token)]
    assert secrets("the bearer instrument matters; Bearer authentication is described here") == []
    assert token_like("abc123def456ghi7") and not token_like("authenticationxyz")


def test_ntlm_negotiate_rule() -> None:
    msg = "TlRMTVNTUA" + "ABAAAAB4IIog" + "AAAAAAAAAAA="
    assert secrets(f"WWW-Authenticate: NTLM {msg}") == [("ntlm_negotiate", msg)]
    assert secrets("NTLM authentication is enabled on Negotiate endpoints") == []
