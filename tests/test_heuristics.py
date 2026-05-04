import base64
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from plugins.admin.main import is_semantic_admin_response
from plugins.graphql.main import is_graphql_json_response
from plugins.host_header_injection.main import reflection_context
from plugins.jwt_analyzer.main import decode_jwt, test_weak_secrets
from plugins.takeover.main import evaluate_takeover_signal


def _jwt(header: dict, payload: dict, signature: str = "sig") -> str:
    h = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
    p = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    return f"{h}.{p}.{signature}"


def test_graphql_json_response_validator():
    assert is_graphql_json_response('{"data":{"x":1}}')
    assert is_graphql_json_response('{"errors":[{"message":"x"}]}')
    assert not is_graphql_json_response("<html>not graphql</html>")


def test_admin_semantic_response_filter():
    body = "<html><title>Admin Dashboard</title><h1>Users</h1></html>"
    assert is_semantic_admin_response(body, "Admin Dashboard", "/admin")
    assert not is_semantic_admin_response("<html>Not Found</html>", "Not Found", "/foo")


def test_host_header_reflection_context():
    dangerous = '<form action="https://evil-enum-allma.com/login"></form>'
    safe = '<link rel="canonical" href="https://evil-enum-allma.com/">'
    assert reflection_context(dangerous.lower(), "evil-enum-allma.com") == "DANGEROUS"
    assert reflection_context(safe.lower(), "evil-enum-allma.com") == "SAFE"


def test_takeover_signal_scoring():
    assert evaluate_takeover_signal(True, True, False) == ("HIGH", "VULNERABLE")
    assert evaluate_takeover_signal(False, True, True) == ("CONFIRMED", "CONFIRMED")
    assert evaluate_takeover_signal(False, False, False) == ("LOW", "POTENTIAL")


def test_jwt_decode_and_weak_secret():
    token = _jwt({"alg": "HS256", "typ": "JWT"}, {"sub": "1"}, signature="")
    h, p = decode_jwt(token)
    assert h["alg"] == "HS256"
    assert p["sub"] == "1"
    assert test_weak_secrets("a.b.c", "RS256") is None
