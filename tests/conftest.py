import importlib.util
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parent.parent
FIXTURE_SERVERS = ROOT / "fixtures" / "servers"


def load_fixture_module(name: str) -> ModuleType:
    """Import fixtures/servers/<name>.py fresh, so each test gets its own server instance."""
    path = FIXTURE_SERVERS / f"{name}.py"
    spec = importlib.util.spec_from_file_location(f"fixture_{name}", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(autouse=True)
def no_real_browser(monkeypatch):
    """No test may open the user's browser; sign-in tests pass a stand-in instead."""

    def refuse(*args, **kwargs):
        raise AssertionError("a test tried to open a real browser")

    monkeypatch.setattr("webbrowser.open", refuse)


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"
