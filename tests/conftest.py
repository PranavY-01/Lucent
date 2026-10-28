import socket
from datetime import UTC, datetime

import pytest

FROZEN_TIME = datetime(2026, 10, 28, 12, 0, 0, tzinfo=UTC)


@pytest.fixture(autouse=True)
def _block_network(monkeypatch):
    def guard(*args, **kwargs):
        raise RuntimeError("Network access attempted during tests")

    monkeypatch.setattr(socket.socket, "connect", guard)
    monkeypatch.setattr(socket, "getaddrinfo", guard)
    monkeypatch.setattr(socket, "create_connection", guard)


@pytest.fixture(autouse=True)
def _plain_terminal(monkeypatch):
    # Tests compare plain text; a developer's colour-forcing variables must not add ANSI codes.
    for name in ("FORCE_COLOR", "PY_COLORS", "TTY_COMPATIBLE", "TTY_INTERACTIVE"):
        monkeypatch.delenv(name, raising=False)


@pytest.fixture
def frozen_clock():
    return lambda: FROZEN_TIME
