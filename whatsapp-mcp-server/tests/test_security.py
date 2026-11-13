"""Security checks for the Python MCP server.

Run from whatsapp-mcp-server/:  uv run --with pytest pytest -q tests
"""
import os
import sqlite3
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import whatsapp  # noqa: E402


@pytest.fixture
def outbox(tmp_path, monkeypatch):
    box = tmp_path / "outbox"
    monkeypatch.setenv("WHATSAPP_MCP_OUTBOX", str(box))
    return os.path.realpath(whatsapp.get_outbox_dir())


def test_outbox_is_private(outbox):
    assert oct(os.stat(outbox).st_mode & 0o777) == oct(0o700)


def test_file_inside_outbox_allowed(outbox):
    path = os.path.join(outbox, "photo.jpg")
    open(path, "wb").close()
    assert whatsapp.check_media_path(path) == path


@pytest.mark.parametrize("make_path", [
    lambda out, tmp: str(tmp / "secret.txt"),                       # outside
    lambda out, tmp: os.path.join(out, "..", "secret.txt"),          # ../ escape
    lambda out, tmp: os.path.join(out, "link.txt"),                  # symlink out
])
def test_files_outside_outbox_refused(outbox, tmp_path, make_path):
    secret = tmp_path / "secret.txt"
    secret.write_text("x")
    os.symlink(secret, os.path.join(outbox, "link.txt"))
    with pytest.raises(ValueError):
        whatsapp.check_media_path(make_path(outbox, tmp_path))


def test_send_file_refuses_without_calling_bridge(outbox, tmp_path, monkeypatch):
    called = []
    monkeypatch.setattr(whatsapp, "_post", lambda *a, **k: called.append(a))
    (tmp_path / "id_ed25519").write_text("key")
    ok, msg = whatsapp.send_file("201001234567", str(tmp_path / "id_ed25519"))
    assert not ok and "only be sent" in msg
    assert called == []


def test_direct_chat_lookup_is_exact(tmp_path, monkeypatch):
    db = tmp_path / "messages.db"
    conn = sqlite3.connect(db)
    conn.executescript("""
        CREATE TABLE chats (jid TEXT PRIMARY KEY, name TEXT, last_message_time TIMESTAMP);
        CREATE TABLE messages (id TEXT, chat_jid TEXT, sender TEXT, content TEXT, timestamp TIMESTAMP,
            is_from_me BOOLEAN, media_type TEXT);
        INSERT INTO chats VALUES ('201001234567@s.whatsapp.net', 'Alice', NULL);
        INSERT INTO chats VALUES ('441001234567@s.whatsapp.net', 'Bob', NULL);
    """)
    conn.commit(); conn.close()
    monkeypatch.setattr(whatsapp, "MESSAGES_DB_PATH", str(db))
    # A partial number used to match whichever chat came first
    assert whatsapp.get_direct_chat_by_contact("1001234567") is None
    assert whatsapp.get_direct_chat_by_contact("+20 100 123 4567").name == "Alice"


def test_requests_carry_token_and_timeout(tmp_path, monkeypatch):
    token_file = tmp_path / "api_token"
    token_file.write_text("t" * 64 + "\n")
    monkeypatch.setattr(whatsapp, "API_TOKEN_PATH", str(token_file))
    seen = {}

    def fake_post(url, json, headers, timeout):
        seen.update(url=url, headers=headers, timeout=timeout)
        class R:
            status_code = 200
            def json(self): return {"success": True, "message": "ok"}
        return R()

    monkeypatch.setattr(whatsapp.requests, "post", fake_post)
    assert whatsapp.send_message("201001234567", "hi") == (True, "ok")
    assert seen["url"].startswith("http://127.0.0.1:8080/")
    assert seen["headers"]["Authorization"] == "Bearer " + "t" * 64
    assert seen["timeout"] == whatsapp.REQUEST_TIMEOUT
