"""Regressions for concurrent cron redaction and Codex fail-closed inputs."""
import base64
import sqlite3
from concurrent.futures import ThreadPoolExecutor

from privacy import blocked_content_for_key
from vault import AliasVault


def test_blocked_responses_input_is_list():
    value = blocked_content_for_key("input")
    assert isinstance(value, list)
    assert value[0]["content"][0]["type"] == "input_text"
    assert value[0]["content"][0]["text"] == "[PRIVACY_GATEWAY_BLOCKED_REQUEST]"


def test_concurrent_alias_and_resolve():
    vault = AliasVault(
        connection=sqlite3.connect(":memory:", check_same_thread=False),
        encoded_key=base64.urlsafe_b64encode(bytes(range(32))).decode(),
    )

    def work(i):
        original = f"test {i % 101}"
        alias = vault.alias("PERSON", original)
        assert vault.resolve(alias) == original

    with ThreadPoolExecutor(max_workers=16) as pool:
        list(pool.map(work, range(5000)))
