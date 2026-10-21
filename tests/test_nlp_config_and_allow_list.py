import base64
import secrets
import sqlite3
from pathlib import Path
from types import SimpleNamespace

import pytest

pytest.importorskip("presidio_analyzer")

from privacy import PrivacyEngine
from vault import AliasVault


PLUGIN_DIR = Path(__file__).resolve().parent.parent


def memory_vault():
    key = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode()
    return AliasVault(connection=sqlite3.connect(":memory:"), encoded_key=key)


def engine_with_fake_spans(spans, allow_list=()):
    engine = object.__new__(PrivacyEngine)
    engine.language = "en"
    engine.score_threshold = 0.55
    engine.vault = memory_vault()
    engine.allow_list = frozenset(term.casefold() for term in allow_list)

    class FakeAnalyzer:
        def analyze(self, *, text, language, score_threshold):
            results = []
            for value, entity in spans:
                start = text.index(value)
                score = 0.75 if entity == "PHONE_NUMBER" else 0.85
                results.append(
                    SimpleNamespace(start=start, end=start + len(value), score=score, entity_type=entity)
                )
            return results

    engine.analyzer = FakeAnalyzer()
    return engine


def test_allow_list_keeps_allowed_terms_case_insensitively():
    engine = engine_with_fake_spans(
        [("notion", "LOCATION"), ("MCP", "ORGANIZATION"), ("Kamil Grabowski", "PERSON")],
        allow_list=["Notion", "mcp"],
    )
    sanitized = engine.sanitize("Kamil Grabowski zapisał to w notion przez MCP.")
    assert "notion" in sanitized
    assert "MCP" in sanitized
    assert "Kamil Grabowski" not in sanitized


def test_allow_list_does_not_exempt_spans_that_merely_contain_a_term():
    engine = engine_with_fake_spans([("Notion Kamil", "PERSON")], allow_list=["Notion"])
    assert "Notion Kamil" not in engine.sanitize("Notatka: Notion Kamil.")


def test_allow_list_ignores_surrounding_punctuation():
    engine = engine_with_fake_spans([("Claude,", "PERSON")], allow_list=["Claude"])
    assert engine.sanitize("Zapytaj Claude, potem odpisz.") == "Zapytaj Claude, potem odpisz."


def test_digit_only_name_entities_yield_to_pattern_types():
    engine = engine_with_fake_spans([("728934610", "PERSON"), ("728934610", "PHONE_NUMBER")])
    sanitized = engine.sanitize("tel. 728934610")
    assert sanitized.startswith("tel. [PHONE_NUMBER_")


def test_polish_nlp_config_tags_names_not_common_words():
    spacy_util = pytest.importorskip("spacy.util")
    if not spacy_util.is_package("pl_core_news_lg"):
        pytest.skip("pl_core_news_lg is not installed")

    engine = PrivacyEngine(PLUGIN_DIR / "nlp-pl.yaml", vault=memory_vault())

    def entities(text):
        return {
            (r.entity_type, text[r.start : r.end])
            for r in engine.analyzer.analyze(text=text, language="en", score_threshold=0.55)
        }

    assert ("PERSON", "Kamil Grabowski") in entities("Pisze Kamil Grabowski z Warszawy.")
    assert not entities("Najpierw sprawdź opóźnienie zamówienia, potem odpal ręcznie.")
    # Pattern recognizers stay active under the en registry label.
    assert ("EMAIL_ADDRESS", "kamil@example.com") in entities("mail kamil@example.com")
