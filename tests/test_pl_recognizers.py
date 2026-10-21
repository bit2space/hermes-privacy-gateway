import base64
import secrets
import sqlite3
from pathlib import Path

import pytest

pytest.importorskip("presidio_analyzer")
spacy_util = pytest.importorskip("spacy.util")
if not spacy_util.is_package("en_core_web_lg"):
    pytest.skip("en_core_web_lg is not installed", allow_module_level=True)

from privacy import PrivacyEngine
from vault import AliasVault


THRESHOLD = 0.55


@pytest.fixture(scope="module")
def engine():
    key = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode()
    vault = AliasVault(connection=sqlite3.connect(":memory:"), encoded_key=key)
    return PrivacyEngine(
        Path(__file__).resolve().parent.parent / "nlp.yaml",
        score_threshold=THRESHOLD,
        enable_pl_recognizers=True,
        vault=vault,
    )


def detected(engine, text):
    results = engine.analyzer.analyze(text=text, language="en", score_threshold=THRESHOLD)
    return {(r.entity_type, text[r.start : r.end]) for r in results}


@pytest.mark.parametrize(
    "text, value",
    [
        ("Zadzwoń na +48 728 934 610 jutro", "+48 728 934 610"),
        ("numer 0048728934610 jest aktywny", "0048728934610"),
        ("biuro: +48 22 123 45 67", "+48 22 123 45 67"),
        ("ja Kamil o numerze telefonu 728934610", "728934610"),
        ("tel. 728-934-610", "728-934-610"),
        ("komórka 728 934 610", "728 934 610"),
        ("tel. stacjonarny (22) 123-45-67", "(22) 123-45-67"),
    ],
)
def test_polish_phone_numbers_are_detected(engine, text, value):
    assert ("PHONE_NUMBER", value) in detected(engine, text)


@pytest.mark.parametrize(
    "text",
    [
        "zamówienie 728934610 wysłane",
        "zamówienie nr 728934610 wysłane",
        "sesja 20261021_205723_093991 zakończona",
        "kwota 728 934 610 zł",
    ],
)
def test_bare_nine_digit_numbers_without_phone_context_are_not_phones(engine, text):
    assert not {entity for entity, _ in detected(engine, text)} & {"PHONE_NUMBER"}


def test_pesel_with_valid_checksum_is_detected(engine):
    assert ("PL_PESEL", "44051401359") in detected(engine, "PESEL 44051401359")


def test_pesel_with_invalid_checksum_is_ignored(engine):
    assert "PL_PESEL" not in {e for e, _ in detected(engine, "PESEL 44051401358")}


def test_pesel_is_not_carved_out_of_longer_numbers(engine):
    assert "PL_PESEL" not in {e for e, _ in detected(engine, "id 9944051401359")}


@pytest.mark.parametrize(
    "text, value",
    [
        ("NIP 1234563218", "1234563218"),
        ("NIP: 123-456-32-18", "123-456-32-18"),
        ("nip 123-45-63-218", "123-45-63-218"),
        ("VAT UE PL1234563218", "PL1234563218"),
    ],
)
def test_nip_with_valid_checksum_is_detected(engine, text, value):
    assert ("PL_NIP", value) in detected(engine, text)


def test_nip_with_invalid_checksum_is_ignored(engine):
    assert "PL_NIP" not in {e for e, _ in detected(engine, "NIP 1234563219")}


def test_plain_ten_digit_number_without_context_is_not_nip(engine):
    # Valid NIP checksum, but looks like any other ID or unix timestamp.
    assert "PL_NIP" not in {e for e, _ in detected(engine, "timestamp 1234563218")}


def test_id_card_with_valid_checksum_and_context_is_detected(engine):
    assert ("PL_ID_CARD", "ABA300000") in detected(engine, "dowód osobisty ABA300000")


def test_id_card_with_invalid_checksum_is_ignored(engine):
    assert "PL_ID_CARD" not in {e for e, _ in detected(engine, "dowód osobisty ABA300001")}


def test_sanitize_aliases_polish_identifiers_and_rehydrates(engine):
    source = "tel. 728934610, PESEL 44051401359, NIP 123-456-32-18"
    sanitized = engine.sanitize(source)
    for raw in ("728934610", "44051401359", "123-456-32-18"):
        assert raw not in sanitized
    assert engine.rehydrate(sanitized) == source


def test_polish_recognizers_are_opt_in():
    key = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode()
    vault = AliasVault(connection=sqlite3.connect(":memory:"), encoded_key=key)
    default_engine = PrivacyEngine(
        Path(__file__).resolve().parent.parent / "nlp.yaml", vault=vault
    )
    names = {r.name for r in default_engine.analyzer.registry.recognizers}
    assert "PlPhoneRecognizer" not in names
