"""Polish PII recognizers for the analyzer's own language registry.

Presidio ships its Polish recognizers for the ``pl`` registry only, while this
plugin analyzes mixed Polish/English text with a single (``en``) registry, so
Polish identifiers were silently skipped. These recognizers are registered for
whatever language the engine runs with.

Checksum-bearing identifiers keep their pattern score when the checksum holds
(instead of Presidio's default jump to 1.0) so that a random number that
happens to pass a mod-10/mod-11 check still needs a context word ("NIP",
"tel", "dowód") to cross the score threshold.
"""

from __future__ import annotations

from typing import Optional

from presidio_analyzer import Pattern, PatternRecognizer
from presidio_analyzer.predefined_recognizers import PlPeselRecognizer as _PresidioPesel

# Identifiers must not be carved out of longer tokens such as Hermes session
# IDs, hashes, or millisecond timestamps.
_START = r"(?<![\w+])"
_END = r"(?!\w)"
_SEP = r"[ -]?"


class PlPhoneRecognizer(PatternRecognizer):
    """Polish mobile and landline numbers.

    A +48/0048 prefix is a strong signal on its own. A bare nine-digit number
    is not (order, invoice, and task IDs look the same), so it only crosses
    the default threshold next to a context word.
    """

    PATTERNS = [
        Pattern(
            "PL_PHONE_INTL_MOBILE",
            _START + r"(?:\+|00)48" + _SEP + r"\d{3}" + _SEP + r"\d{3}" + _SEP + r"\d{3}" + _END,
            0.85,
        ),
        Pattern(
            "PL_PHONE_INTL_LANDLINE",
            _START + r"(?:\+|00)48" + _SEP + r"\(?\d{2}\)?" + _SEP + r"\d{3}" + _SEP + r"\d{2}" + _SEP + r"\d{2}" + _END,
            0.85,
        ),
        Pattern(
            "PL_PHONE_MOBILE",
            _START + r"\d{3}" + _SEP + r"\d{3}" + _SEP + r"\d{3}" + _END,
            0.4,
        ),
        Pattern(
            "PL_PHONE_LANDLINE",
            r"(?<![\w+(])\(?\d{2}\)?[ -]\d{3}[ -]\d{2}[ -]\d{2}" + _END,
            0.3,
        ),
    ]

    # Presidio matches context words as case-insensitive substrings of the
    # surrounding tokens, so "tel" also covers "telefonu"/"telefonem". "nr" and
    # "numer" are left out on purpose: "zamówienie nr 123456789" is not a phone.
    CONTEXT = ["tel", "komórk", "komork", "phone", "mobile", "sms", "whatsapp"]

    def __init__(self, supported_language: str = "en", name: Optional[str] = None) -> None:
        super().__init__(
            supported_entity="PHONE_NUMBER",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
            supported_language=supported_language,
            name=name or "PlPhoneRecognizer",
        )


class PlPeselTokenRecognizer(_PresidioPesel):
    """Presidio's PESEL checksum recognizer, bounded to whole tokens.

    Named differently from the parent on purpose: Presidio's YAML registry
    loader resolves predefined recognizers by class name across subclasses.
    """

    PATTERNS = [
        Pattern(
            "PESEL",
            _START + r"[0-9]{2}([02468][1-9]|[13579][012])(0[1-9]|1[0-9]|2[0-9]|3[01])[0-9]{5}" + _END,
            0.4,
        ),
    ]

    CONTEXT = ["pesel"]

    def __init__(self, supported_language: str = "en", name: Optional[str] = None) -> None:
        super().__init__(
            patterns=self.PATTERNS,
            context=self.CONTEXT,
            supported_language=supported_language,
            name=name or "PlPeselTokenRecognizer",
        )


class PlNipRecognizer(PatternRecognizer):
    """Polish tax ID (NIP), plain or in the common dashed groupings."""

    PATTERNS = [
        Pattern(
            "NIP_PREFIXED",
            _START + r"PL" + _SEP + r"\d{10}" + _END,
            0.6,
        ),
        Pattern(
            "NIP_DASHED",
            _START + r"(?:\d{3}-\d{3}-\d{2}-\d{2}|\d{3}-\d{2}-\d{2}-\d{3})" + _END,
            0.6,
        ),
        Pattern(
            "NIP_PLAIN",
            _START + r"\d{10}" + _END,
            0.3,
        ),
    ]

    CONTEXT = ["nip", "vat", "tax", "podatk"]

    _WEIGHTS = (6, 5, 7, 2, 3, 4, 5, 6, 7)

    def __init__(self, supported_language: str = "en", name: Optional[str] = None) -> None:
        super().__init__(
            supported_entity="PL_NIP",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
            supported_language=supported_language,
            name=name or "PlNipRecognizer",
        )

    def validate_result(self, pattern_text: str) -> Optional[bool]:
        digits = [int(char) for char in pattern_text if char.isdigit()]
        if len(digits) != 10:
            return False
        check = sum(d * w for d, w in zip(digits, self._WEIGHTS)) % 11
        # None keeps the pattern score; see the module docstring.
        return None if check == digits[9] else False


class PlIdCardRecognizer(PatternRecognizer):
    """Polish identity card number (three letters, six digits, checksum)."""

    PATTERNS = [
        Pattern(
            "PL_ID_CARD",
            _START + r"[A-Z]{3} ?\d{6}" + _END,
            0.4,
        ),
    ]

    CONTEXT = ["dowód", "dowod", "osobist", "seria", "id card", "identity"]

    _WEIGHTS = (7, 3, 1, 9, 7, 3, 1, 7, 3)

    def __init__(self, supported_language: str = "en", name: Optional[str] = None) -> None:
        super().__init__(
            supported_entity="PL_ID_CARD",
            patterns=self.PATTERNS,
            context=self.CONTEXT,
            supported_language=supported_language,
            name=name or "PlIdCardRecognizer",
        )

    def validate_result(self, pattern_text: str) -> Optional[bool]:
        chars = pattern_text.replace(" ", "")
        if len(chars) != 9:
            return False
        values = [ord(c) - ord("A") + 10 if c.isalpha() else int(c) for c in chars]
        # The check digit sits at position 4 with weight 9, so a valid number
        # sums to a multiple of 10.
        total = sum(v * w for v, w in zip(values, self._WEIGHTS))
        return None if total % 10 == 0 else False


def polish_recognizers(language: str) -> list[PatternRecognizer]:
    return [
        PlPhoneRecognizer(supported_language=language),
        PlPeselTokenRecognizer(supported_language=language),
        PlNipRecognizer(supported_language=language),
        PlIdCardRecognizer(supported_language=language),
    ]
