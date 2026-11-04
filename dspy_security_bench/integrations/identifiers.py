"""Shared syntax checks for generated/imported Python target identifiers."""

from __future__ import annotations

import keyword
import re
import unicodedata

MAX_TARGET_CHARACTERS = 256


def valid_module(value: object) -> bool:
    return (isinstance(value, str) and 1 <= len(value) <= MAX_TARGET_CHARACTERS
            and re.fullmatch(r"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*", value) is not None
            and all(part.isidentifier() and not keyword.iskeyword(part)
                    and unicodedata.normalize("NFKC", part) == part for part in value.split(".")))


def valid_target(value: object) -> bool:
    if not isinstance(value, str) or len(value) > MAX_TARGET_CHARACTERS or value.count(":") != 1:
        return False
    module, function = value.split(":")
    return valid_module(module) and "." not in function and valid_module(function)
