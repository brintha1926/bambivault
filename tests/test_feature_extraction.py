"""Focused edge cases for password feature extraction."""

from feature_extraction import extract_features


def test_unicode_emoji_password_is_supported():
    result = extract_features("😊😍🔥")

    assert result["length"] == 3
    assert isinstance(result["entropy"], float)
    assert result["entropy"] >= 0
    assert isinstance(result["flags"], list)
