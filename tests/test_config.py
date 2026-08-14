"""Regression tests for environment parsing."""

from config import _int_env


def test_int_env_parses_valid_integer(monkeypatch):
    monkeypatch.setenv("TEST_INTEGER_SETTING", "2525")
    assert _int_env("TEST_INTEGER_SETTING", 10) == 2525


def test_int_env_falls_back_for_invalid_integer(monkeypatch):
    monkeypatch.setenv("TEST_INTEGER_SETTING", "invalid")
    assert _int_env("TEST_INTEGER_SETTING", 10) == 10
