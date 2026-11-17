"""The REQUIRE_REAL_DATA switch (decision 053 item 3): a missing real-data input skips by default and fails when required."""
from __future__ import annotations

import pytest

import real_data


@pytest.mark.parametrize("value", ["1", "true", "TRUE", "Yes", "on", " 1 "])
def test_required_for_true_like_values(monkeypatch, value):
    monkeypatch.setenv(real_data.ENV_VAR, value)
    assert real_data.required() is True


@pytest.mark.parametrize("value", [None, "", "0", "false", "no", "off", "2", "maybe"])
def test_not_required_by_default_or_for_other_values(monkeypatch, value):
    if value is None:
        monkeypatch.delenv(real_data.ENV_VAR, raising=False)
    else:
        monkeypatch.setenv(real_data.ENV_VAR, value)
    assert real_data.required() is False


def test_missing_input_skips_when_not_required(monkeypatch):
    monkeypatch.delenv(real_data.ENV_VAR, raising=False)
    with pytest.raises(pytest.skip.Exception) as ei:
        real_data.missing_input("data/processed/x.sqlite3 missing")
    assert "x.sqlite3" in str(ei.value)


def test_missing_input_fails_when_required_and_names_the_input(monkeypatch):
    monkeypatch.setenv(real_data.ENV_VAR, "1")
    with pytest.raises(pytest.fail.Exception) as ei:
        real_data.missing_input("data/processed/x.sqlite3 missing")
    assert "REQUIRE_REAL_DATA=1" in str(ei.value) and "x.sqlite3" in str(ei.value)


def test_missing_input_never_returns_in_an_expression(monkeypatch):
    """The call sites use it inside conditional expressions (`x if ok else missing_input(..)`), so it must raise."""
    monkeypatch.delenv(real_data.ENV_VAR, raising=False)
    with pytest.raises(pytest.skip.Exception):
        _ = 1 if False else real_data.missing_input("db missing")
