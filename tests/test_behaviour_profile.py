"""Behavioural-profile priority and classifier-output tests."""

import pytest
from feature_extraction import extract_features


def test_clean_password_has_no_flags():
    feats = extract_features("Xk9#mLp2vQ7z")
    assert feats["flags"] == ["none_detected"]
    assert feats["has_keyboard_walk"] == 0
    assert feats["has_year"] == 0
    assert feats["has_common_sub"] == 0
    assert feats["has_dict_word"] == 0


def test_keyboard_walk_detected():
    feats = extract_features("qwerty12345")
    assert feats["has_keyboard_walk"] == 1
    assert "keyboard_walk" in feats["flags"]


def test_year_pattern_detected():
    feats = extract_features("Summer2024")
    assert feats["has_year"] == 1
    assert "name_year_combo" in feats["flags"]


def test_dict_word_detected():
    feats = extract_features("password99")
    assert feats["has_dict_word"] == 1
    assert "dict_word" in feats["flags"]


def test_entropy_is_zero_for_empty_string():
    feats = extract_features("")
    assert feats["entropy"] == 0.0
    assert feats["length"] == 0


def test_entropy_increases_with_character_diversity():
    """A password using more distinct characters should have entropy >=
    one repeating a single character, all else equal."""
    low_entropy = extract_features("aaaaaaaa")
    high_entropy = extract_features("aB3$xZ9!")
    assert high_entropy["entropy"] > low_entropy["entropy"]


def test_classify_behaviour_profile_priority_order(app_module):
    """Locks in the documented priority: keyboard_walk > year > sub > dict_word > Clean."""
    classify = app_module.classify_behaviour_profile

    # A password that could match BOTH keyboard_walk and year should
    # resolve to Keyboard-Walk Type per the if/elif order in app.py.
    feats = extract_features("qwerty2024")
    assert classify(feats) == "Keyboard-Walk Type"

    feats_year_only = extract_features("Summer2024")
    assert classify(feats_year_only) == "Name+Year Type"

    feats_clean = extract_features("Xk9#mLp2vQ7z")
    assert classify(feats_clean) == "Clean"


def test_classify_strength_returns_expected_shape(app_module):
    """Uses the stubbed model (see conftest._StubModel) — verifies the
    plumbing (feature vector ordering, predict_proba indexing) works,
    not the real model's accuracy."""
    feats = extract_features("Xk9#mLp2vQ7z")
    score, label, confidence = app_module.classify_strength(feats)

    assert isinstance(score, int)
    assert label in app_module.STRENGTH_LABELS
    assert 0.0 <= confidence <= 100.0


def test_overall_recommendations_prioritise_breaches_and_patterns(app_module):
    recommendations = app_module._generate_user_overall_recommendations(
        total=4,
        breached=1,
        avg_entropy=42.0,
        distribution=[
            {'label': 'Weak', 'count': 2},
            {'label': 'Strong', 'count': 2},
        ],
        top_patterns=[('keyboard_walk', 2)],
    )

    assert 1 <= len(recommendations) <= 3
    assert 'known breaches' in recommendations[0]
    assert any('keyboard walk' in item for item in recommendations)


def test_overall_recommendations_handle_empty_history(app_module):
    recommendations = app_module._generate_user_overall_recommendations(
        total=0,
        breached=0,
        avg_entropy=0,
        distribution=[],
        top_patterns=[],
    )

    assert len(recommendations) == 1
    assert 'Analyse a password first' in recommendations[0]
