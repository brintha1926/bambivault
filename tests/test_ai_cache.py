import ai_feedback


def test_ai_cache_round_trip(monkeypatch, tmp_path):
    monkeypatch.setattr(ai_feedback, 'CACHE_DB_PATH', str(tmp_path / 'ai-cache.db'))
    ai_feedback._set_cache('key', ['Use a longer unique passphrase.'])
    assert ai_feedback._get_cache('key') == ['Use a longer unique passphrase.']


def test_ai_cache_key_includes_material_metrics():
    breach = {'risk_label': 'Critical', 'breach_count': 50}
    first = ai_feedback._make_cache_key('Weak', 1, 'Clean', [], 2.0, 8, breach)
    second = ai_feedback._make_cache_key('Weak', 1, 'Clean', [], 3.0, 16, breach)
    assert first != second
