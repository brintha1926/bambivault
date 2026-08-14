"""Shared Random Forest password-strength classifier."""
import joblib
import numpy as np

ML_MODEL = joblib.load('model/strength_model_rf_v3.pkl')

FEATURE_ORDER = [
    'length', 'num_upper', 'num_lower', 'num_digits', 'num_special',
    'entropy', 'has_keyboard_walk', 'has_year', 'has_common_sub', 'has_dict_word'
]

STRENGTH_LABELS = ['Very Weak', 'Weak', 'Medium', 'Strong', 'Very Strong']


def classify_strength(feats: dict) -> tuple[int, str, float]:
    vector = np.array([[feats[k] for k in FEATURE_ORDER]])
    score = int(ML_MODEL.predict(vector)[0])
    label = STRENGTH_LABELS[score]
    probabilities = ML_MODEL.predict_proba(vector)[0]
    confidence = round(float(probabilities[score]) * 100, 1)
    return score, label, confidence
