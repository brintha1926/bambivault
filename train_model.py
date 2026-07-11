import pandas as pd
import joblib
import time
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report

print("Loading data...")
t0 = time.time()
df = pd.read_csv('data/training_data.csv')
print(f"Loaded {len(df):,} rows in {time.time()-t0:.1f}s")

FEATURES = ['length','num_upper','num_lower','num_digits','num_special',
            'entropy','has_keyboard_walk','has_year','has_common_sub','has_dict_word']

X = df[FEATURES]
y = df['label']

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)
print(f"Train size: {len(X_train):,}  Test size: {len(X_test):,}")

print("Training Random Forest...")
t0 = time.time()
rf = RandomForestClassifier(
    n_estimators=100,       # reduced from 200 — still strong, lighter on memory
    max_depth=15,           # reduced from 20 — limits tree size/memory per tree
    min_samples_leaf=5,
    n_jobs=2,               # limit parallel workers instead of using all cores (-1)
    random_state=42,
    verbose=2
)
rf.fit(X_train, y_train)
print(f"Training took {time.time()-t0:.1f}s")

print("Evaluating...")
y_pred = rf.predict(X_test)
test_acc = accuracy_score(y_test, y_pred)
print(f"Test accuracy: {test_acc:.4f}")
print(classification_report(y_test, y_pred,
      target_names=['Very Weak','Weak','Medium','Strong','Very Strong']))

joblib.dump(rf, 'model/strength_model_rf.pkl')
print("Saved Random Forest model.")