import pandas as pd
import joblib
import time
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report

print("Loading data...")
t0 = time.time()
df = pd.read_csv('data/training_data_v3.csv')
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
    n_estimators=100,
    max_depth=15,
    min_samples_leaf=5,
    n_jobs=2,
    random_state=42,
    verbose=2,
    class_weight='balanced'
)
rf.fit(X_train, y_train)
print(f"Training took {time.time()-t0:.1f}s")

print("Evaluating...")
y_pred = rf.predict(X_test)
test_acc = accuracy_score(y_test, y_pred)
print(f"Test accuracy: {test_acc:.4f}")
print(classification_report(y_test, y_pred,
      labels=[0,1,2,3,4],
      target_names=['Very Weak','Weak','Medium','Strong','Very Strong'],
      zero_division=0))

joblib.dump(rf, 'model/strength_model_rf_v3.pkl')
print("Saved model as model/strength_model_rf_v3.pkl")