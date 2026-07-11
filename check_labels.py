import pandas as pd

df = pd.read_csv('data/training_data_v3.csv')
print("Label distribution:")
print(df['label'].value_counts().sort_index())

print("\nAs percentages:")
print((df['label'].value_counts(normalize=True).sort_index() * 100).round(2))