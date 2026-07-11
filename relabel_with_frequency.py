import pandas as pd
from collections import Counter

print("Loading raw passwords...")
with open('data/rockyou.txt', 'r', encoding='utf-8', errors='ignore') as f:
    passwords = f.read().splitlines()

print(f"Counting frequency of {len(passwords):,} passwords...")
freq = Counter(passwords)

# Save frequency lookup for later use
freq_df = pd.DataFrame(freq.items(), columns=['password', 'freq_count'])
freq_df.to_csv('data/password_frequency.csv', index=False)
print("Saved frequency table to data/password_frequency.csv")
print(freq_df['freq_count'].describe())