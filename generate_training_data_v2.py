import csv
import pandas as pd
from feature_extraction import extract_features

print("Loading frequency table...")
freq_df = pd.read_csv('data/password_frequency.csv')
freq_lookup = dict(zip(freq_df['password'], freq_df['freq_count']))

INPUT_FILE  = 'data/rockyou_clean.txt'
OUTPUT_FILE = 'data/training_data_v2.csv'

FIELDNAMES = ['length','num_upper','num_lower','num_digits','num_special',
              'entropy','has_keyboard_walk','has_year','has_common_sub',
              'has_dict_word','label']

def freq_to_label(freq_count):
    """
    Label derived ONLY from real-world frequency in the breach corpus.
    This value is NOT one of the 10 input features, so the model
    genuinely has to learn the relationship from password structure.
    """
    if freq_count >= 1000:
        return 0   # Very Weak — extremely common, seen 1000+ times
    elif freq_count >= 100:
        return 1   # Weak
    elif freq_count >= 10:
        return 2   # Medium
    elif freq_count >= 2:
        return 3   # Strong — seen only a couple times
    else:
        return 4   # Very Strong — completely unique in the leak

def main():
    with open(INPUT_FILE, 'r', encoding='utf-8', errors='ignore') as f:
        passwords = f.read().splitlines()

    total_unique = len(set(passwords))
    print(f"Processing {len(passwords)} passwords...")

    with open(OUTPUT_FILE, 'w', newline='', encoding='utf-8') as out:
        writer = csv.DictWriter(out, fieldnames=FIELDNAMES)
        writer.writeheader()

        for i, pw in enumerate(passwords):
            if not pw:
                continue
            feats = extract_features(pw)
            freq_count = freq_lookup.get(pw, 1)
            label = freq_to_label(freq_count)

            row = {k: feats[k] for k in FIELDNAMES if k in feats}
            row['label'] = label
            writer.writerow(row)

            if i % 500000 == 0:
                print(f"  {i:,} processed...")

    print("Done. Saved to", OUTPUT_FILE)

if __name__ == '__main__':
    main()