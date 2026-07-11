import csv
from feature_extraction import extract_features, rule_based_strength

INPUT_FILE  = 'data/rockyou_clean.txt'
OUTPUT_FILE = 'data/training_data.csv'

FIELDNAMES = ['length','num_upper','num_lower','num_digits','num_special',
              'entropy','has_keyboard_walk','has_year','has_common_sub',
              'has_dict_word','label']

def main():
    with open(INPUT_FILE, 'r', encoding='utf-8', errors='ignore') as f:
        passwords = f.read().splitlines()

    print(f"Processing {len(passwords)} passwords...")

    with open(OUTPUT_FILE, 'w', newline='', encoding='utf-8') as out:
        writer = csv.DictWriter(out, fieldnames=FIELDNAMES)
        writer.writeheader()

        for i, pw in enumerate(passwords):
            if not pw:
                continue
            feats = extract_features(pw)
            score, label = rule_based_strength(feats)
            row = {k: feats[k] for k in FIELDNAMES if k in feats}
            row['label'] = score   # 0–4 numeric label
            writer.writerow(row)

            if i % 500000 == 0:
                print(f"  {i:,} processed...")

    print("Done. Saved to", OUTPUT_FILE)

if __name__ == '__main__':
    main()