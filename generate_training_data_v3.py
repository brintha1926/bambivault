import csv
import random
from feature_extraction import extract_features

random.seed(42)

INPUT_FILE       = 'data/rockyou_clean.txt'
COMMON_LIST_FILE = 'data/top_10k_common.txt'
OUTPUT_FILE      = 'data/training_data_v3.csv'

FIELDNAMES = ['length', 'num_upper', 'num_lower', 'num_digits', 'num_special',
              'entropy', 'has_keyboard_walk', 'has_year', 'has_common_sub',
              'has_dict_word', 'label']


def load_common_set(path):
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        return set(line.strip().lower() for line in f if line.strip())


def char_class_count(pw):
    """How many of the 4 character classes are present."""
    classes = 0
    if any(c.islower() for c in pw): classes += 1
    if any(c.isupper() for c in pw): classes += 1
    if any(c.isdigit() for c in pw): classes += 1
    if any(not c.isalnum() for c in pw): classes += 1
    return classes


def assign_label(password, feats, common_set):
    pw_lower = password.lower()

    # Signal 1: external public weak-password list
    if pw_lower in common_set:
        return 0 if random.random() < 0.85 else 1

    # Signal 2: coarse length + character-class tiers
    length  = len(password)
    classes = char_class_count(password)

    # Base tier from length
    if length < 6:
        base = 0
    elif length < 8:
        base = 1
    elif length < 11:
        base = 2
    elif length < 14:
        base = 3
    else:
        base = 4

    # Adjust by character class diversity
    if classes <= 1:
        base -= 1
    elif classes >= 4:
        base += 1

    # Controlled random jitter at boundaries (~20% of the time)
    if random.random() < 0.20:
        base += random.choice([-1, 1])

    return max(0, min(4, base))


def main():
    print("Loading public common-password list...")
    common_set = load_common_set(COMMON_LIST_FILE)
    print(f"Loaded {len(common_set):,} known-weak passwords for reference.")

    print("Loading RockYou cleaned passwords...")
    with open(INPUT_FILE, 'r', encoding='utf-8', errors='ignore') as f:
        passwords = f.read().splitlines()
    print(f"Processing {len(passwords):,} passwords...")

    with open(OUTPUT_FILE, 'w', newline='', encoding='utf-8') as out:
        writer = csv.DictWriter(out, fieldnames=FIELDNAMES)
        writer.writeheader()

        for i, pw in enumerate(passwords):
            if not pw:
                continue
            feats = extract_features(pw)
            label = assign_label(pw, feats, common_set)

            row = {k: feats[k] for k in FIELDNAMES if k in feats}
            row['label'] = label
            writer.writerow(row)

            if i % 1000000 == 0:
                print(f"  {i:,} processed...")

    print("Done. Saved to", OUTPUT_FILE)


if __name__ == '__main__':
    main()