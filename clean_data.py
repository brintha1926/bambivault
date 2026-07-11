import pandas as pd

# Load
with open('data/rockyou.txt', 'r', encoding='utf-8', errors='ignore') as f:
    passwords = f.read().splitlines()

print(f"Before cleaning: {len(passwords)} passwords")

# Remove blanks
passwords = [p for p in passwords if p]

# Remove duplicates
passwords = list(set(passwords))
print(f"After removing duplicates: {len(passwords)} passwords")

# Remove passwords shorter than 4 or longer than 30 characters
passwords = [p for p in passwords if 4 <= len(p) <= 30]
print(f"After length filtering (4-30 chars): {len(passwords)} passwords")

# Remove non-ASCII
passwords = [p for p in passwords if p.isascii()]
print(f"After removing non-ASCII: {len(passwords)} passwords")

# Save cleaned version
with open('data/rockyou_clean.txt', 'w', encoding='utf-8') as f:
    f.write('\n'.join(passwords))

print("Saved to data/rockyou_clean.txt")