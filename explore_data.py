import pandas as pd

# Load dataset - rockyou has encoding issues so we handle errors
with open('data/rockyou.txt', 'r', encoding='utf-8', errors='ignore') as f:
    passwords = f.read().splitlines()

print(f"Total passwords loaded: {len(passwords)}")
print(f"\nFirst 10 entries:")
for p in passwords[:10]:
    print(repr(p))

print(f"\nShortest password length: {min(len(p) for p in passwords if p)}")
print(f"Longest password length:  {max(len(p) for p in passwords if p)}")

# Length distribution sample
lengths = [len(p) for p in passwords if p]
avg = sum(lengths) / len(lengths)
print(f"Average password length:  {avg:.2f}")