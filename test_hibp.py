import hashlib
import requests

def check_breach(password):
    sha1 = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix = sha1[:5]
    suffix = sha1[5:]

    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    response = requests.get(url, headers={'Add-Padding': 'true'})

    if response.status_code != 200:
        return None, "API unavailable"

    hashes = response.text.splitlines()
    for line in hashes:
        h, count = line.split(':')
        if h == suffix:
            return True, int(count)
    return False, 0

# Test with known breached and safe passwords
test_cases = ['123456', 'password', 'qwerty', 'Xk9#mLp2$vQ!']

for pw in test_cases:
    found, count = check_breach(pw)
    if found:
        print(f"'{pw}' — BREACHED ({count:,} times)")
    else:
        print(f"'{pw}' — Not found in breaches")