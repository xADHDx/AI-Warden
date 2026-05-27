import secrets
import blake3

def is_prime(n):
    # Check if a number is prime
    if n < 2:
        return False
    if n == 2:
        return True
    if n % 2 == 0:
        return False
    for i in range(3, int(n**0.5) + 1, 2):
        # Check for factors from 3 to the square root of n
        if n % i == 0:
            return False
    return True

def generate_prime(min_value=1000000000, max_value=9999999999):
    # Generate a cryptographically random 10-digit prime
    while True:
        candidate = secrets.randbelow(max_value - min_value) + min_value
        # Ensure the candidate is odd and prime before returning
        if candidate % 2 != 0 and is_prime(candidate):
            return candidate

def checksum(token, prime):
    # BLAKE3 keyed hash using session prime as key
    # produces cryptographically strong verification
    key = str(prime).zfill(32).encode()[:32]  # 32-byte key from prime
    return blake3.blake3(str(token).encode(), key=key).hexdigest()

def verify_token(token, prime, expected_hash):
    # Verify token against its stored BLAKE3 hash
    return checksum(token, prime) == expected_hash