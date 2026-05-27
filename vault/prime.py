import secrets

def is_prime(n):     # Check if a number is prime
    if n < 2:
        return False
    if n == 2:
        return True
    if n % 2 == 0:
        return False
    for i in range(3, int(n**0.5) + 1, 2):     # Check for factors from 3 to the square root of n
        if n % i == 0:
            return False
    return True

def generate_prime(min_value=1000000000, max_value=9999999999): # Generate prime number within the range
    while True:
        candidate = secrets.randbelow(max_value - min_value) + min_value
        if candidate % 2 != 0 and is_prime(candidate):  # Ensure the candidate is odd and prime
            return candidate

def checksum(token):          # Calculate the checksum by summing the digits of the token
    return sum(int(d) for d in str(token))

def verify_token(token, prime):      # Verify if the checksum of the token is divisible by the prime number
    return checksum(token) % prime == 0