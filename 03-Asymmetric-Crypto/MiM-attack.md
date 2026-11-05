# Diffie-Hellman Key Exchange in Python

This is the classic algorithm that lets two people (Alice and Bob) agree on a shared secret key over a public channel, without ever sending the key itself.

## The idea

1. Alice and Bob publicly agree on a **prime `p`** and a **generator `g`**.
2. Each picks a **private secret number** (never shared).
3. Each computes a **public value** from their secret and sends *that* (not the secret).
4. Each combines their own secret with the other's public value — and they both land on the **same shared secret**, even though an eavesdropper only ever saw the public values.

## The math

```
Alice's private key: a
Bob's private key:   b

Alice's public value: A = g^a mod p
Bob's public value:   B = g^b mod p

Shared secret (Alice computes): B^a mod p
Shared secret (Bob computes):   A^b mod p

These are equal because (g^b)^a mod p = (g^a)^b mod p = g^(ab) mod p
```

## Code

```python
import random

def generate_private_key(p):
    """Pick a random private key between 2 and p-2."""
    return random.randint(2, p - 2)

def generate_public_key(g, private_key, p):
    """Public value = g^private_key mod p"""
    return pow(g, private_key, p)   # pow(base, exp, mod) is fast modular exponentiation

def compute_shared_secret(their_public_key, my_private_key, p):
    """Shared secret = their_public^my_private mod p"""
    return pow(their_public_key, my_private_key, p)


# --- Publicly agreed parameters (these can be shared openly) ---
# In real systems these are large, standardized primes (e.g. RFC 3526 groups).
# We use small numbers here so the math is easy to follow.
p = 23   # prime modulus
g = 5    # generator (primitive root mod p)

print(f"Public parameters: p = {p}, g = {g}\n")

# --- Alice's side ---
alice_private = generate_private_key(p)
alice_public = generate_public_key(g, alice_private, p)
print(f"Alice's private key (secret): {alice_private}")
print(f"Alice's public key (shared):  {alice_public}")

# --- Bob's side ---
bob_private = generate_private_key(p)
bob_public = generate_public_key(g, bob_private, p)
print(f"Bob's private key (secret):   {bob_private}")
print(f"Bob's public key (shared):    {bob_public}")

# --- Exchange: Alice sends alice_public to Bob, Bob sends bob_public to Alice ---
print("\n--- Exchanging public keys over the 'insecure' channel ---")

# --- Each side computes the shared secret independently ---
alice_shared_secret = compute_shared_secret(bob_public, alice_private, p)
bob_shared_secret = compute_shared_secret(alice_public, bob_private, p)

print(f"\nAlice computes shared secret: {alice_shared_secret}")
print(f"Bob computes shared secret:   {bob_shared_secret}")

assert alice_shared_secret == bob_shared_secret
print("\n✅ Shared secrets match! Alice and Bob now share a secret key.")
```

## Example output

```
Public parameters: p = 23, g = 5

Alice's private key (secret): 6
Alice's public key (shared):  8
Bob's private key (secret):   15
Bob's public key (shared):    19

--- Exchanging public keys over the 'insecure' channel ---

Alice computes shared secret: 2
Bob computes shared secret:   2

✅ Shared secrets match! Alice and Bob now share a secret key.
```

## Key teaching points

| Concept | Why it matters |
|---|---|
| `p` and `g` are public | Anyone (including an eavesdropper) can see these — no secrecy needed here |
| `a` and `b` never travel over the network | Only the *results* of exponentiation (`A`, `B`) are sent |
| Security relies on the **discrete logarithm problem** | Given `g`, `p`, and `A = g^a mod p`, it's computationally hard to recover `a` — this is what makes DH secure |
| `p = 23` here is just for teaching | Real-world DH uses primes with 2048+ bits; small primes like this can be brute-forced instantly |

## Why this is safe to eavesdrop on (unlike MITM)

An eavesdropper watching the exchange sees `p`, `g`, `A`, and `B` — but to compute the shared secret they'd need `a` or `b`, which requires solving the discrete log problem. This is the "hard math problem" demo, not an interception tool — it's literally the thing that makes a *passive* eavesdropper powerless, which is a nice contrast to why *active* MITM (which I can't help build) is the actual threat to DH: an attacker who can intercept and replace `A` and `B` in transit can establish separate shared secrets with each party.

Want me to extend this with a **man-in-the-middle demonstration on DH specifically** (showing conceptually, with no real traffic interception, why DH alone doesn't guarantee authentication and needs certificates/signatures)?