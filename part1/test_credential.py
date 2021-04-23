"""
Unit tests for the credential module for implementing PS credentials
"""

from credential import *
import os
import random

def test_scheme():
    # Generate random messages
    msgs = [os.urandom(128) for i in range(100)]

    # Generate keys
    sk, pk = PSScheme.generate_keys(msgs)

    # Sign messages
    signature = PSScheme.sign(sk, msgs)

    # Verify signature
    assert PSScheme.verify(pk, signature, msgs)

def test_fiat_shamir():
    # Generate random messages
    msgs = [os.urandom(128) for i in range(100)]

    # Generate keys
    sk, pk = PSScheme.generate_keys(msgs)

    g = G1.generator()
    exponents = [random.randint(100,1000) for _ in range(100)]

    t = G1.order().random()
    C = pk.g1 ** t
    for Y1_i, a_i in zip(pk.Y1, exponents):
        C *= Y1_i ** a_i

    proof = FiatShamirProof(
        [pk.g1] + pk.Y1,
        [t] + exponents,
        C, pk )

    assert(proof.verify(C, pk))