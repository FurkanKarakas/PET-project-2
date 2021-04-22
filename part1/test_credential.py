"""
Unit tests for the credential module for implementing PS credentials
"""

from credential import SecretKey, PublicKey, Signature, PSScheme
import os

def test_scheme():
    # Generate random messages
    msgs = [os.urandom(128) for i in range(100)]

    # Generate keys
    sk, pk = PSScheme.generate_keys(msgs)

    # Sign messages
    signature = PSScheme.sign(sk, msgs)

    # Verify signature
    assert PSScheme.verify(pk, signature, msgs)
