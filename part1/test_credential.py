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
    exponents = [random.randint(100, 1000) for _ in range(100)]

    t = G1.order().random()
    C = pk.g1 ** t
    for Y1_i, a_i in zip(pk.Y1, exponents):
        C *= Y1_i ** a_i

    # Check that verification passes on correct proof
    proof = FiatShamirProof(
        C, pk, G1,
        [pk.g1] + pk.Y1,
        [t] + exponents)

    assert proof.verify(C, pk)

    # Check that verification fails on wrong C
    assert not proof.verify(C**2, pk)


def test_protocol_run():
    N = 10
    # Generate random messages
    attributes = [os.urandom(128) for i in range(N)]

    # Get random indices for user and issuer attributes
    possible_indices = set(range(N))
    user_indices = set(random.sample(possible_indices, N//2))
    issuer_indices = possible_indices - user_indices

    # Get attribute maps
    user_attributes = {i: attributes[i] for i in user_indices}
    issuer_attributes = {i: attributes[i] for i in issuer_indices}

    # Choose which attributes should be revealed to verifyer
    disclosed_indices = set(random.sample(possible_indices, N//2))
    hidden_indices = possible_indices - disclosed_indices
    disclosed_attributes = {i: attributes[i] for i in disclosed_indices}
    hidden_attributes = {i: attributes[i] for i in hidden_indices}

    # Generate keys
    sk, pk = PSScheme.generate_keys(attributes)

    # Get issue request as well as the state t which we need for later
    request, t = ABCIssue.create_issue_request(pk, user_attributes)

    response = ABCIssue.sign_issue_request(sk, pk, request, issuer_attributes)

    credential = ABCIssue.obtain_credential(pk, response, t)

    message = os.urandom(128)
    disclosure_proof = ABCVerify.create_disclosure_proof(
        pk, credential, hidden_attributes, disclosed_attributes, message)

    verification = ABCVerify.verify_disclosure_proof(
        pk, disclosure_proof, message)

    assert(verification)