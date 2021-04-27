"""
Unit tests for the credential module for implementing PS credentials
"""

from credential import *
import os
import random


def test_ps_scheme():
    """Test PS Scheme
    """
    # Generate random messages
    attributes = ["restaurant", "bar", "sushi", "username"]

    # Generate keys
    sk1, pk1 = PSScheme.generate_keys(attributes)
    sk2, pk2 = PSScheme.generate_keys(attributes)

    msgs = [os.urandom(128) for _ in attributes]

    # Sign messages
    signature = PSScheme.sign(sk1, msgs)

    # Verify signature is valid with correct pk
    assert PSScheme.verify(pk1, signature, msgs)

    # Verify signature is invalid with wrong pk
    assert not PSScheme.verify(pk2, signature, msgs)


def test_fiat_shamir():
    """Test Fiat Shamir proof when verification should succeed
    """
    N = 100
    # Generate random messages
    msgs = [os.urandom(128) for i in range(N)]

    # Generate keys
    sk, pk = PSScheme.generate_keys(msgs)

    g = G1.generator()
    bases = [g ** random.randint(100, 1000) for _ in range(N)]
    exponents = [random.randint(100, 1000) for _ in range(N)]

    C = bases[0] ** exponents[0]
    for b, e in zip(bases[1:], exponents[1:]):
        C *= b ** e

    # Check that verification passes on correct proof
    proof = FiatShamirProof(
        G1, C, pk,  # type:ignore
        bases,  # type:ignore
        exponents)  # type:ignore

    assert proof.verify(C, pk)

    # Check that verification fails on wrong C
    assert not proof.verify(C**2, pk)


def test_abc():

    # Attributes with random values
    attributes = ["restaurant", "bar", "sushi", "username"]
    attribute_map = {a: os.urandom(128) for a in attributes}

    # User attribute is just username, issuer attributes are the rest
    user_attributes = ["restaurant", "bar", "sushi", "username"]
    issuer_attributes = [a for a in attributes if a not in user_attributes]

    # Do not disclose username
    disclosed_attributes = ["restaurant", "bar", "sushi"]

    # Get random indices for user and issuer attributes
    user_attribute_map = {a: attribute_map[a] for a in user_attributes}
    issuer_attribute_map = {a: attribute_map[a] for a in issuer_attributes}

    # Generate keys
    sk, pk = PSScheme.generate_keys(attributes)

    # Get issue request as well as the state t which we need for later
    request, t = ABCIssue.create_issue_request(pk, user_attribute_map)

    response = ABCIssue.sign_issue_request(
        sk, pk, request, issuer_attribute_map)

    credential = ABCIssue.obtain_credential(pk, response, attribute_map, t)

    # Create random message
    message = os.urandom(128)

    # Check that correct disclosure proof verifies
    disclosure_proof = ABCVerify.create_disclosure_proof(
        pk, credential, disclosed_attributes, message)
    verification = ABCVerify.verify_disclosure_proof(
        pk, disclosure_proof, message)
    assert verification

    sk2, pk2 = PSScheme.generate_keys(attributes)

    # Check that disclosure proof with wrong pk fails
    disclosure_proof2 = ABCVerify.create_disclosure_proof(
        pk2, credential, disclosed_attributes, message)

    verification2 = ABCVerify.verify_disclosure_proof(
        pk2, disclosure_proof, message)
    assert not verification2

    # Check that disclosure proof with wrong message fails
    message2 = os.urandom(128)
    verification3 = ABCVerify.verify_disclosure_proof(
        pk, disclosure_proof, message2)
    assert not verification3
