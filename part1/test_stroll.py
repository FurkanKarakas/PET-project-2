"""
Unit tests for stroll.py
"""

from stroll import *
import pytest


def test_setup_valid_and_invalid():
    """Test the whole setup
    """
    server = Server()
    client = Client()

    attributes = ["restaurant", "bar", "sushi", "username"]
    username = "Furkan"
    subscriptions = ["bar", "sushi"]
    revealed_attributes = ["sushi"]
    message = b"Hello from Mars!"

    server_sk, server_pk = server.generate_ca(attributes)

    issuance_request, private_state = client.prepare_registration(
        server_pk, username, subscriptions)

    server_response = server.process_registration(
        server_sk, server_pk, issuance_request, username, subscriptions)

    credentials = client.process_registration_response(
        server_pk, server_response, private_state)

    signature = client.sign_request(
        server_pk, credentials, message, revealed_attributes)

    assert server.check_request_signature(
        server_pk, message, revealed_attributes, signature)

    # Check that invalid signature won't be accepted
    signature_wrong = jsonpickle.decode(signature)
    assert isinstance(signature_wrong, DisclosureProof)
    signature_wrong.signature.sig **= 2
    signature_wrong = jsonpickle.encode(signature_wrong).encode()
    assert not server.check_request_signature(
        server_pk, message, revealed_attributes, signature_wrong)


def test_wrong_subscription():
    """Test if the client requests wrong subscriptions
    """
    server = Server()
    client = Client()

    attributes = ["restaurant", "bar", "sushi", "username"]
    username = "Furkan"
    subscriptions = ["bar", "very secret place"]
    revealed_attributes = ["bar"]
    message = b"Hello from Mars!"

    server_sk, server_pk = server.generate_ca(attributes)

    with pytest.raises(Exception):
        issuance_request, private_state = client.prepare_registration(
            server_pk, username, subscriptions)


def test_wrong_reveal():
    """Test if revealed attributes are not a subset of subscriptions
    """
    server = Server()
    client = Client()

    attributes = ["restaurant", "bar", "sushi", "username"]
    username = "Furkan"
    subscriptions = ["sushi", "bar"]
    revealed_attributes = ["sushi", "bar", "username", "restaurant"]
    message = b"Hello from Mars!"

    server_sk, server_pk = server.generate_ca(attributes)

    issuance_request, private_state = client.prepare_registration(
        server_pk, username, subscriptions)

    server_response = server.process_registration(
        server_sk, server_pk, issuance_request, username, subscriptions)

    credentials = client.process_registration_response(
        server_pk, server_response, private_state)

    with pytest.raises(Exception):
        signature = client.sign_request(
            server_pk, credentials, message, revealed_attributes)


def test_username():
    """Test if we don't reveal any attributes
    """
    server = Server()
    client = Client()

    attributes = ["restaurant", "bar", "sushi", "username"]
    username = "Furkan"
    subscriptions = ["bar", "sushi"]
    revealed_attributes = []
    message = b"Hello from Mars!"

    server_sk, server_pk = server.generate_ca(attributes)

    issuance_request, private_state = client.prepare_registration(
        server_pk, username, subscriptions)

    server_response = server.process_registration(
        server_sk, server_pk, issuance_request, username, subscriptions)

    credentials = client.process_registration_response(
        server_pk, server_response, private_state)

    signature = client.sign_request(
        server_pk, credentials, message, revealed_attributes)

    assert server.check_request_signature(server_pk, message, revealed_attributes, signature)
