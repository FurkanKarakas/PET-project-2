"""
Unit tests for stroll.py
"""

from stroll import *


def test_setup():
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
