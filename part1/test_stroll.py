"""
Unit tests for stroll.py
"""

from stroll import *


server = Server()
attributes = ["age", "sex", "hobby", "temp1", "temp2", "very secret info"]
user_attributes = ["temp1", "temp2", "very secret info"]
issuer_attributes = [
    attribute for attribute in attributes if attribute not in user_attributes]
revealed_attributes = ["temp2"]
hidden_attributes = [
    attribute for attribute in attributes if attribute not in revealed_attributes]
username = "username"
server_sk, server_pk = server.generate_ca(attributes+[username])
client = Client()
message = "Hello from Mars!".encode()


def test_setup():
    """Test the whole setup
    """
    issuance, state = client.prepare_registration(
        server_pk, username, user_attributes)
    server_response = server.process_registration(
        server_sk, server_pk, issuance, username, issuer_attributes)
    credential = client.process_registration_response(
        server_pk, server_response, state)
    signature = client.sign_request(server_pk, credential,
                                    message, revealed_attributes)

    assert server.check_request_signature(
        server_pk, message, revealed_attributes, signature)
