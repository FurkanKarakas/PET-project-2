"""
Unit tests for stroll.py
"""

from stroll import *


server = Server()
server_sk, server_pk = server.generate_ca(["age", "sex", "hobby", "username"])
client = Client()


def test_setup():
    """Test the whole setup
    """
    issuance, state = client.prepare_registration(
        server_pk, "username", ["hobby", "age"])
    server_response = server.process_registration(
        server_sk, server_pk, issuance, "username", ["hobby", "age"])
    # TODO: The line below fails.
    credentials = client.process_registration_response(
        server_pk, server_response, state)
    signature = client.sign_request(server_pk, credentials,
                                    b"Hello from the client!", ["sex"])
