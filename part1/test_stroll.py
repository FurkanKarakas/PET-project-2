"""
Unit tests for stroll.py
"""

from stroll import *


server = Server()
attributes = ["age", "sex", "hobby", "temp1", "temp2", "very secret info"]
chosen_attributes = ["very secret info", "temp2", "temp1"]
revealed_attributes = ["temp2"]
username = "username"
server_sk, server_pk = server.generate_ca(attributes+[username])
client = Client()
message = "Hello from Mars!".encode()


def test_setup():
    """Test the whole setup
    """
    issuance, state = client.prepare_registration(
        server_pk, username, chosen_attributes)
    server_response = server.process_registration(
        server_sk, server_pk, issuance, username, chosen_attributes)
    # TODO: The line below fails.
    credential = client.process_registration_response(
        server_pk, server_response, state)
    signature = client.sign_request(server_pk, credential,
                                    message, ["sex"])
