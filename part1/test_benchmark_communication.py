"""5 10 20 50 100 500"""
from stroll import *


def whole_setup(n):
    """Test the whole setup
    """
    server = Server()
    client = Client()

    attributes = [str(i) for i in range(n)]+["username"]
    username = "Furkan"
    subscriptions = [str(i) for i in range(n)]
    revealed_attributes = [str(i) for i in range(n)]
    message = b"Hello from Mars!"

    keygen = issuance = sign = verify = 0

    server_sk, server_pk = server.generate_ca(attributes)

    #keygen += len(server_pk)

    issuance_request, private_state = client.prepare_registration(
        server_pk, username, subscriptions)

    server_response = server.process_registration(
        server_sk, server_pk, issuance_request, username, subscriptions)

    credentials = client.process_registration_response(
        server_pk, server_response, private_state)

    issuance += len(server_pk)+len(issuance_request)+len(server_response)

    signature = client.sign_request(
        server_pk, credentials, message, revealed_attributes)

    #sign += len(signature)
    verify += len(signature)

    print(
        f"\nSize: {n}\nKeygen: {keygen}\nIssuance: {issuance}\nSign: {sign}\nVerify: {verify}\n")

    return server.check_request_signature(
        server_pk, message, revealed_attributes, signature)


if __name__ == "__main__":
    for n in (5, 10, 20, 50, 100, 500):
        assert whole_setup(n)
