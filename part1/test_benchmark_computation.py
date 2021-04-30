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

    server_sk, server_pk = server.generate_ca(attributes)

    issuance_request, private_state = client.prepare_registration(
        server_pk, username, subscriptions)

    server_response = server.process_registration(
        server_sk, server_pk, issuance_request, username, subscriptions)

    credentials = client.process_registration_response(
        server_pk, server_response, private_state)

    signature = client.sign_request(
        server_pk, credentials, message, revealed_attributes)

    return server.check_request_signature(
        server_pk, message, revealed_attributes, signature)


def key_gen(server, client, attributes):
    server_sk, server_pk = server.generate_ca(attributes)


def issuance(server, client, server_sk, server_pk, username, subscriptions):
    issuance_request, private_state = client.prepare_registration(
        server_pk, username, subscriptions)

    server_response = server.process_registration(
        server_sk, server_pk, issuance_request, username, subscriptions)

    credentials = client.process_registration_response(
        server_pk, server_response, private_state)


def sign(server, client, server_pk, credentials, message, revealed_attributes):
    signature = client.sign_request(
        server_pk, credentials, message, revealed_attributes)


def verify(server, client, server_pk, message, revealed_attributes, signature):
    server.check_request_signature(
        server_pk, message, revealed_attributes, signature)


def test_keygen5(benchmark):
    """Benchmark testing"""
    n = 5
    server = Server()
    client = Client()

    attributes = [str(i) for i in range(n)]+["username"]
    username = "Furkan"
    subscriptions = [str(i) for i in range(n)]
    revealed_attributes = [str(i) for i in range(n)]
    message = b"Hello from Mars!"

    benchmark.pedantic(key_gen, args=(
        server, client, attributes), rounds=100)


def test_keygen10(benchmark):
    """Benchmark testing"""
    n = 10
    server = Server()
    client = Client()

    attributes = [str(i) for i in range(n)]+["username"]
    username = "Furkan"
    subscriptions = [str(i) for i in range(n)]
    revealed_attributes = [str(i) for i in range(n)]
    message = b"Hello from Mars!"

    benchmark.pedantic(key_gen, args=(
        server, client, attributes), rounds=100)


def test_keygen20(benchmark):
    """Benchmark testing"""
    n = 20
    server = Server()
    client = Client()

    attributes = [str(i) for i in range(n)]+["username"]
    username = "Furkan"
    subscriptions = [str(i) for i in range(n)]
    revealed_attributes = [str(i) for i in range(n)]
    message = b"Hello from Mars!"

    benchmark.pedantic(key_gen, args=(
        server, client, attributes), rounds=100)


def test_keygen50(benchmark):
    """Benchmark testing"""
    n = 50
    server = Server()
    client = Client()

    attributes = [str(i) for i in range(n)]+["username"]
    username = "Furkan"
    subscriptions = [str(i) for i in range(n)]
    revealed_attributes = [str(i) for i in range(n)]
    message = b"Hello from Mars!"

    benchmark.pedantic(key_gen, args=(
        server, client, attributes), rounds=100)


def test_keygen100(benchmark):
    """Benchmark testing"""
    n = 100
    server = Server()
    client = Client()

    attributes = [str(i) for i in range(n)]+["username"]
    username = "Furkan"
    subscriptions = [str(i) for i in range(n)]
    revealed_attributes = [str(i) for i in range(n)]
    message = b"Hello from Mars!"

    benchmark.pedantic(key_gen, args=(
        server, client, attributes), rounds=100)


def test_keygen500(benchmark):
    """Benchmark testing"""
    n = 500
    server = Server()
    client = Client()

    attributes = [str(i) for i in range(n)]+["username"]
    username = "Furkan"
    subscriptions = [str(i) for i in range(n)]
    revealed_attributes = [str(i) for i in range(n)]
    message = b"Hello from Mars!"

    benchmark.pedantic(key_gen, args=(
        server, client, attributes), rounds=100)


def test_issue5(benchmark):
    """Benchmark testing"""
    n = 5
    server = Server()
    client = Client()

    attributes = [str(i) for i in range(n)]+["username"]
    username = "Furkan"
    subscriptions = [str(i) for i in range(n)]
    revealed_attributes = [str(i) for i in range(n)]
    message = b"Hello from Mars!"

    server_sk, server_pk = server.generate_ca(attributes)

    benchmark.pedantic(issuance, args=(
        server, client, server_sk, server_pk, username, subscriptions), rounds=100)


def test_issue10(benchmark):
    """Benchmark testing"""
    n = 10
    server = Server()
    client = Client()

    attributes = [str(i) for i in range(n)]+["username"]
    username = "Furkan"
    subscriptions = [str(i) for i in range(n)]
    revealed_attributes = [str(i) for i in range(n)]
    message = b"Hello from Mars!"

    server_sk, server_pk = server.generate_ca(attributes)

    benchmark.pedantic(issuance, args=(
        server, client, server_sk, server_pk, username, subscriptions), rounds=100)


def test_issue20(benchmark):
    """Benchmark testing"""
    n = 20
    server = Server()
    client = Client()

    attributes = [str(i) for i in range(n)]+["username"]
    username = "Furkan"
    subscriptions = [str(i) for i in range(n)]
    revealed_attributes = [str(i) for i in range(n)]
    message = b"Hello from Mars!"

    server_sk, server_pk = server.generate_ca(attributes)

    benchmark.pedantic(issuance, args=(
        server, client, server_sk, server_pk, username, subscriptions), rounds=100)


def test_issue50(benchmark):
    """Benchmark testing"""
    n = 50
    server = Server()
    client = Client()

    attributes = [str(i) for i in range(n)]+["username"]
    username = "Furkan"
    subscriptions = [str(i) for i in range(n)]
    revealed_attributes = [str(i) for i in range(n)]
    message = b"Hello from Mars!"

    server_sk, server_pk = server.generate_ca(attributes)

    benchmark.pedantic(issuance, args=(
        server, client, server_sk, server_pk, username, subscriptions), rounds=100)


def test_issue100(benchmark):
    """Benchmark testing"""
    n = 100
    server = Server()
    client = Client()

    attributes = [str(i) for i in range(n)]+["username"]
    username = "Furkan"
    subscriptions = [str(i) for i in range(n)]
    revealed_attributes = [str(i) for i in range(n)]
    message = b"Hello from Mars!"

    server_sk, server_pk = server.generate_ca(attributes)

    benchmark.pedantic(issuance, args=(
        server, client, server_sk, server_pk, username, subscriptions), rounds=100)


def test_issue500(benchmark):
    """Benchmark testing"""
    n = 500
    server = Server()
    client = Client()

    attributes = [str(i) for i in range(n)]+["username"]
    username = "Furkan"
    subscriptions = [str(i) for i in range(n)]
    revealed_attributes = [str(i) for i in range(n)]
    message = b"Hello from Mars!"

    server_sk, server_pk = server.generate_ca(attributes)

    benchmark.pedantic(issuance, args=(
        server, client, server_sk, server_pk, username, subscriptions), rounds=100)


def test_sign5(benchmark):
    """Benchmark testing"""
    n = 5
    server = Server()
    client = Client()

    attributes = [str(i) for i in range(n)]+["username"]
    username = "Furkan"
    subscriptions = [str(i) for i in range(n)]
    revealed_attributes = [str(i) for i in range(n)]
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

    benchmark.pedantic(sign, args=(
        server, client, server_pk, credentials, message, revealed_attributes), rounds=100)


def test_sign10(benchmark):
    """Benchmark testing"""
    n = 10
    server = Server()
    client = Client()

    attributes = [str(i) for i in range(n)]+["username"]
    username = "Furkan"
    subscriptions = [str(i) for i in range(n)]
    revealed_attributes = [str(i) for i in range(n)]
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

    benchmark.pedantic(sign, args=(
        server, client, server_pk, credentials, message, revealed_attributes), rounds=100)


def test_sign20(benchmark):
    """Benchmark testing"""
    n = 20
    server = Server()
    client = Client()

    attributes = [str(i) for i in range(n)]+["username"]
    username = "Furkan"
    subscriptions = [str(i) for i in range(n)]
    revealed_attributes = [str(i) for i in range(n)]
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

    benchmark.pedantic(sign, args=(
        server, client, server_pk, credentials, message, revealed_attributes), rounds=100)


def test_sign50(benchmark):
    """Benchmark testing"""
    n = 50
    server = Server()
    client = Client()

    attributes = [str(i) for i in range(n)]+["username"]
    username = "Furkan"
    subscriptions = [str(i) for i in range(n)]
    revealed_attributes = [str(i) for i in range(n)]
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

    benchmark.pedantic(sign, args=(
        server, client, server_pk, credentials, message, revealed_attributes), rounds=100)


def test_sign100(benchmark):
    """Benchmark testing"""
    n = 100
    server = Server()
    client = Client()

    attributes = [str(i) for i in range(n)]+["username"]
    username = "Furkan"
    subscriptions = [str(i) for i in range(n)]
    revealed_attributes = [str(i) for i in range(n)]
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

    benchmark.pedantic(sign, args=(
        server, client, server_pk, credentials, message, revealed_attributes), rounds=100)


def test_sign500(benchmark):
    """Benchmark testing"""
    n = 500
    server = Server()
    client = Client()

    attributes = [str(i) for i in range(n)]+["username"]
    username = "Furkan"
    subscriptions = [str(i) for i in range(n)]
    revealed_attributes = [str(i) for i in range(n)]
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

    benchmark.pedantic(sign, args=(
        server, client, server_pk, credentials, message, revealed_attributes), rounds=100)


def test_verify5(benchmark):
    """Benchmark testing"""
    n = 5
    server = Server()
    client = Client()

    attributes = [str(i) for i in range(n)]+["username"]
    username = "Furkan"
    subscriptions = [str(i) for i in range(n)]
    revealed_attributes = [str(i) for i in range(n)]
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

    benchmark.pedantic(verify, args=(
        server, client, server_pk, message, revealed_attributes, signature), rounds=100)


def test_verify10(benchmark):
    """Benchmark testing"""
    n = 10
    server = Server()
    client = Client()

    attributes = [str(i) for i in range(n)]+["username"]
    username = "Furkan"
    subscriptions = [str(i) for i in range(n)]
    revealed_attributes = [str(i) for i in range(n)]
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

    benchmark.pedantic(verify, args=(
        server, client, server_pk, message, revealed_attributes, signature), rounds=100)


def test_verify20(benchmark):
    """Benchmark testing"""
    n = 20
    server = Server()
    client = Client()

    attributes = [str(i) for i in range(n)]+["username"]
    username = "Furkan"
    subscriptions = [str(i) for i in range(n)]
    revealed_attributes = [str(i) for i in range(n)]
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

    benchmark.pedantic(verify, args=(
        server, client, server_pk, message, revealed_attributes, signature), rounds=100)


def test_verify50(benchmark):
    """Benchmark testing"""
    n = 50
    server = Server()
    client = Client()

    attributes = [str(i) for i in range(n)]+["username"]
    username = "Furkan"
    subscriptions = [str(i) for i in range(n)]
    revealed_attributes = [str(i) for i in range(n)]
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

    benchmark.pedantic(verify, args=(
        server, client, server_pk, message, revealed_attributes, signature), rounds=100)


def test_verify100(benchmark):
    """Benchmark testing"""
    n = 100
    server = Server()
    client = Client()

    attributes = [str(i) for i in range(n)]+["username"]
    username = "Furkan"
    subscriptions = [str(i) for i in range(n)]
    revealed_attributes = [str(i) for i in range(n)]
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

    benchmark.pedantic(verify, args=(
        server, client, server_pk, message, revealed_attributes, signature), rounds=100)


def test_verify500(benchmark):
    """Benchmark testing"""
    n = 500
    server = Server()
    client = Client()

    attributes = [str(i) for i in range(n)]+["username"]
    username = "Furkan"
    subscriptions = [str(i) for i in range(n)]
    revealed_attributes = [str(i) for i in range(n)]
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

    benchmark.pedantic(verify, args=(
        server, client, server_pk, message, revealed_attributes, signature), rounds=100)
