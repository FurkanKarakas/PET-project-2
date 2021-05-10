"""
Classes that you need to complete.
"""


from credential import *
from typing import List, Tuple

# Optional import
from serialization import jsonpickle


PRESENT_SUBSCRIPTION = b'present'
ABSENT_SUBSCRIPTION = b'absent'


class State:
    def __init__(self, attributes, t):
        self.attributes = attributes
        self.t = t


class Server:
    """Server"""

    def __init__(self):
        """
        Server constructor.
        """
        pass

    @classmethod
    def generate_ca(cls, subscriptions: List[str]) -> Tuple[bytes, bytes]:
        """Initializes the credential system. Runs exactly once in the
        beginning. Decides on schemes public parameters and choses a secret key
        for the server.

        Args:
            subscriptions: a list of all valid attributes. Users cannot get a
                credential with a attribute which is not included here.

        Returns:
            tuple containing:
                - server's secret key
                - server's public information
            You are free to design this as you see fit, but the return types
            should be encoded as bytes.
        """

        # Store the valid subscriptions
        cls.valid_subscriptions = subscriptions

        sk, pk = PSScheme.generate_keys(subscriptions)
        return jsonpickle.encode(sk).encode(), jsonpickle.encode(pk).encode()

    def process_registration(
        self,
        server_sk: bytes,
        server_pk: bytes,
        issuance_request: bytes,
        username: str,
        subscriptions: List[str]
    ) -> bytes:
        """ Registers a new account on the server.

        Args:
            server_sk: the server's secret key (serialized)
            issuance_request: The issuance request (serialized)
            username: username
            subscriptions: attributes


        Return:
            serialized response (the client should be able to build a
                credential with this response).
        """

        # Decode the public and secret keys
        sk, pk = jsonpickle.decode(server_sk), jsonpickle.decode(server_pk)

        # Check the types of sk and pk and make sure that they are in proper format.
        if not isinstance(sk, SecretKey) or not isinstance(pk, PublicKey):
            raise TypeError("Invalid type provided.")

        # Decode the issuance
        issuance = jsonpickle.decode(issuance_request)

        if not isinstance(issuance, IssueRequest):
            raise TypeError("Invalid type provided.")

        # Make sure that subscriptions are valid
        # The issuer will issue all the attributes
        issuer_attributes = {
            attribute: ABSENT_SUBSCRIPTION for attribute in self.valid_subscriptions}
        for sub in subscriptions:
            if sub not in self.valid_subscriptions:
                raise Exception(f"{sub} is not a valid subscription")
            # Make sure that they are not duplicate
            if issuer_attributes[sub] == PRESENT_SUBSCRIPTION:
                raise Exception(f"{sub} included many times")
            issuer_attributes[sub] = PRESENT_SUBSCRIPTION

        # Also add the username
        # Check if there was a subscription with name `username`
        if issuer_attributes["username"] == PRESENT_SUBSCRIPTION:
            raise Exception(f"A subscription with name username is present")
        issuer_attributes["username"] = username.encode()

        # Use the helper function to get the blind signature, the issuer does not have to add any attributes
        blind_signature = ABCIssue.sign_issue_request(
            sk, pk, issuance, issuer_attributes)

        # Encode and return it
        return jsonpickle.encode(blind_signature).encode()

    def check_request_signature(
        self,
        server_pk: bytes,
        message: bytes,
        revealed_attributes: List[str],
        signature: bytes
    ) -> bool:
        """ Verify the signature on the location request

        Args:
            server_pk: the server's public key (serialized)
            message: The message to sign
            revealed_attributes: revealed attributes
            signature: user's authorization (serialized)

        Returns:
            whether a signature is valid
        """

        pk = jsonpickle.decode(server_pk)
        if not isinstance(pk, PublicKey):
            raise TypeError("Invalid type provided.")
        sig = jsonpickle.decode(signature)
        if not isinstance(sig, DisclosureProof):
            raise TypeError("Invalid type provided.")

        for a in revealed_attributes:
            if a not in sig.disclosed_attributes or sig.disclosed_attributes[a] != PRESENT_SUBSCRIPTION:
                return False

        return ABCVerify.verify_disclosure_proof(pk, sig, message)


class Client:
    """Client"""

    def __init__(self):
        """
        Client constructor.
        """
        pass

    def prepare_registration(
        self,
        server_pk: bytes,
        username: str,
        subscriptions: List[str]
    ) -> Tuple[bytes, State]:
        """Prepare a request to register a new account on the server.

        Args:
            server_pk: a server's public key (serialized)
            username: user's name
            subscriptions: user's subscriptions

        Return:
            A tuple containing:
                - an issuance request
                - A private state. You can use state to store and transfer information
                from prepare_registration to proceed_registration_response.
                You need to design the state yourself.
        """

        pk = jsonpickle.decode(server_pk)
        if not isinstance(pk, PublicKey):
            raise TypeError("Invalid type provided.")

        # Check that subscriptions are valid ones
        # Also make sure that they are unique
        count_dict: Dict[str, int] = dict()
        for sub in subscriptions:
            if sub not in pk.attributes:
                raise Exception(f"{sub} is not a valid subscription.")
            count_dict[sub] = count_dict.get(sub, 0)+1
            if count_dict[sub] > 1:
                raise Exception(f"{sub} included multiple times.")

        # Lastly check for the username
        count_dict["username"] = count_dict.get("username", 0)+1
        if count_dict["username"] > 1:
            raise Exception(
                f"Attribute username already included in subscriptions and username with value {username} already provided. Make sure that you do not include any username in the subscriptions list.")

        # Store the subscriptions and username in a list
        self.user_attributes = subscriptions+[username]

        issue_request, t = ABCIssue.create_issue_request(pk, {})

        return jsonpickle.encode(issue_request).encode(), State({}, t)

    def process_registration_response(
        self,
        server_pk: bytes,
        server_response: bytes,
        private_state: State
    ) -> bytes:
        """Process the response from the server.

        Args:
            server_pk a server's public key (serialized)
            server_response: the response from the server (serialized)
            private_state: state from the prepare_registration
            request corresponding to this response

        Return:
            credentials: create an attribute-based credential for the user
        """

        pk = jsonpickle.decode(server_pk)
        if not isinstance(pk, PublicKey):
            raise TypeError("Invalid type provided.")

        response = jsonpickle.decode(server_response)
        if not isinstance(response, BlindSignature):
            raise TypeError("Invalid type provided.")

        # Check that the server indeed issued the correct credentials
        if response.issuer_attributes["username"] != self.user_attributes[-1].encode():
            raise Exception("Server username: {server}, user's username: {client}".format(
                server=response.issuer_attributes["username"].decode(), client=self.user_attributes[-1]))
        for key, value in response.issuer_attributes.items():
            # If key is in user_attributes and value is not present subscription, then the server issued a false crendential
            if key in self.user_attributes and value != PRESENT_SUBSCRIPTION:
                raise Exception(
                    f"The attribute {key} is not issued by the server")
            # If key is not in user_attributes and value is present in subscription, then the server issued a false credential
            if key not in self.user_attributes and value == PRESENT_SUBSCRIPTION:
                raise Exception(f"The attribute {key} is issued by the server")

        credential = ABCIssue.obtain_credential(
            pk, response, private_state.attributes, private_state.t)

        return jsonpickle.encode(credential).encode()

    def sign_request(
        self,
        server_pk: bytes,
        credentials: bytes,
        message: bytes,
        types: List[str]
    ) -> bytes:
        """Signs the request with the client's credential.

        Arg:
            server_pk: a server's public key (serialized)
            credential: client's credential (serialized)
            message: message to sign
            types: which attributes should be sent along with the request?

        Returns:
            A message's signature (serialized)
        """

        pk = jsonpickle.decode(server_pk)
        if not isinstance(pk, PublicKey):
            raise TypeError("Invalid type provided.")

        credential = jsonpickle.decode(credentials)
        if not isinstance(credential, AnonymousCredential):
            raise TypeError("Invalid type provided.")

        # Verify that revealed attributes are in user subscriptions.
        for typee in types:
            if typee not in credential.attributes:
                raise Exception(f"{typee} is not in user subscriptions.")
            if credential.attributes[typee] == ABSENT_SUBSCRIPTION:
                raise Exception(f"{typee} is not in user subscriptions.")

        sig = ABCVerify.create_disclosure_proof(pk, credential, types, message)
        return jsonpickle.encode(sig).encode()
