"""
Classes that you need to complete.
"""

from credential import ABCIssue, IssueRequest, PSScheme, PublicKey, SecretKey
from typing import Any, Dict, List, Tuple

# Optional import
from serialization import jsonpickle

# Type aliases
State = Any


class Server:
    """Server"""

    def __init__(self):
        """
        Server constructor.
        """
        ###############################################
        # TODO: Complete this function.
        ###############################################
        pass

    @classmethod
    def generate_ca(cls,
                    subscriptions: List[str]
                    ) -> Tuple[bytes, bytes]:
        """Initializes the credential system. Runs exactly once in the
        beginning. Decides on schemes public parameters and choses a secret key
        for the server.

        Args:
            subscriptions: a list of all valid attributes. Users cannot get a
                credential with a attribute which is not included here.

        Returns:
            tuple containing:
                - server's secret key
                - server's pubic information
            You are free to design this as you see fit, but the return types
            should be encoded as bytes.
        """
        ###############################################
        # TODO: Complete this function.
        ###############################################
        sk, pk = PSScheme.generate_keys(
            [subscription.encode() for subscription in subscriptions])
        # Save subscriptions as `valid_attributes`
        cls.valid_attributes: Dict[int, str] = dict()
        cls.valid_attributes_inverse: Dict[str, int] = dict()
        for i, subscription in enumerate(subscriptions):
            cls.valid_attributes[i] = subscription
            cls.valid_attributes_inverse[subscription] = i
        # jsonpickle.encode() returns a string. So, we encode it again to return a byte array
        # The default .encode() method uses utf-8
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
        ###############################################
        # TODO: Complete this function.
        ###############################################
        # Decode the public and secret keys
        sk, pk = jsonpickle.decode(server_sk), jsonpickle.decode(server_pk)

        # Check the types of sk and pk and make sure that they are in proper format.
        if not isinstance(sk, SecretKey) or not isinstance(pk, PublicKey):
            raise TypeError("Invalid type provided.")

        subscriptions = subscriptions+[username]
        # Decode the issuance
        issuance = jsonpickle.decode(issuance_request)

        if not isinstance(issuance, IssueRequest):
            raise TypeError("Invalid type provided.")

        user_dict: Dict[int, bytes] = dict()
        # Check if attributes are valid and create the user index-attribute dictionary
        for subscription in subscriptions+[username]:
            if subscription not in self.valid_attributes_inverse:
                raise AttributeError(
                    f"{subscription} is not a valid attribute.")
            user_dict[self.valid_attributes_inverse[subscription]
                      ] = subscription.encode()
        # Use the helper function to get the blind signature
        blind_signature = ABCIssue.sign_issue_request(
            sk, pk, issuance, user_dict)
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
        ###############################################
        # TODO: Complete this function.
        ###############################################
        pk = jsonpickle.decode(server_pk)
        if not isinstance(pk, PublicKey):
            raise TypeError("Invalid type provided.")
        sig = jsonpickle.decode(signature)
        # if not isinstance(sig,)

        user_attributes: Dict[int, bytes] = dict()
        # Check if attributes are valid and create the user index-attribute dictionary
        for subscription in revealed_attributes:
            if subscription not in self.valid_attributes_inverse:
                raise AttributeError(
                    f"{subscription} is not a valid attribute.")
            user_attributes[self.valid_attributes_inverse[subscription]
                            ] = subscription.encode()


class Client:
    """Client"""

    def __init__(self):
        """
        Client constructor.
        """
        ###############################################
        # TODO: Complete this function.
        ###############################################
        raise NotImplementedError()

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
        ###############################################
        # TODO: Complete this function.
        ###############################################
        raise NotImplementedError

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
        ###############################################
        # TODO: Complete this function.
        ###############################################
        raise NotImplementedError

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
        ###############################################
        # TODO: Complete this function.
        ###############################################
        raise NotImplementedError
