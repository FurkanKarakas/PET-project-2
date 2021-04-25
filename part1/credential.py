"""
Skeleton credential module for implementing PS credentials
The goal of this skeleton is to help you implementing PS credentials. Following
this API is not mandatory and you can change it as you see fit. This skeleton
only provides major functionality that you will need.
You will likely have to define more functions and/or classes. In particular, to
maintain clean code, we recommend to use classes for things that you want to
send between parties. You can then use `jsonpickle` serialization to convert
these classes to byte arrays (as expected by the other classes) and back again.
We also avoided the use of classes in this template so that the code more closely
resembles the original scheme definition. However, you are free to restructure
the functions provided to resemble a more object-oriented interface.
"""

from typing import Any, List, Tuple, Mapping
from petrelic.multiplicative.pairing import G1, G2, GT
from petrelic.bn import Bn
from serialization import jsonpickle
import hashlib


# Type hint aliases
# Feel free to change them as you see fit.
# Maybe at the end, you will not need aliases at all!
Attribute = bytes
AttributeMap = Mapping[int, Attribute]
DisclosureProof = Any


######################
## SIGNATURE SCHEME ##
######################

class SecretKey:
    def __init__(self, x, X1, y):
        self.x = x
        self.X1 = X1
        self.y = y

    def __repr__(self):
        return f"{self.__class__.__name__}({repr(self.x)}, {repr(self.X1)}, {repr(self.y)})"


class PublicKey:
    def __init__(self, g1, Y1, g2, X2, Y2):
        self.g1 = g1
        self.Y1 = Y1
        self.g2 = g2
        self.X2 = X2
        self.Y2 = Y2

    def __repr__(self):
        return f"{self.__class__.__name__}({repr(self.g1)}, {repr(self.Y1)}, {repr(self.g2)}, {repr(self.X2)}, {repr(self.Y2)})"


class Signature:
    def __init__(self, sig1, sig2):
        self.sig1 = sig1
        self.sig2 = sig2

    def __repr__(self):
        return f"{self.__class__.__name__}({repr(self.h)}, {repr(self.sig)})"


class FiatShamirProof:
    def __init__(self, C, pk, G, values, exponents):
        self.values = values
        self.g = G.generator()
        self.noise = [G.order().random() for _ in values]
        self.commitment = G.unity()
        for v, n in zip(values, self.noise):
            self.commitment *= v**n

        self.challenge = self.hash_challenge(C, pk, self.commitment)
        self.response = [n.mod_sub(self.challenge * e, G.order())
                         for n, e in zip(self.noise, exponents)]

    @staticmethod
    def hash_challenge(C, pk, commitment):
        challenge_str = jsonpickle.encode([C, pk, commitment])
        challenge_hash = hashlib.sha256(challenge_str.encode())
        return Bn.from_binary(challenge_hash.digest())

    def verify(self, C, pk):
        challenge = self.hash_challenge(C, pk, self.commitment)
        if challenge != self.challenge:
            return False
        commitment = C ** self.challenge
        for v, r in zip(self.values, self.response):
            commitment *= v**r

        return commitment == self.commitment


class IssueRequest:
    def __init__(self, C, proof: FiatShamirProof):
        self.C = C
        self.proof = proof


class Proof:
    def __init__(self, *args: List[Any]):
        argbytes = jsonpickle.encode(args).encode()
        arghash = hashlib.sha256(argbytes)
        self.value = Bn.from_binary(arghash.digest())

    def __eq__(self, other: Any):
        return isinstance(other, Proof) and self.proof == other.proof


class DisclosureProof:
    def __init__(self, signature, attributes, proof):
        self.signature = signature
        self.attributes = attributes
        self.proof = proof


class PSScheme:
    """This class contains basic operations in a Pointcheval-Sanders scheme"""

    @staticmethod
    def generate_keys(attributes: List[Attribute]) -> Tuple[SecretKey, PublicKey]:
        """ Generate signer key pair """

        # Pick uniformly random variables
        x = G1.order().random()
        y = [G1.order().random() for _ in range(len(attributes))]

        # take generators of G1 and G2
        g1 = G1.generator()
        g2 = G2.generator()

        # Compute Xs and Ys
        X1 = g1 ** x
        X2 = g2 ** x
        Y1 = [g1 ** y_i for y_i in y]
        Y2 = [g2 ** y_i for y_i in y]

        # Output public and secret keys
        pk = PublicKey(g1, Y1, g2, X2, Y2)
        sk = SecretKey(x, X1, y)
        return sk, pk

    @staticmethod
    def sign(sk: SecretKey, msgs: List[bytes]) -> Signature:
        """ Sign the vector of messages `msgs` """
        assert(len(msgs) == len(sk.y))

        # pick generator
        h = G1.generator()
        exponent = sk.x + sum([y_i * Bn.from_binary(m_i)
                               for (y_i, m_i) in zip(sk.y, msgs)])

        return Signature(h, h**exponent)

    @staticmethod
    def verify(pk: PublicKey, signature: Signature, msgs: List[bytes]) -> bool:
        """ Verify the signature on a vector of messages """
        if signature.sig1 == G1.unity():
            return False
        else:
            accum = pk.X2
            assert(len(msgs) == len(pk.Y2))
            for Y2_i, m_i in zip(pk.Y2, msgs):
                accum *= Y2_i**Bn.from_binary(m_i)
            return signature.sig1.pair(accum) == signature.sig2.pair(pk.g2)


#################################
## ATTRIBUTE-BASED CREDENTIALS ##
#################################

## ISSUANCE PROTOCOL ##
class ABCIssue:

    @staticmethod
    def create_issue_request(
        pk: PublicKey,
        user_attributes: AttributeMap
    ) -> IssueRequest:
        """ Create an issuance request
        This corresponds to the "user commitment" step in the issuance protocol.
        *Warning:* You may need to pass state to the `obtain_credential` function.
        """
        user_attributes_ints = [Bn.from_binary(
            a) for a in user_attributes.values()]
        Y1s = [pk.Y1[i] for i in user_attributes.keys()]

        # Calculate C
        t = G1.order().random()
        C = pk.g1 ** t
        for Y1_i, a_i in zip(Y1s, user_attributes_ints):
            C *= Y1_i ** a_i

        proof = FiatShamirProof(
            C, pk, G1,
            [pk.g1] + Y1s,
            [t] + user_attributes_ints,
        )

        # TODO: Furkan: We pass t as "state" to the obtain credential function, we need to store it somewhere
        return IssueRequest(C, proof), t

    @staticmethod
    def sign_issue_request(
        sk: SecretKey,
        pk: PublicKey,
        request: IssueRequest,
        issuer_attributes: AttributeMap
    ) -> Signature:
        """ Create a signature corresponding to the user's request
        This corresponds to the "Issuer signing" step in the issuance protocol.
        """

        assert(request.proof.verify(request.C, pk))

        u = G1.order().random()

        accum = sk.X1 * request.C
        for i, a_i in issuer_attributes.items():
            accum *= pk.Y1[i] ** Bn.from_binary(a_i)

        return Signature(pk.g1**u, accum**u)

    @ staticmethod
    def obtain_credential(
        pk: PublicKey,
        response: Signature,
        t: Bn
    ) -> Signature:
        """ Derive a credential from the issuer's response
        This corresponds to the "Unblinding signature" step.
        """
        return Signature(response.sig1, response.sig2 / (response.sig1 ** t))


## SHOWING PROTOCOL ##
class ABCVerify:

    @ staticmethod
    def create_disclosure_proof(
        pk: PublicKey,
        credential: Signature,
        hidden_attributes: AttributeMap,
        disclosed_attributes: AttributeMap,
        message: bytes
    ) -> DisclosureProof:
        """ Create a disclosure proof """
        r = G1.order().random()
        t = G1.order().random()
        signature = Signature(
            credential.sig1**r, (credential.sig2 * credential.sig1**t)**r)

        sig1 = signature.sig1.pair(pk.g2)
        Y2s = [signature.sig1.pair(pk.Y2[i]) for i in hidden_attributes.keys()]
        a_is = [Bn.from_binary(a) for a in hidden_attributes.values()]

        C = sig1 ** t
        for Y2_i, a_i in zip(Y2s, a_is):
            C *= Y2_i ** a_i

        proof = FiatShamirProof(
            C, pk, GT,
            [signature.sig1.pair(pk.g2)] + Y2s,
            [t] + a_is
        )

        return DisclosureProof(signature, disclosed_attributes, proof)

    @ staticmethod
    def verify_disclosure_proof(
        pk: PublicKey,
        disclosure_proof: DisclosureProof,
        message: bytes
    ) -> bool:
        """ Verify the disclosure proof
        Hint: The verifier may also want to retrieve the disclosed attributes
        """

        signature = disclosure_proof.signature

        if signature.sig1 == G1.unity():
            return False

        sig2 = signature.sig2.pair(pk.g2)
        Y2s = [signature.sig1.pair(pk.Y2[i]) for i in disclosure_proof.attributes.keys()]
        a_is = [Bn.from_binary(a) for a in disclosure_proof.attributes.values()]

        C = sig2 / signature.sig1.pair(pk.X2)
        for Y2_i, a_i in zip(Y2s, a_is):
            C *= Y2_i ** (-a_i)

        return  disclosure_proof.proof.verify(C, pk)
