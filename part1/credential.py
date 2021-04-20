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

from typing import Any, List, Tuple
from petrelic.multiplicative.pairing import G1, G2, GT
from serialization import jsonpickle


# Type hint aliases
# Feel free to change them as you see fit.
# Maybe at the end, you will not need aliases at all!
Attribute = Any
AttributeMap = Any
IssueRequest = Any
BlindSignature = Any
AnonymousCredential = Any
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
    def __init__(self, h, sig):
        self.h = h
        self.sig = sig

    def __repr__(self):
        return f"{self.__class__.__name__}({repr(self.h)}, {repr(self.sig)})"


class PSScheme:
    """This class contains basic operations in a Pointcheval-Sanders scheme"""

    @staticmethod
    def generate_key(attributes: List[Attribute]) -> Tuple[SecretKey, PublicKey]:
        """ Generate signer key pair """

        # Pick uniformly random variables
        x = G1.order().random()
        y = [G1.order().random() for _ in range(len(attributes))]

        # pick  random  generators
        # TODO: I'm not sure if they are random
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
        return pk, sk

    @staticmethod
    def sign(sk: SecretKey, msgs: List[bytes]) -> Signature:
        """ Sign the vector of messages `msgs` """
        assert(len(msgs) == len(sk.y))
        # pick random generator
        # TODO: I'm not sure its random
        h = G1.generator()
        exponent = sk.x + sum([y_i * m_i for (y_i, m_i) in zip(sk.y, msgs)])

        return Signature(h, h**exponent)

    @staticmethod
    def verify(pk: PublicKey, signature: Signature, msgs: List[bytes]) -> bool:
        """ Verify the signature on a vector of messages """
        if signature.h == G1.unity():
            return False
        else:
            accum = pk.X2
            assert(len(msgs) == len(pk.Y2))
            for Y2_i, m_i in zip(pk.Y2, msgs):
                accum *= Y2_i**m_i

            return signature.h.pair(accum) == signature.sig.pair(pk.g2)


#################################
## ATTRIBUTE-BASED CREDENTIALS ##
#################################

## ISSUANCE PROTOCOL ##

def create_issue_request(
    pk: PublicKey,
    user_attributes: AttributeMap
) -> IssueRequest:
    """ Create an issuance request

    This corresponds to the "user commitment" step in the issuance protocol.

    *Warning:* You may need to pass state to the `obtain_credential` function.
    """
    raise NotImplementedError()


def sign_issue_request(
    sk: SecretKey,
    pk: PublicKey,
    request: IssueRequest,
    issuer_attributes: AttributeMap
) -> BlindSignature:
    """ Create a signature corresponding to the user's request

    This corresponds to the "Issuer signing" step in the issuance protocol.
    """
    raise NotImplementedError()


def obtain_credential(
    pk: PublicKey,
    response: BlindSignature
) -> AnonymousCredential:
    """ Derive a credential from the issuer's response

    This corresponds to the "Unblinding signature" step.
    """
    raise NotImplementedError()


## SHOWING PROTOCOL ##

def create_disclosure_proof(
    pk: PublicKey,
    credential: AnonymousCredential,
    hidden_attributes: List[Attribute],
    message: bytes
) -> DisclosureProof:
    """ Create a disclosure proof """
    raise NotImplementedError()


def verify_disclosure_proof(
    pk: PublicKey,
    disclosure_proof: DisclosureProof,
    message: bytes
) -> bool:
    """ Verify the disclosure proof

    Hint: The verifier may also want to retrieve the disclosed attributes
    """
    raise NotImplementedError()
