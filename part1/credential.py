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

from typing import Dict, List, Tuple, Union
from petrelic.multiplicative.pairing import G1, G2, GT, G1Element, G2Element, GTElement
from petrelic.bn import Bn
from serialization import jsonpickle
import hashlib


# Attributes
Attribute = bytes
# Maps from attribute index to attribute value
AttributeMap = Dict[int, Attribute]


######################
## SIGNATURE SCHEME ##
######################
class SecretKey:
    def __init__(self, x: Bn, X1: G1Element, y: List[Bn]):
        """Secret Key of a Pointcheval-Sanders scheme

        Args:
            x (Bn): random secret number
            X1 (G1Element): g1 ^ x
            y (List[Bn]): list of random, secret numbers
        """
        self.x = x
        self.X1 = X1
        self.y = y

    def __repr__(self):
        return f"{self.__class__.__name__}({repr(self.x)}, {repr(self.X1)}, {repr(self.y)})"


class PublicKey:
    def __init__(self, g1: G1Element, Y1: List[G1Element], g2: G2Element, X2: G2Element, Y2: List[G2Element]):
        """Public Key of a Pointcheval-Sanders scheme

        Args:
            g1 (G1Element): Any Generator of G1
            Y1 (List[G1Element]): public part of y from SecretKey in G1, g1 ^ y
            g2 (G2Element): Any Generator of G2
            X2 (G2Element): public part of x fom SecretKey, g2 ^ x
            Y2 (List[G2Element]): public part of y from SecretKey in G2, g2 ^ y 
        """
        self.g1 = g1
        self.Y1 = Y1
        self.g2 = g2
        self.X2 = X2
        self.Y2 = Y2

    def __repr__(self):
        return f"{self.__class__.__name__}({repr(self.g1)}, {repr(self.Y1)}, {repr(self.g2)}, {repr(self.X2)}, {repr(self.Y2)})"


class Signature:
    def __init__(self, gen: G1Element, sig: G1Element):
        """Signature of PS ABC scheme

        Args:
            gen (G1Element): A randomized generator, g^r where r is a randomly chosen value
            sig (G1Element): The signature some value x, with sig=g^(r*x)
        """
        self.gen = gen
        self.sig = sig

    def __repr__(self):
        return f"{self.__class__.__name__}({repr(self.gen)}, {repr(self.sig)})"


class BlindSignature:
    def __init__(self, signature: Signature, issuer_attributes: AttributeMap):
        """Signature of Issuer over user and issuer attributes

        Args:
            signature (Signature): Signature of user and issuer attributes
            issuer_attributes (AttributeMap): issuer attributes
        """
        self.signature = signature
        self.issuer_attributes = issuer_attributes


class FiatShamirProof:
    def __init__(self, G: Union[G1, G2, GT], C: Union[G1Element, G2Element, GTElement], pk: PublicKey, bases: List[Union[G1Element, G2Element, GTElement]], exponents: List[Bn]):
        """Fiat shamir non-interactive to show, that we calculated 
        C = bases[0]**exponents[0] * ... * bases[n]**exponents[n] correctly

        Args:
            G (Union[G1, G2, GT]): The group this proof works on
            C (Union[G1Element, G2Element, GTElement]): Element of group G, The result we want to proof correctness of
            pk (PublicKey): Public Key of the PS Scheme
            bases (List[Union[G1Element, G2Element, GTElement]]): Elements of group G, Bases used to caclulate C
            exponents (List[Bn]): Exponents used to calculate C
        """
        self.bases = bases
        noise = [G.order().random() for _ in bases]

        self.commitment = G.unity()
        for v, n in zip(bases, noise):
            self.commitment *= v**n

        self.challenge = self.create_hash(C, pk, self.commitment)
        self.response = [n.mod_sub(self.challenge * e, G.order())
                         for n, e in zip(noise, exponents)]

    @staticmethod
    def create_hash(*args):
        """Creates a hash from the passed arguments

        Returns:
            Bn: A Bn representing the hashed value of the passed arguments
        """
        challenge_str = jsonpickle.encode(args)
        challenge_hash = hashlib.sha256(challenge_str.encode())
        return Bn.from_binary(challenge_hash.digest())

    def verify(self, C: Union[G1Element, G2Element, GTElement], pk: PublicKey):
        """Verifies the proof with any C and pk

        Args:
            C (Union[G1Element, G2Element, GTElement]): The C we want to verify
            pk (PublicKey): Public Key of ABC Scheme

        Returns:
            bool: True iff the prove could be verified, False otherwises
        """
        # Check if the challenge matches
        challenge = self.create_hash(C, pk, self.commitment)
        if challenge != self.challenge:
            return False

        # Check if commitment matches
        commitment = C ** challenge
        for v, r in zip(self.bases, self.response):
            commitment *= v**r

        return commitment == self.commitment


class IssueRequest:
    def __init__(self, C: G1Element, proof: FiatShamirProof):
        """Request from user to issuer to specify which user attributes they want to include

        Args:
            C (G1Element): Calculated with attributes user wants to include according to User commitment step
            proof (FiatShamirProof): Proof that C was calculated correctly
        """
        self.C = C
        self.proof = proof


class DisclosureProof:
    def __init__(self, signature: Signature, disclosed_attributes: AttributeMap, proof: FiatShamirProof):
        """Proof which attributes should be disclosed to the verifier

        Args:
            signature (Signature): randomized signature over all attributes
            disclosed_attributes (AttributeMap): All attributes that should be disclosed to the verifier
            proof (FiatShamirProof): Non-interactive proof to show that randomized signature is valid
        """
        self.signature = signature
        self.disclosed_attributes = disclosed_attributes
        self.proof = proof


class PSScheme:
    """This class contains basic operations in a Pointcheval-Sanders scheme"""

    @staticmethod
    def generate_keys(attributes: List[Attribute]) -> Tuple[SecretKey, PublicKey]:
        """Generate signer key pair

        Args:
            attributes (List[Attribute]): The attributes for which the key pair should be generated

        Returns:
            Tuple[SecretKey, PublicKey]: Secret andpPublic keys for given attributes
        """
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
        pk = PublicKey(g1, Y1, g2, X2, Y2)  # type:ignore
        sk = SecretKey(x, X1, y)
        return sk, pk

    @staticmethod
    def sign(sk: SecretKey, msgs: List[bytes]) -> Signature:
        """Sign the vector of messages `msgs`

        Args:
            sk (SecretKey): Secret Key of PSScheme
            msgs (List[bytes]): Vector of messages that are to be signed

        Returns:
            Signature: Signature of these messages
        """
        assert(len(msgs) == len(sk.y))

        # pick generator
        h = G1.generator()
        exponent = sk.x + sum([y_i * Bn.from_binary(m_i)
                               for (y_i, m_i) in zip(sk.y, msgs)])

        return Signature(h, h**exponent)  # type:ignore

    @staticmethod
    def verify(pk: PublicKey, signature: Signature, msgs: List[bytes]) -> bool:
        """Verify the signature on a vector of messages

        Args:
            pk (PublicKey): Public Key of PS Scheme
            signature (Signature): Signature to verify
            msgs (List[bytes]): Vector of messages which are claimed to be signed by the signature

        Returns:
            bool: True iff signature is valid, false otherwise
        """
        # Check that generator is not 1
        if signature.gen == G1.unity():
            return False
        else:
            assert(len(msgs) == len(pk.Y2))
            accum = pk.X2
            for Y2_i, m_i in zip(pk.Y2, msgs):
                accum = accum * Y2_i**Bn.from_binary(m_i)
            return signature.gen.pair(accum) == signature.sig.pair(pk.g2)


#################################
## ATTRIBUTE-BASED CREDENTIALS ##
#################################

        """ Create an issuance request
        This corresponds to the "user commitment" step in the issuance protocol.
        *Warning:* You may need to pass state to the `obtain_credential` function.
        """

## ISSUANCE PROTOCOL ##


class ABCIssue:

    @staticmethod
    def create_issue_request(
        pk: PublicKey,
        user_attributes: AttributeMap
    ) -> Tuple[IssueRequest, Bn]:
        """Create an issuance request
        This corresponds to the "user commitment" step in the issuance protocol.

        Args:
            pk (PublicKey): Public Key of PS Scheme
            user_attributes (AttributeMap): Attributes belonging to the user

        Returns:
            Tuple[IssueRequest, Bn]: Request specifying which Attributs belong to the user,
                                     as well as the random t which the user needs again later.
        """
        user_attributes_ints = [Bn.from_binary(
            a) for a in user_attributes.values()]
        Y1s = [pk.Y1[i] for i in user_attributes.keys()]

        # Calculate C
        t = G1.order().random()
        C = pk.g1 ** t
        for Y1_i, a_i in zip(Y1s, user_attributes_ints):
            C *= Y1_i ** a_i

        # Proof that C has been calculated correctly
        proof = FiatShamirProof(
            G1, C, pk,  # type:ignore
            [pk.g1] + Y1s,  # type:ignore
            [t] + user_attributes_ints,
        )

        # TODO: Furkan: We pass t as "state" to the obtain credential function, you need to store it and pass it to obtain_credential again
        return IssueRequest(C, proof), t

    @staticmethod
    def sign_issue_request(
        sk: SecretKey,
        pk: PublicKey,
        request: IssueRequest,
        issuer_attributes: AttributeMap
    ) -> BlindSignature:
        """Create a signature corresponding to the user's request
        This corresponds to the "Issuer signing" step in the issuance protocol.

        Args:
            sk (SecretKey): Secret Key of PS Scheme
            pk (PublicKey): Public Key of PS Scheme
            request (IssueRequest): Requested attributes of user
            issuer_attributes (AttributeMap): Attributes belonging to issuer

        Returns:
            Signature: Signature 
        """
        # Verify that C has been calculated correctly
        assert(request.proof.verify(request.C, pk))

        # Sign issuer attributes
        u = G1.order().random()
        accum = sk.X1 * request.C
        for i, a_i in issuer_attributes.items():
            accum = accum * pk.Y1[i] ** Bn.from_binary(a_i)

        signature = Signature(pk.g1 ** u, accum ** u)
        return BlindSignature(signature, issuer_attributes)

    @ staticmethod
    def obtain_credential(
        pk: PublicKey,
        attributes: List[Attribute],
        response: BlindSignature,
        t: Bn
    ) -> Signature:
        """Derive a credential from the issuer's response
        This corresponds to the "Unblinding signature" step.

        Args:
            pk (PublicKey): Public Key of PS Scheme
            attributes (List[Attribute]): All attributes of issuer and user combined
            response (BlindSignature): Blind Signature of Issuer over user and issuer attributes
            t (Bn): Random number from create_issue_request

        Returns:
            Signature: Final, unblinded signature over attributes
        """
        # Unblind signature
        unblinded_signature = Signature(
            response.signature.gen, response.signature.sig / (response.signature.gen ** t))

        # Check that signature is valid
        assert PSScheme.verify(pk, unblinded_signature, attributes)

        # Return unblinded signature
        return unblinded_signature


## SHOWING PROTOCOL ##
class ABCVerify:
    @ staticmethod
    def create_disclosure_proof(
        pk: PublicKey,
        signature: Signature,
        hidden_attributes: AttributeMap,
        disclosed_attributes: AttributeMap
    ) -> DisclosureProof:
        """Create a disclosure proof

        Args:
            pk (PublicKey): Public Key of PS Scheme
            signature (Signature): Signature over all attributes
            hidden_attributes (AttributeMap): Attributes that are to be hidden from verifier
            disclosed_attributes (AttributeMap): All attributes not in hidden_attributes

        Returns:
            DisclosureProof: Proof that both parties agree on which arguments are disclosed
        """
        # Randomize signature
        r = G1.order().random()
        t = G1.order().random()
        signature = Signature(
            signature.gen**r, (signature.sig * signature.gen**t)**r)

        # Calculate proof over hidden attributes (right hand side of showing protocol 2b)
        sig1 = signature.gen.pair(pk.g2)
        Y2s = [signature.gen.pair(pk.Y2[i]) for i in hidden_attributes.keys()]
        a_is = [Bn.from_binary(a) for a in hidden_attributes.values()]

        C = sig1 ** t
        for Y2_i, a_i in zip(Y2s, a_is):
            C = C * Y2_i ** a_i

        # Proof that C was calculated correctly
        proof = FiatShamirProof(
            GT, C, pk,  # type:ignore
            [signature.gen.pair(pk.g2)] + Y2s,  # type:ignore
            [t] + a_is
        )

        return DisclosureProof(signature, disclosed_attributes, proof)

    @ staticmethod
    def verify_disclosure_proof(
        pk: PublicKey,
        disclosure_proof: DisclosureProof
    ) -> bool:
        """Verify the disclosure proof

        Args:
            pk (PublicKey): Public Key of PS scheme
            disclosure_proof (DisclosureProof): Proof that both parties agree on which arguments are disclosed

        Returns:
            bool: True iff the disclosure proof could be verified, False otherwise
        """

        signature = disclosure_proof.signature
        disclosed_attributes = disclosure_proof.disclosed_attributes

        # Check that the signature generator is not 1
        if signature.gen == G1.unity():
            return False

        # Calculate proof over disclosed attributes (left hand side of showing protocol 2b)
        sig2 = signature.sig.pair(pk.g2)
        Y2s = [signature.gen.pair(pk.Y2[i])
               for i in disclosed_attributes.keys()]
        a_is = [Bn.from_binary(a)
                for a in disclosed_attributes.values()]

        C = sig2 / signature.gen.pair(pk.X2)
        for Y2_i, a_i in zip(Y2s, a_is):
            C = C * Y2_i ** (-a_i)

        return disclosure_proof.proof.verify(C, pk)
