from dataclasses import dataclass

# Cryptography imports
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import ec

@dataclass
class CertBundle:
    """
    Helper dataclass. Allows saving cryptograpic pieces together -
    Certificate and Private Key togehter.

    :var cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey | cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateKey private_key: 
    The private key object.

    :var cryptography.x509.Certificate certificate: 
    The certifcate object
    
    :var bytes pem_key:
    The PEM formatted private key.

    :var bytes pem_cert:
    The PEM formatted certificate.
    """
    private_key: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey
    certificate: x509.Certificate
    pem_key: bytes
    pem_cert: bytes