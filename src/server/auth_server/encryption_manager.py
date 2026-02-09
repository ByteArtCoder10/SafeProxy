from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import serialization
from diffiehellman import DiffieHellman
import os

from ..server_constants import AUTH_KEYS_SIZE
from ..logs.loggers import db_logger
class EncryptionManager:
    """
    Uses AES-GCM-256 mode for symetric encryption and DH for assymetric encrpytion
    and symetric key establishement. AES-GCM mode is of type AEAD - both encrypted and authenticated.

    Note: AES-256 is vital here and 192-bits/128-bits keys are not suitable- 
    (some background)
    After establishing a secure communication between client and auth server,
    The client sends a login/signup attempt. if successfull, the server replies back with a jwt token.
    to create a jwt token, the jwt protocol requires authentication. there are 2 ways to fulfill this requirement:
    1. Asymetric encryption - for a simple, Certinaly Encrpted connection this is too resource-expensive and un-needed.
    2. Symetric encryption - In our situation, client & server already share the same aes-256 key. Therefore, already
    half the work is done, and it is a much simpler, cheper and intuitive choice to pick.

    The problem with symetric encryption:
    jwt is a modern and quite new protocol replacing the older protocl swt (simple-web-token).
    Therefore, security-wise, it supports only cryptogrpaphic protocols with 256-bit+ key size.
    Hence, using AES-192/128 in here will require using a NEW symetric key, which will complicate the auth proccess
    and probably slow it.

    However, this opens a door for a cryptographic attack and is a vulnreablity. Using the same key for different
    cryptographic porpuses (Encrpytion, Authentication) is dangerous. 
    
    Luckily, there is a better solution - the DH 2048-bit key. In order to establish a secure communication,
    we first use the DH algorithm to create a mutual 2048-bit key, and from that key we derive the AES-256 key using HKDF and
    SHA-256.

    The same way, we can derive another 256-bit key for jwt authentucation purpose. adding the salt "auth" will differ our 
    aes-256 key for our auth-key

    --I'm writing this while expirementing so understand the drastic decision changes--

    However, and it's a big one, the proxy has to verify the key on EVERY request. this will require him being of
    posession of the auth-derived-key. since the proxy server, and the auth server are two differnet "entities"
    transfering this key won't be esay and requires some kind of API between the two.
    Well, how about keeping the token on the DB (that way the proxy doesnt't need access to the auth
    key and it is much simpler)? well this has two criticla problems:
    1. It creates the same exact problem, the DB operates on the auth server, not the proxy server. the proxy will need access to the DB.
    2. It will (probably) slow the proxy drastically. The proxy gets many simultaneous requests. making a DB query for each one is
    not ideal and bad.

    So, we're left with: Asymetric encryption.
    The auth server will have the privat key, and will sign tokens with it. and the proxy server will have the public, 
    performing fast ad lghtweight calculations for verification. This keeps the proxy fast while also secured and able to
    verify. Another pro of this method, is that if a hacker manages to attack/hack/get unautharized access to the proxy server,
    he will not be able to genreate new tokens, because the private key is on the auth server. 
    """

    def __init__(self, key : bytes):
        """
        Initialize with a symmetric key.

        :param key: 32-byte AES key.
        """
        self.key = key # 32-bytes key
        self.aesgcm = AESGCM(self.key) # the aes-gcm object used to encryt/decrypt

    def aes_encrypt(self, txt: str) -> bytes:
        """
        Encrypts a string using AES-GCM. Adds the 12-byte nonce to the ciphertext.

        :type txt: str
        :param txt: The plaintext string to encrypt.

        :rtype: bytes
        :returns: Nonce + cipher text + (tag, for auth)
        """
        # set unique nonce for every msg (NIST recommends 12-byte nonce)
        nonce = os.urandom(12)

        raw_data = txt.encode()
        ct = self.aesgcm.encrypt(nonce=nonce, data=raw_data, associated_data=None)        
        return nonce + ct

    def aes_decrypt(self, cipher_text: bytes) -> str:
        """
        Decrypts bytes using AES-GCM. Extracts nonce from the first 12 bytes.

        :type cipher_text: bytes
        :param cipher_text: The raw encrypted data - (Nonce + Ciphertext).

        :rtype: str
        :return: The decrypted plaintext.
        
        :raises cryptography.exceptions.InvalidTag: if ciphertext 
        was tamperd, or key/nonce/tag are wrong.
        """
        nonce = cipher_text[:12]
        actual_ciphertext = cipher_text[12:]

        msg = self.aesgcm.decrypt(nonce=nonce, data=actual_ciphertext, associated_data=None).decode()
        return msg
    
    @staticmethod
    def derive_key_from_dh_key(shared_dh_key: bytes, salt: bytes | None = None) -> bytes:
        """
        Derives a 32-byte AES key from the Diffie-Hellman shared secret using HKDF.

        :type shared_dh_key: bytes
        :param shared_dh_key: The raw shared key from DH exchange.

        :type salt: bytes | None = None
        :param salt: Optional salt for HKDF.
        
        :rtype: bytes
        :return: A 32-byte derived key.
        """
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32, # AES-256-bits master key is 32 bytes long
            salt=salt,
            info=None
        )
        return hkdf.derive(shared_dh_key)

    @staticmethod
    def get_dh_public_key() -> tuple[DiffieHellman, bytes]:
        """
        Generates a Diffie-Hellman public/private pair (2048-bit each).

        :rtype: Tuple[DiffieHelman, bytes]
        :return: DiffieHellman object, the public key
        """
        dh = DiffieHellman(group=14, key_bits=2048)
        pk = dh.get_public_key()
        return dh, pk

    @staticmethod
    def get_dh_shared_key(dh_1: DiffieHellman, pk_2: bytes, length=256) -> bytes:
        """
        Computes the shared secret using the local private key and remote public key.

        :type dh_1: DiffieHellman
        :param dh_1: The local DiffieHellman object.

        :type pk_2: bytes
        :param pk_2: The other side's public key.
        :param length:  key length, up until 'length' bytes. (default 256 bytes).

        :rtype: bytes
        :return: The shared secret.
        """
        dh_shared = dh_1.generate_shared_key(pk_2)
        return dh_shared[:length]

    @staticmethod
    def generate_jwt_key_pair(isECDSA=True):
        """
        NOTE:
        A one-time use only function, to create a pair of RSA/ECDSA private-key and public key for sigining.
        The private_key will be used by the auth server for signing JWT tokens.
        The public_key will be used by the proxy-server for verifing JWT tokens.
        """

        # create the pair - since these keys are the base for the verifcation of a client and are highly vital,
        # 4096-bit RSA keys will be used (although, generally 2048-bit is ok too)
        if isECDSA:
            private_key = ec.generate_private_key(curve=ec.SECP256R1())
        else:
            private_key = rsa.generate_private_key(public_exponent=65537, key_size=AUTH_KEYS_SIZE)

        public_key = private_key.public_key()
        private_key_path = os.getenv("AUTH_SERVER_PRIVATE_KEY_FILE_PATH")
        public_key_path = os.getenv("PROXY_SERVER_PUBLIC_KEY_FILE_PATH")

        # to pem
        priv_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )


        #save both
        try:
            with open(private_key_path, "wb") as f1:
                f1.write(priv_pem)
            
            with open(public_key_path, "wb") as f2:
                f2.write(public_pem)
        except Exception as e:
           db_logger.critical(f"Couldn't save Auth key pair to disk: {e}", exc_info=True)


if __name__ == "__main__":
    EncryptionManager.generate_jwt_key_pair()
    # text = "hello world 1234567"
    # PRIVATE_KEY = b"it is my secret password12345678" # 256-bit (32-bytes) key for best encrypton aes-256
    # NONCE = b"good to try!" # 12-bytes nonce best accordig to NIST recommendation
    # print("start text:", text)

    # c1 = EncryptionManager(PRIVATE_KEY, NONCE)
    # encrypted_text = c1.aes_encrypt(text)
    # c2 = EncryptionManager(PRIVATE_KEY, NONCE)
    # message = c2.aes_decrypt(encrypted_text)
    # print("after text: ", message)

    # dh1, dh1_public = EncryptionManager.get_dh_public_key()
    # dh2, dh2_public = EncryptionManager.get_dh_public_key()

    # sk1 = EncryptionManager.get_dh_shared_key(dh1, dh2_public)
    # sk2 = EncryptionManager.get_dh_shared_key(dh2, dh1_public)
    # print("shared key 1: ", sk1)
    # print("shared key 2: ", sk2)
    
    # """
    # should output:
    # hello world 1234567
    # hello world 1234567
    # same
    # same

    # test checked - vlaid code
    # """