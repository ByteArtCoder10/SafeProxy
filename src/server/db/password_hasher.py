import os
import hashlib
import hmac

class PassswordHasher:

    @staticmethod
    def hash_new_password(password) -> tuple[bytes, bytes]:
        """
        Hash the provided password with a randomly-generated salt and return the
        salt and hash to store in the database.
        """
        salt = os.urandom(16)
        pw_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
        return salt, pw_hash

    @staticmethod
    def is_correct_password(salt, password, pw_hash):
        """
        Given a previously-stored salt and hash, and a password provided by a user
        trying to log in, check whether the password is correct.
        """
        return hmac.compare_digest(
            pw_hash,
            hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
        )

if __name__=='__main__':
    salt, pw_hash = PassswordHasher.hash_new_password('abcd1234')
    salt2, pw_hash2 = PassswordHasher.hash_new_password('1q2w3e')
    print(PassswordHasher.is_correct_password(salt, 'abcd1234', pw_hash)) # True
    print(PassswordHasher.is_correct_password(salt2, '1q2w3e', pw_hash2)) # True
    print(PassswordHasher.is_correct_password(salt, 'password', pw_hash)) # False
    print(PassswordHasher.is_correct_password(salt, 'password2', pw_hash2)) # False
    