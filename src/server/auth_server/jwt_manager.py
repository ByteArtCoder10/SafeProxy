import jwt
import datetime

class JWTManager:
    """
    Static utility for creating and verifying JWT.
    """

    @staticmethod
    def create_token(jwt_auth_private_key: str, username: str, isECDSA=True) -> str | None:
        """
        Signs a new JWT with a 30-minute expiration.
        uses RSA/ECDSA to sign the tokens.
        if isECDSA true signs with ecdsa, oterwise RSA.
        """
        try:
            now = datetime.datetime.now(datetime.timezone.utc)
            payload = {
                "sub": username,
                "iat": now,
                "exp": now + datetime.timedelta(minutes=30)
            }
            
            alg = "ES256" if isECDSA else "RS256"
            
            # sign
            return jwt.encode(payload=payload, key=jwt_auth_private_key, algorithm=alg)
        except Exception:
            return None
    
    @staticmethod
    def verify_token(jwt_auth_public_key: str, jwt_token: str, isECDSA=True) -> bool:
        """
        Verifies signature and expiration of a JWT.
        signature-wise: uses RSA/ECDSA to verify the tokens
        time-wise: verifies that the token is not expired.
        if isECDSA true verifies with ecdsa, oterwise RSA. 
        """
        try:
            payload = jwt.decode(
                    jwt=jwt_token,
                    key=jwt_auth_public_key,
                    algorithms="ES256" if isECDSA else "RS256",
                    options={"verify_signature": True}
            )
            return True
        except Exception:
            return False