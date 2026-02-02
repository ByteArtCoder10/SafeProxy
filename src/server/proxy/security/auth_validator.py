import os
from ...logs.loggers import core_logger
from ...auth_server.jwt_manager import JWTManager
from ..structures.request import Request
from ...constants import HTTP_AUTH_HEADER_NAME
class AuthValidator:

    @staticmethod    
    def is_request_authorized(req: Request, auth_public_key : str) -> bool:
        if HTTP_AUTH_HEADER_NAME not in req.headers:
            return False
        
        token = req.headers[HTTP_AUTH_HEADER_NAME]
        if not token:
            return False
        
        return JWTManager.verify_token(jwt_auth_public_key=auth_public_key, jwt_token=token) 
    
    @staticmethod
    def fetch_auth_public_key() -> str | None:
        try: 
            # get path
            path = os.getenv("PROXY_SERVER_PUBLIC_KEY_FILE_PATH")

            with open(path, "r") as f:
                pk = f.read()
            
            core_logger.info("Successfully fetched Auth-public-key from disk.")
            core_logger.debug(f"Auth-pk: {pk}")

            return pk

        except Exception as e:
            core_logger.critical(f"Couldn't fetch auth-public-key from disk. Will not be able to identify and validate users! {e}", exc_info=True)
            return None