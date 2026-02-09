import socket
import json
import threading
from dataclasses import dataclass
from enum import Enum

from ...logs.logger import client_logger
from ...client_constants import AUTH_SERVER_PORT, SOCKET_BUFFER_SIZE
from .encryption_manager import EncryptionManager
from ..inject_server.inject_server import InjectServer

class BaseFormattedObj:
    def to_json(self) -> str:
        return json.dumps(self.__dict__, default=lambda x: x.value if isinstance(x, Enum) else x)
    
    @classmethod
    def from_json(cls):
        "virtual method. should be overriden."
        return NotImplemented
    
    @classmethod
    def from_dict(cls, data: dict):
        return cls(**data)

class ReqCMD(Enum):
    # Auth proccess
    LOGIN = "LOGIN"
    SIGNUP =  "SIGNUP"
    DELETE = "DELETE"

    # blacklist proccess - 
    ADD_BLACKLISTED_HOST = "ADD_BLACKLISTED_HOST"
    DELETE_BLACKLISTED_HOST = "DELETE_BLACKLISTED_HOST"
    DELETE_ALL_BLACKLSITED = "DELETE_ALL_BLACKLSITED"
    GET_BLACKLIST = "GET_BLACKLIST" 


class RspStatus(Enum):
    FAIL = "FAIL"
    SUCCESS =  "SUCCESS"

class FailReason(Enum):
    # sign up
    USER_EXISTS = "Username already exists."

    # login
    USER_DOESNT_EXIST = "Username doesn't exist." 
    WRONG_PW = "Wrong password."
    
    # Auth-general
    INVALID_USERNAME_LEN = "Username's length invalid."
    JWT_ERROR = "Failed generating JWT token."
    INVALID_PW_LEN = "Password's length invalid."
    

    # General
    DB_ERROR = "Database error."
    INVALID_FORMAT = "Request's format invalid."
    NETWORK_ERROR = "Network communication error."


@dataclass
class FormattedReq(BaseFormattedObj):
    cmd: ReqCMD
    username: str
    pw: str | None = None
    blacklisted_host : str | None = None
    blacklist_host_details : str | None = None
    
    @classmethod
    def from_json(cls, json_str: str):
        """
        Handle getting raw json {"cmd": "LOGIN"...} while serializing 
        a FormattedReq's attribute cmd with type str will fail (only accept ReqCMD).
        Function searches for key "cmd" after loading a dict from a json.
        """
        data = json.loads(json_str)
        
        if "cmd" in data and data["cmd"]: # data["cmd"] a safety measure for accidently None passed as cmd
            data["cmd"] = ReqCMD(data["cmd"])
            
        return cls.from_dict(data)

@dataclass
class FormattedRsp(BaseFormattedObj):
    status: RspStatus
    jwt_token: str | None = None
    blacklist: dict | None = None
    fail_reason: FailReason | None = None

    @classmethod
    def from_json(cls, json_str: str):
        """
        Handle getting raw json {"status": "FAIL", ... , "fail_reason": "Wrong password."}
        while serializing a FormattedRsp's attribute "status" and "fail_reason" with type
        str will fail since the class expectes Enum type and not str. 
        Function searches for key "status" & "fail_reason" after loading a dict from a json.
        """
        try:
            data = json.loads(json_str)

            # status 
            if "status" in data and data["status"]:
                data["status"] = RspStatus(data["status"])
            
            # fail reason
            if "fail_reason" in data and data["fail_reason"]:
                data["fail_reason"] = FailReason(data["fail_reason"])
            
            return cls.from_dict(data)
        
        except Exception as e:
            client_logger.error(e, exc_info=True)
            return cls(status=RspStatus.FAIL, fail_reason=FailReason.INVALID_FORMAT)

class AuthHandler:
    """
    Handles the authentication proccess between the Client and the Auth Server.
    
    Responsible fore:
    - Establishing secure socket connection (DH Key Exchange).
    - Sending formatted Login/Signup/Delete requests.
    - Handling the response and starting the InjectServer upon success.
    """
    
    def __init__(self, ip: str):
        """
        :param ip: Auth server's IP address.
        """
        self._server_ip = ip
        self._server_port = AUTH_SERVER_PORT
        self._client_socket: socket.socket | None = None
        self.em: EncryptionManager | None = None
        self.inject_server_thread: threading.Thread | None = None

    def connect(self) -> bool:
        """
        Connects to Auth server securely.        
        
        :return bool: True if successful, False otherwise.
        """
        try:
            self._client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._client_socket.connect((self._server_ip, self._server_port))
            client_logger.info(f"[Auth] Connected to Auth server at ({self._server_ip},{self._server_port})")

            self._establish_secure_connection()
            return True
        
        except Exception as e:
            client_logger.error(f"[Auth] Secure connection with Auth server failed: {e}")
            return False
        

    def _establish_secure_connection(self):
        """
        Performs Diffie-Hellman protocol to calculate a session AES key.
        """
        # local DH keys
        dh_self, self_pk = EncryptionManager.get_dh_public_key()
        
        # Exchange public keys
        self._client_socket.sendall(self_pk)
        server_pk = self._client_socket.recv(256) # DH public key set to 256-bytes intially
        
        # Calc shared secret and AES key
        shared_secret = EncryptionManager.get_dh_shared_key(dh_self, server_pk)
        aes_key = EncryptionManager.derive_key_from_dh_key(shared_secret)
        
        # Create EncryptonManager instance for AES-encrpyt/decrpyt.
        self.em = EncryptionManager(aes_key)
        client_logger.info("[Auth] Secure connection established.")

    def login(self, username: str, password: str) -> FormattedRsp:
        """
        API function - for UI to call. 
        Handles Login proccess (send Request -> Return Response)

        :return FormattedRsp: Auth server's response
        """
        req = FormattedReq(cmd=ReqCMD.LOGIN, username=username, pw=password)
        return self._send_and_get_rsp(req)

    def signup(self, username: str, password: str) -> FormattedRsp:
        """
        API function - for UI to call. 
        Handles Signup proccess (send Request -> Return Response)

        :return FormattedRsp: Auth server's response
        """
        req = FormattedReq(cmd=ReqCMD.SIGNUP, username=username, pw=password)
        return self._send_and_get_rsp(req)

    def delete(self, username: str) -> FormattedRsp:
        """
        API function - for UI to call. 
        Handles Delete proccess (send Request -> Return Response)

        :return FormattedRsp: Auth server's response
        """
        req = FormattedReq(cmd=ReqCMD.DELETE, username=username)
        return self._send_and_get_rsp(req)
    
    def add_blacklist_host(self, username : str, blacklisted_host : str, details: str)-> FormattedRsp:
        """
        API function - for UI to call. 
        Handles dding/updating a given host to a user's blacklist. (send Request -> Return Response)

        :return FormattedRsp: Auth server's response
        """
        req = FormattedReq(
            cmd=ReqCMD.ADD_BLACKLISTED_HOST,
            username=username,
            blacklisted_host=blacklisted_host,
            blacklist_host_details=details
        )
        return self._send_and_get_rsp(req)

    def delete_blacklist_host(self, username : str, blacklisted_host : str)-> FormattedRsp:
        """
        API function - for UI to call. 
        Handles deleting a given host froma user's blacklist (send Request -> Return Response)

        :return FormattedRsp: Auth server's response
        """
        req = FormattedReq(cmd=ReqCMD.DELETE_BLACKLISTED_HOST, username=username, blacklisted_host=blacklisted_host, )
        return self._send_and_get_rsp(req)
    
    def delete_full_blacklist(self, username : str,)-> FormattedRsp:
        """
        API function - for UI to call. 
        Handles deleting full blacklist of a user (send Request -> Return Response)

        :return FormattedRsp: Auth server's response
        """
        req = FormattedReq(cmd=ReqCMD.DELETE_ALL_BLACKLSITED, username=username)
        return self._send_and_get_rsp(req)
    
    def get_blacklist(self, username : str,)-> FormattedRsp:
        """
        API function - for UI to call. 
        Handles getting full blacklist of a user (send Request -> Return Response)

        :return FormattedRsp: Auth server's response
        """
        req = FormattedReq(cmd=ReqCMD.GET_BLACKLIST, username=username)
        return self._send_and_get_rsp(req)
    
    def _send_and_get_rsp(self, req: FormattedReq) -> FormattedRsp:
        """

        - Formats request
        - Encrypts it
        - Sends it to Auth server
        - Decrypts response
        - Formats response to a FormmatedRsp obj

        :type req: FormattedReq
        :param req: The request to send the the server. 

        :return FormattedRsp: The server's response.

        
        """
        client_logger.info(f"Client's request: {req.__dict__}")
        if not self._client_socket:
            if not self.connect():
                return FormattedRsp(status=RspStatus.FAIL, fail_reason=FailReason.NETWORK_ERROR)

        try:
            # Format, encrypt and send to server
            json_req = req.to_json()
            encrypted_req = self.em.aes_encrypt(json_req)
            self._client_socket.sendall(encrypted_req)

            # Receive rsp, decrypt it and format
            encrypted_rsp = self._client_socket.recv(SOCKET_BUFFER_SIZE)
            decrypted_rsp = self.em.aes_decrypt(encrypted_rsp)
            response = FormattedRsp.from_json(decrypted_rsp)
            
            
            return response

        except Exception as e:
            client_logger.warning(f"[Auth] Sending request/recieving response failed: {e}", exc_info=True)
            return FormattedRsp(status=RspStatus.FAIL, fail_reason=FailReason.NETWORK_ERROR)

    def _start_inject_server(self, token: str):
        """
        Starts the local Inject Server in a background thread 
        using the given JWT.

        :param token: the JWT token to start inject server with

        :return bool: True if setting up injectServer and connecting to
        proxy server successful, otherwise False.
        """
        client_logger.warning("[Auth] Starting Inject Server...")
        
        # Asuming proxy and auth_server sit on same IP, we can use auth_Server ip
        # to connect the inject server to the proxy.
        inject_server = InjectServer() 
        
        self.inject_server_thread = threading.Thread(
            target=inject_server.start, 
            args=(token,), 
            daemon=True
        )
        self.inject_server_thread.start()

if __name__ == "__main__":
    ah = AuthHandler("127.0.0.1", AUTH_SERVER_PORT)
    ah.connect_to_auth_server()
    ah._establish_secure_connection()
    ah.send_request_to_server(FormattedReq(ReqCMD.LOGIN, username="23ws42", pw="4545232332"))
    ah.handle_server_response()