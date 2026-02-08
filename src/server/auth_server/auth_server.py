import socket
import threading
import os
import json
from dataclasses import dataclass
from enum import Enum

from ..constants import MAX_CLIENTS, SOCKET_BUFFER_SIZE, AUTH_SERVER_PORT
from ..logs.loggers import db_logger
from ..auth_server.encryption_manager import EncryptionManager
from ..db.sql_auth_manager import SQLAuthManager
from ..auth_server.jwt_manager import JWTManager

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
    
    def __repr__(self) -> str:
        class_name = self.__class__.__name__ + "\n"
        attrs = ''.join([f"{k}: {v}\n" for k,v in self.__dict__.items()])
        return class_name + attrs

class ReqCMD(Enum):
    # Auth proccess
    LOGIN = "LOGIN"
    SIGNUP =  "SIGNUP"
    DELETE = "DELETE"

    # blacklist proccess
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
    blacklist : dict | None = None
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
        
        except Exception:
            return cls(status=RspStatus.FAIL, fail_reason=FailReason.INVALID_FORMAT)

class AuthServer:
    """
    The Authentication Server.
    
    Responsible for:
    - Listeing for incoming connections.
    - Perforing Diffie-Hellman Key Exchange with clients.
    - Validating credentials against SQL DB.
    - Issuing JWT tokens signed with a ECDSA/RSA private key.
    """

    def __init__(self, ip: str, port: int):
        self._ip = ip
        self._port = port
        self._db = SQLAuthManager()
        self._auth_priv_key = self._load_priv_key()
        self._server_socket: socket.socket | None = None

    def start(self):
        """
        Starts the server listener loop.
        """
        try:
            self._server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._server_socket.bind((self._ip, self._port))
            self._server_socket.listen(MAX_CLIENTS)
            
            db_logger.info(f"Auth Server running on ({self._ip}, {self._port})")

            while True:
                client_sock, addr = self._server_socket.accept()
                threading.Thread(target=self.handle_client, args=(client_sock, addr), daemon=True).start()
                db_logger.info(f"Auth Thread started for client - ({addr[0]}, {addr[1]})")

        except Exception as e:
            db_logger.critical(f"Auth Server error: {e}", exc_info=True)
        finally:
            if self._server_socket:
                self._server_socket.close()

    def handle_client(self, client_socket: socket.socket, addr: tuple[str, int]):
        """
        Handles a single client session: Key Exchange -> Decrypt -> Validate -> Respond.
        """
        try:
            # Establish secore connection
            shared_key = self._perform_key_exchange(client_socket)
            aes_key = EncryptionManager.derive_key_from_dh_key(shared_key)
            em = EncryptionManager(aes_key)
            db_logger.info(f"Established secure connection with ({addr[0]}, {addr[1]})")
            
            while True:
                # Receive encrypted request
                try:
                    encrypted_data = client_socket.recv(SOCKET_BUFFER_SIZE)
                    if not encrypted_data: 
                        break
                except (ConnectionResetError, OSError, BrokenPipeError):
                    db_logger.info(f"Client ({addr[0]}, {addr[1]}) closed connection. Closing gracefully.")
                    break
                
                # decrypt + format request
                json_req = em.aes_decrypt(encrypted_data)
                request = FormattedReq.from_json(json_req)
                db_logger.debug(f"Client ({addr[0]}, {addr[1]}): {request.__repr__()}") # REMOVE EVENTUALLY
                
                # Process request
                response = self._process_request(request)
                db_logger.debug(f"Auth server response: {response.__repr__()}") # REMOVE EVENTUALLY

                # encrypt + send
                encrypted_rsp = em.aes_encrypt(response.to_json())
                client_socket.sendall(encrypted_rsp)
                db_logger.info(f"Response sent to {addr}")

        except Exception as e:
            db_logger.error(f"Failed handling client ({addr[0]}, {addr[1]}): {e}", exc_info=True)
        
        finally:
            client_socket.close()
            db_logger.info(f"Closed connection with {addr}.")

    def _perform_key_exchange(self, client_socket: socket.socket) -> bytes | None:
        """Performs DH exchange: Receives client PK, sends server PK, returns shared secret."""
        try:
            client_pk = client_socket.recv(256)
            dh, server_pk = EncryptionManager.get_dh_public_key()
            client_socket.sendall(server_pk)
            return EncryptionManager.get_dh_shared_key(dh, client_pk)
        except Exception as e:
            db_logger.error(f"Failed performing DH  with client: {e}", exc_info=True)
            return None

    def _process_request(self, req: FormattedReq) -> FormattedRsp:
        """Validates credentials and generates JWT/fetch blacklist if valid."""
        try:            
            # length validation - just incase UI failed to check/bypassed.
            if len(req.username) < 3 or len(req.username) > 30:
                return FormattedRsp(status=RspStatus.FAIL, fail_reason=FailReason.INVALID_USERNAME_LEN)
            
            match req.cmd:
                
                # signup
                case ReqCMD.SIGNUP:
                    if self._db.username_exist(req.username):
                        return FormattedRsp(status=RspStatus.FAIL, fail_reason=FailReason.USER_EXISTS)
                    self._db.save_user(req.username, req.pw)

                # login
                case ReqCMD.LOGIN:
                    if not self._db.username_exist(req.username):
                        return FormattedRsp(status=RspStatus.FAIL, fail_reason=FailReason.USER_DOESNT_EXIST)
                
                    if not self._db.check_psssword(req.username, req.pw):
                        return FormattedRsp(status=RspStatus.FAIL, fail_reason=FailReason.WRONG_PW)

                # delete
                case ReqCMD.DELETE:
                    if self._db.delete_user(req.username):
                        return FormattedRsp(RspStatus.SUCCESS)
                    return FormattedRsp(RspStatus.FAIL, fail_reason=FailReason.DB_ERROR)
                
                # add blacklist host
                case ReqCMD.ADD_BLACKLISTED_HOST:
                    if self._db.add_host_to_blacklist(
                    req.username, req.blacklisted_host, req.blacklist_host_details):
                        return FormattedRsp(RspStatus.SUCCESS)
                    return FormattedRsp(RspStatus.FAIL,fail_reason=FailReason.DB_ERROR)
                
                # delete blacklist host
                case ReqCMD.DELETE_BLACKLISTED_HOST:
                    if self._db.delete_host_from_blacklist(
                    req.username, req.blacklisted_host):
                        return FormattedRsp(RspStatus.SUCCESS)
                    return FormattedRsp(RspStatus.FAIL,fail_reason=FailReason.DB_ERROR)

                # delete full blacklist
                case ReqCMD.DELETE_ALL_BLACKLSITED:
                    if self._db.delete_blacklist(req.username):
                        return FormattedRsp(RspStatus.SUCCESS)
                    return FormattedRsp(RspStatus.FAIL,fail_reason=FailReason.DB_ERROR)
                
                # get full blacklist
                case ReqCMD.GET_BLACKLIST:
                    bl = self._db.get_blacklist(req.username)
                    db_logger.debug(bl)
                    if bl or bl == {}:
                        return FormattedRsp(RspStatus.SUCCESS, blacklist=bl)
                    return FormattedRsp(RspStatus.FAIL, fail_reason=FailReason.DB_ERROR)
                
                case _:
                    return FormattedRsp(RspStatus.FAIL,fail_reason=FailReason.INVALID_FORMAT)
                
        except Exception as e:
            print(f"A DB error occured. returning FAIL: {e}")
            return FormattedRsp(status=RspStatus.FAIL, fail_reason=FailReason.DB_ERROR)

        
        # Token creation
        try: 
            token = JWTManager.create_token(self._auth_priv_key, req.username)
            if not token:
                return FormattedRsp(status=RspStatus.FAIL, fail_reason=FailReason.JWT_ERROR)

            return FormattedRsp(status=RspStatus.SUCCESS, jwt_token=token)
        
        except Exception as e:
            print(f"A JWT error occured. returning FAIL: {e}")
            return FormattedRsp(status=RspStatus.FAIL, fail_reason=FailReason.JWT_ERROR)
        
    def _load_priv_key(self) -> str | None:
        try:
            path = os.getenv("AUTH_SERVER_PRIVATE_KEY_FILE_PATH")
            with open(path, "r") as f:
                data = f.read()
            
            db_logger.info("Successfully Loaded private key for sigining JWT tokens.")
            return data

        except Exception:
            db_logger.critical("Could not load Auth Private Key! JWT generation will fail: {e}.", exc_info=True)
            return None

if __name__ == "__main__":
    server = AuthServer(os.getenv("PROXY_BIND"), AUTH_SERVER_PORT)
    server.start()