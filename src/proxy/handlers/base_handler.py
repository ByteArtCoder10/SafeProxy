import socket
import ssl
import socket

from abc import ABC, abstractmethod
from ...constants import SOCKET_BUFFER_SIZE
from ..structures.request import Request
from ..structures.response import Response
from ..structures.connection_status import ConnectionStatus
from ..security.url_manager import UrlManager
from ...logs.loggers import core_logger
        
class BaseHandler(ABC):
    """
    An abstract base class that defines the core interface and shared utility 
    methods for all proxy request handlers. It provides mechanisms for 
    forwarding data, responding to clients, and centralized error handling.

    :var Optional[socket] client_socket: 
    Socket that will be used to communicate with the client.
    
    :var Optional[socket] server_socket: 
    Socket that will be used to communicate with the server.
    
    :var UrlManager url_manager: 
    Helper field used for URL Blacklist and malice checks, as well as redirect URLS creations.
     """

    BUFFER_SIZE = SOCKET_BUFFER_SIZE
    """The standard chunk size for reading and writing to network sockets."""

    def __init__(self):
        self._client_socket = None
        self._server_socket = None
        self.url_manager = UrlManager()

        
    def handle(self, req: Request, client_socket: socket):
        """
        The primary entry point for the handler. Responsible for handling the request 
        by calling the concrete 'process' implementation.

        :type req: Request
        :param req: The initial parsed request from the client.

        :type client_socket: socket.socket
        :param client_socket: The active communication socket for the client.
        """
        try:
            # self.create_logger(req, client_socket)
            return self.process(req, client_socket)
        except ConnectionError as e:
            core_logger.critical(f"Handler Crashed. {e}")
        

    # def create_logger(self, req, client_socket):
    #     # 1. Identify the user
    #     try:
    #         addr, port = client_socket.getpeername()

    #         # 2. Get the specific logger
    #         core_logger = LoggerManager.create_connection_logger(addr, port, req.host)

    #         core_logger.info(f"New request to {req.host} from {addr}:{port}")
    #     except Exception as e:
    #         raise ConnectionError(f"Failed to load connection logger. {e}") from e
    
    @abstractmethod
    def process(self, req : Request, client_socket : socket.socket | ssl.SSLSocket):
        return NotImplemented
    
    def _connect_to_server(self, req: Request, googleSearchRedirect: bool) -> ConnectionStatus:
        """
        Tries to establish an un-encrypted connection with server.

        :type req: Request
        :param req: containing host and port's server to connect to.

        :type googleSearchRedirect: bool
        :param googleSearchRedirect: if True, the function returns a Redirect instruction.

        :rtype: ~ConnectionStatus
        :returns: a connection instruction for parent function 

        """
        try:
            self._server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._server_socket.settimeout(5) # if server doesn't respond in 5s, terminate conenction
            self._server_socket.connect((req.host, req.port))

            return ConnectionStatus.SUCCESS
        
        # DNS resolution failed / other Errors -> redirect/send 502
        except Exception:
            if googleSearchRedirect:
                return ConnectionStatus.REDIRECT_REQUIRED # Redirect to google search
            
        return ConnectionStatus.CONENCT_FAILURE
    
    def _forward_request(self, req: Request):
        """
        Arranges and transmits an HTTP request to the server.

        :type req: Request
        :param req: The request object to be forwarded.
        
        :raises TimeoutError: If the server socket times out during transmission.
        :raises Exception: For general transmission failures.
        """
        try:
            raw_req = req.to_raw()
            self._server_socket.sendall(raw_req)
        except socket.timeout as e:
            raise TimeoutError(f"Connection timed-out while trying to forward request: {e}") from e
        except Exception as e:
            raise Exception(f"Forwarding request failed: {e}") from e

    def _respond_to_client(
        self,
        req: Request,
        client_socket : socket.socket | ssl.SSLSocket,
        status_code: int,
        *,
        isConnectionEstablished : bool=False,
        redirectURL : str | None =None,
        addBlackListLabelHTML : bool =False,
        addMaliciousLabelHTML: bool =False):

        """
        Constructs and sends an HTTP response back to the client. This method 
        handles various proxy scenarios including tunnel confirmation, 
        automatic search redirection, and proxy block pages for blacklisted sites.

        :type req: Request
        :param req: The original client request (used for protocol versioning).

        :type client_socket: socket.socket | ssl.SSLSocket
        :param client_socket: The client's communication channel - both unecnrpyted and encrpyted sockets supported.

        :type status_code: int
        :param status_code: The HTTP status code to return.

        :type isConnectionEstablished: bool
        :param isConnectionEstablished: If True, sends a 200 'Connection 
                                         Established' response for TLS tunnels.

        :type redirectURL: str | None
        :param redirectURL: If provided, generates a 200 'OK' response with an 
                            HTML-based redirect to the specified URL.

        :type addBlackListLabelHTML: bool
        :param addBlackListLabelHTML: If True, attaches a standard 'Blocked' 
                                      landing page to the response body.

        :type addMaliciousLabelHTML: bool
        :param addMaliciousLabelHTML: If True, attaches a 'Malicious Content' 
                                      warning page to the response body.

        :raises ConnectionError: If the response cannot be sent to the client.
        """

        if isConnectionEstablished and status_code == 200:
            response = Response(
                req.http_version,
                status_code,
                reason="Connection Established",
                raw_connect=True
            )
        
        elif redirectURL and status_code == 200:
            response = Response(
                req.http_version,
                status_code,
                redirect_url=redirectURL
            )
        else:
            response = Response(req.http_version, status_code)
            if addMaliciousLabelHTML:
                response._add_dynamic_body(addMaliciousLabel=True)
            elif addBlackListLabelHTML:
                response._add_dynamic_body()

        core_logger.debug(response.prettify())
        try:
            client_socket.sendall(response.to_raw())
        except Exception as e:
            raise ConnectionError(f"Responding to client failed: {e}") from e

        '''closes socket objects (origin server and client).'''            
    
    def _close_sockets(self):
        """
        Safely closes both the client and server sockets to release system 
        resources and terminate the connection session. 
        """
        for sock in (self._client_socket, self._server_socket):
            if sock:
                try:
                    sock.close()
                except:
                    pass

        core_logger.info("Client and server's sockets closed.")