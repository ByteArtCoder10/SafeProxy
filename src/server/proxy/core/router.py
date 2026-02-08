import socket
import logging
from http import HTTPMethod

from ...logs.loggers import core_logger
from ..structures.request import Request
from ..structures.response import Response
from ..handlers.http_handler import HttpHandler
from ..handlers.https_tcp_tunnel_handler import HttpsTcpTunnelHandler
# from ..handlers.https_tls_termination_handler import HttpsTlsTerminationHandler
from ..handlers.https_tls_termination_handler_ssl import HttpsTlsTerminationHandlerSSL
from ..certificate.certificate_authority import CertificateAuthority

class Router():
    """
    Determines the processing strategy for incoming client requests.
    
    The Router analyzes the HTTP method and configuration preferences 
    to dispatch the request to the appropriate protocol handler 
    (Plain HTTP, HTTPS Tunneling, or TLS Termination).
    """

    def route_request(self, req: Request, client_socket: socket.socket, ca  : CertificateAuthority, username : str) -> None:
        """
        Hands the request to a specific handler based on the HTTP method
        and configuration settings.

        :type req: Request
        :param req: The parsed Request object.

        :type client_socket: socket.socket
        :param client_socket: The source client socket.

        :type ca: CertifcateAuthority()
        :param ca: The CA's (singleton) instance for TLS-termination
        related tasks.
        
        :type username: str
        :param username: For blacklist blocking. at this point, the client is authorized, in order to check
        for blacklisted urls/hosts, the proxy queries the DB with a username.

        :raises ValueError: If an unsupported or invalid HTTP method is received, but catches the xception.
        """
        try:
            match req.method:
            
                case "CONNECT":                        
                    #if user wants url-filtering
                        # self.httpsTlsTerminationHandler
                    # elif user only cares about hiding his IP
                    if True:
                        # self.handler = HttpsTcpTunnelHandler(ca)
                        self.handler = HttpsTlsTerminationHandlerSSL(ca)
                    
                case req.method if self.is_valid_http_method(req.method):
                    self.handler = HttpHandler()

                case _:
                    core_logger.warning(f"Unsupported method in the request: {req.method}")
                    return 
                
            if self.handler:
                self.handler.handle(req, client_socket, username)
            else:
                raise ValueError("No suitable handler found for the request.")
            
        except socket.timeout:
            core_logger.info("Routing failed: socket timed-out.")
        except (ConnectionResetError, ConnectionAbortedError):
            core_logger.info(f"Client closed connection during routing.")
        except Exception as e:
            core_logger.error(f"Failed to route request: {e}", exc_info=True)
                
    def is_valid_http_method(self, method: str) -> bool:
        """
        Validates if a string is a recognized standard HTTP method.
        
        Note: CONNECT is ignored here as it is handled by specific 
        tunneling logic in route_request.
        """
        if method == "CONNECT":  # CONNECT is handled seperatly
            return False
        try:
            HTTPMethod(method)
            return True
        except Exception:
            return False
         
        