import socket
import logging

from abc import ABC, abstractmethod
from ...constants import SOCKET_BUFFER_SIZE
from ..structures.request import Request
from ..structures.response import Response
from ..security.url_manager import UrlManager

        
class BaseHandler(ABC):
    
    BUFFER_SIZE = SOCKET_BUFFER_SIZE

    def __init__(self):
        self._client_socket = None
        self._server_socket = None
        self.url_manager = UrlManager()

    
    def handle(self, req: Request, client_socket: socket):
        try:
            return self.process(req, client_socket)
        except Exception as e:
            logging.error(f"Handler crashed: {e}", exc_info=True)

    @abstractmethod
    def process(self, req, client_socket):
        pass

    '''Forward the request to the target server via the client socket.'''
    def _forward_request(self, req: Request):
        try:
            raw = req.to_raw()
            self._server_socket.sendall(raw.encode('utf-8'))
        except socket.timeout as e:
            logging.warning(f"Timeout when forwarding request: {e}", exc_info=True)
            raise
        except Exception as e:
            logging.error(f"Forwarding request failed: {e}", exc_info=True)
            raise

    '''Send a response back to the client.'''
    def _respond_to_client(
        self,
        req: Request,
        status_code: int,
        *,
        isConnectionEstablished=False,
        redirectURL=None,
        addBlackListHTML=False,
        addMaliciousHTML=False):

        try:
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
                if addMaliciousHTML:
                    response._add_dynamic_body(addMaliciousLabel=True)
                elif addBlackListHTML:
                    response._add_dynamic_body()
            logging.debug(response.prettify())
            self._client_socket.sendall(response.to_raw().encode("utf-8"))

        except Exception as e:
            logging.warning(f"Responding to client failed: {e}", exc_info=True)
            raise
