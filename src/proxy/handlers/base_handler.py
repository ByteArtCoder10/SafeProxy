import socket
import logging

from abc import ABC, abstractmethod
from ...constants import SOCKET_BUFFER_SIZE
from ..structures.request import Request
from ..structures.response import Response
from ..security.url_valdiator import UrlValidator

class BaseHandler(ABC):

    BUFFER_SIZE = SOCKET_BUFFER_SIZE
    def __init__(self):
        self._client_socket = None
        self._server_socket = None
        self.url_validator = UrlValidator()
        
    
    @abstractmethod
    def handle(self,req: Request, client_socket: socket):
        pass
        
    
    '''Send a 403 Forbidden response with HTML body.'''
    def _send_reject_response(self, req: Request):
        try:
            response = Response(req.http_version, 403)
            response._add_dynamic_body()
            response = response.to_raw()
            self._client_socket.sendall(response.encode('utf-8'))

        except Exception as e:
            logging.warning(f"Unexpected Error: {e}", exc_info=True)