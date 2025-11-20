import socket
import logging

from .base_handler import BaseHandler
from ..structures.request import Request
from ..structures.response import Response

class HttpHandler(BaseHandler):
    '''Handle HTTP requests, or HTTPS after decryption.'''

    '''Handle a client request: forward if allowed, else send 403.'''
    def handle(self, req: Request, client_socket : socket):
        self._client_socket = client_socket
        url  = req.host + req.path
        if self.url_validator.is_blacklisted(url) or \
        self.url_validator.is_malicious(url): 
            self._send_reject_response(req)
        else:
            self._forward_request(req)



    '''Forward the request to the target server via the client socket.'''
    def _forward_request(self, req: Request):
        try:
            request = req.to_raw()
            self._client_socket.sendall(request.encode('utf-8'))

        except socket.timeout as e:
            logging.warning(f"Timeout error: {e}", exc_info=True)
        except Exception as e:
            logging.warning(f"Unexpected Error: {e}", exc_info=True)

