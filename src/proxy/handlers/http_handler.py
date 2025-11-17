import socket
import logging
from ..structures.request import Request
from ..structures.response import Response
from ...constants import BUFFER_SIZE

BLACK_LIST = ['neverssl.com', 'httpforever.com']
class HttpHandler:
    "Handle HTTP requests, or HTTPS after decryption."

    '''Handle a client request: forward if allowed, else send 403.'''
    def handle(self, req: Request, client_socket : socket):
        if self.check_url(req, client_socket):
            self.forward_request(req, client_socket)
        else:
            self.send_reject_response(req, client_socket)

    '''Return True if the request URL is allowed, False if blacklisted.'''
    def check_url(self, req: Request, client_socket : socket) -> bool:
        if req.host.lower() in BLACK_LIST:
            return False
        # LATER ADD MALICIUS URLS CHECK
        return True

    '''Send a 403 Forbidden response with a simple HTML body.'''
    def send_reject_response(self, req: Request, client_socket: socket):
        try:
            response = Response(req.http_version, 403)
            response._add_dynamic_body()
            response = response.to_raw()
            client_socket.sendall(response.encode('utf-8'))

        except Exception as e:
            logging.warning(f"Unexpected Error:\n{e}", exc_info=True)

    '''Forward the request to the target server via the client socket.'''
    def forward_request(self, req: Request, client_socket: socket):
        try:
            client_socket.sendall(req.to_raw().encode('utf-8'))

        except Exception as e:
            logging.warning(f"Unexpected Error:\n{e}", exc_info=True)

