import socket
import logging

from .base_handler import BaseHandler
from ..structures.request import Request
from ..structures.response import Response

class HttpHandler(BaseHandler):
    '''Handle HTTP requests, or HTTPS after decryption.'''

    '''Handle a client request: forward if allowed, else send 403.'''
    def process(self, req: Request, client_socket : socket):
        self._client_socket = client_socket

        url  = req.host + req.path
        if self.url_manager.is_blacklisted(url):
            self._respond_to_client(req, 403, addBlackListHTML=True)
        elif self.url_manager.is_malicious(url):
            self._respond_to_client(req, 403, addMaliciousHTML=True)

        else:
            try:
                self._server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self._server_socket.settimeout(5)
                self._server_socket.connect((req.host, req.port))
            except socket.gaierror:
                # DNS resolution failed - request header wasn't valid
                # 2 options based on user prefrences: 1. redirect to google search 2. show 502 error
                # if user_prefrence = google_src:
                # HTML Body that handles the redirect
                google_search_url = self.url_manager.get_google_url(req.host)
                self._respond_to_client(req, 200, redirectURL=google_search_url)
                return
                
            except Exception as e:
                logging.info(f"Failed to connect to {req.host}:{req.port}")
                # send a 502 "Bad Request" response
                self._respond_to_client(req, 503)
                return
            
            self._forward_request(req)
            self.forward_response(req.host)
    
    '''forward raw response from origin server back to client'''
    def forward_response(self, host):
        # # self._server_socket.settimeout(1)
        s = self._server_socket.recv(8192)
        logging.info(s)
        self._client_socket.sendall(s)
        # try:
        #     while True:
        #         chunk = self._server_socket.recv(BaseHandler.BUFFER_SIZE)
        #         if not chunk:
        #             break
        #         if (host =='neverssl.com'):
        #             logging.info(f"chunk: {chunk}")
        #         self._client_socket.sendall(chunk)

        # except socket.timeout:
        #     # normal for keep-alive connections
        #     pass
        # except Exception as e:
        #     logging.warning(f"Failed to forward webserver response to client: {e}")





