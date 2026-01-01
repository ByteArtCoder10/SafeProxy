import socket
import logging

from .base_handler import BaseHandler
from ..structures.request import Request
from ..structures.response import Response
from ..structures.connection_status import ConnectionStatus

class HttpHandler(BaseHandler):
    '''Handles HTTP requests'''

    def process(self, req: Request, client_socket : socket, *, googleSearchRedirect: bool =True):
        """
        Handles a client request based on URI requested.
        - URI blacklisted/malicious -> sends back to client 
        403 "Forbbiden" response, with customized HTML.
        - URI unresolved (DNS failure)  -> sends back a 200
        redirect response or 502 "Bad Response". 
        
        :type req: Request
        :param req: containing host and port's server to connect to.

        :type googleSearchRedirect: bool
        :param googleSearchRedirect: if True, the function returns a 200 request with
        """
        try:
            self._client_socket = client_socket
            url = req.host + (req.path or "")

            # Blacklist and malice checks
            if self.url_manager.is_blacklisted(url):
                self._respond_to_client(req, self._client_socket, 403, addBlackListLabelHTML=True)
                return
            
            if self.url_manager.is_malicious(url):
                self._respond_to_client(req, self._client_socket, 403, addMaliciousLabelHTML=True)
                return

            # Connection status management
            conn_status = self._connect_to_server(req, googleSearchRedirect=googleSearchRedirect)

            match conn_status:
                case ConnectionStatus.SUCCESS:
                    self._forward_request(req)
                    self.forward_response()
                
                case ConnectionStatus.REDIRECT_REQUIRED:
                    logging.debug(f"Connection failed for {req.host}. Redirecting to Google.")
                    google_search_url = self.url_manager.get_google_url(req.host)
                    self._respond_to_client(req, self._client_socket, 200, redirectURL=google_search_url)
                
                case ConnectionStatus.CONNECT_FAILURE:
                    logging.info(f"Connection failed for {req.host}. Sending 502.")
                    self._respond_to_client(req, self._client_socket, 502)

        except Exception as e:
            logging.critical(f"Handler Error: {e}", exc_info=True)
            # Safe fallback - try to send to client 502 "Bad Request"
            try:
                self._respond_to_client(req, self._client_socket, 502)
            except:
                self._close_sockets() # Close connection


 
          
    def forward_response(self):
        '''
        forwards raw data (response) from the server back to the client.

        :raises TimeoutError: If connection timed out.
        :raises ConnectionError: If conenction was closed/reset by either peer.
        :raises Exception: If an unexpected error occured.
        '''
        try:
            while True:
                # Read chunk from the server
                data = self._server_socket.recv(self.BUFFER_SIZE)
                # If data is empty, the server has finished sending
                if not data:
                    break
                # Forward the chunk to the client
                self._client_socket.sendall(data)
        except socket.timeout as e:
            raise TimeoutError(f"Connection timed out: {e}")
        except OSError as e:
            raise ConnectionError(e)
        except Exception as e:
            raise Exception(f"Unexpected error occured: {e}")