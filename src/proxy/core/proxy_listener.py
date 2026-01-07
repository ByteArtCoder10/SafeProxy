import socket
import threading
import logging
from .parser import Parser
from .router import Router
from ...constants import MAX_CLIENTS, SOCKET_BUFFER_SIZE as BUFFER_SIZE
from ...logs.logging_manager import LoggingManager
from ...logs.loggers import core_logger
from ...logs.proxy_context import ProxyContext
from ..certificate.certificate_authority import CertificateAuthority
HTTP_SUPPORTED_METHODS = ['GET', 'POST', 'PUT',
                          'DELETE', 'HEAD', 'OPTIONS', 'PATCH']

class ProxyListener:
    '''
    listens for incoming connections, and handels them based on type of request.
    '''

    def __init__(self, ip: str, port: int):
        self._ip = ip
        self._port = port
        self._server_socket = None
        self._clients = []
        self._parser = Parser
        self._router = Router()


    def setup_and_start_proxy(self):
        try:
            # set up Certifcate aouthority to have a singelton CA in all proxy
            self._ca = CertificateAuthority()
            self.start()
        except Exception as e:
            core_logger.critical(f"SafeProxy crashed! {e}.", exc_info=True)
    

    '''starts the server and routes http/s requests.'''
    def start(self) -> None:
        try:
            self._server_socket = socket.socket(
                socket.AF_INET, socket.SOCK_STREAM)
            self._server_socket.bind((self._ip, self._port))
            core_logger.info(f"server is up at {self._ip, self._port}.")

            self._server_socket.listen(MAX_CLIENTS)
            while True:

                client_socket, client_address = self._server_socket.accept()
                core_logger.info(f"client connected - {client_address}.")

                self._clients.append((client_socket, client_address))
                client_thread = threading.Thread(
                    target=self.handle_client_request, args=(client_socket, client_address))
                client_thread.daemon = True
                client_thread.start()
                core_logger.info(f"Thread started for client - {client_address}")

        except Exception as e:
            core_logger.warning(f"Unexpected error:\n{e}", exc_info=True)

    '''Handles client requst'''
    def handle_client_request(self, client_socket: socket, client_address: tuple) -> None: 
        try:
            # set thread vars - host not parsed yet.
            ProxyContext.set_local(None, client_address[0], client_address[1])

            client_request = client_socket.recv(BUFFER_SIZE).decode('utf-8')
            core_logger.debug(f"A request from {client_address}:\n{client_request}")
            
            # Returns a Request obj 
            parsed_request = self._parser.parse_request(client_request)
            
            # reset local thread vars -  updating it with host
            ProxyContext.set_local_host(parsed_request.host)

            # Route based on request
            self._router.route_request(parsed_request, client_socket, self._ca)

            
        except Exception as e:
            core_logger.warning(f"Unexpected Error: {e}", exc_info=True)

    
    def _set_thread_vars(self, host: str | None, ip : str, port: int):
        ProxyContext.set_local(host, ip, port)


