import socket
import threading
import logging
from .parser import Parser
from .router import Router
from ...constants import SOCKET_BUFFER_SIZE as BUFFER_SIZE
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

    '''starts the server and routes http/s requests.'''
    def start(self, clients_capacity: int) -> None:
        try:
            self._server_socket = socket.socket(
                socket.AF_INET, socket.SOCK_STREAM)
            self._server_socket.bind((self._ip, self._port))
            logging.info(f"server is up at {self._ip, self._port}.")

            self._server_socket.listen(clients_capacity)
            while True:

                client_socket, client_address = self._server_socket.accept()
                logging.info(f"client connected - {client_address}.")

                self._clients.append((client_socket, client_address))
                client_thread = threading.Thread(
                    target=self.handle_client_request, args=(client_socket, client_address))
                client_thread.daemon = True
                client_thread.start()
                logging.info(f"Thread started for client - {client_address}")

        except Exception as e:
            logging.warning(f"Unexpected error:\n{e}", exc_info=True)

    '''Handles client requst'''
    def handle_client_request(self, client_socket: socket, client_address: tuple) -> None: 
        try:
            client_request = client_socket.recv(BUFFER_SIZE).decode('utf-8')
            logging.debug(f"A request from {client_address}:\n{client_request}")
            
            # Returns a Request obj 
            parsed_request = self._parser.parse_request(client_request)
            self._parser
            # Route based on request
            self._router.route_request(parsed_request, client_socket)

        except Exception as e:
            logging.warning(f"Unexpected Error: {e}", exc_info=True)
 


