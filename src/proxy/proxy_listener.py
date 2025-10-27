import socket
import threading
import logging
from .http_handler import HttpHandler

BUFFER_SIZE = 8192
HTTP_SUPPORTED_METHODS = ['GET', 'POST', 'PUT',
                          'DELETE', 'HEAD', 'OPTIONS', 'PATCH']

class ProxyListener:
    '''
    listens for incoming connections, and handels them based on type of request.
    '''

    def __init__(self, ip: str, port: int):
        self.__ip = ip
        self.__port = port
        self.__server_socket = None
        self.__clients = []
        self.__http_handler = HttpHandler()

    '''starts the server and routes http/s requests.'''
    def start(self, clients_capacity: int, ) -> None:
        try:
            self.__server_socket = socket.socket(
                socket.AF_INET, socket.SOCK_STREAM)
            self.__server_socket.bind((self.__ip, self.__port))
            logging.info(f"server is up at {self.__ip, self.__port}.")

            self.__server_socket.listen(clients_capacity)
            while True:

                client_socket, client_address = self.__server_socket.accept()
                logging.info(f"client connected - {client_address}.")

                self.__clients.append((client_socket, client_address))
                client_thread = threading.Thread(
                    target=self.handle_client_request, args=(client_socket, client_address))
                client_thread.daemon = True
                client_thread.start()
                logging.info(f"Thread started for client - {client_address}")

        except Exception as e:
            logging.warning(f"Unexpected error:\n{e}", exc_info=True)


    def handle_client_request(self, client_socket: socket, client_address: tuple) -> None: 
        try:
            client_request = client_socket.recv(BUFFER_SIZE).decode('utf-8')
            logging.debug(f"A request from {client_address}:\n{client_request}")
            method, host, port, path, http_version = self.__http_handler.parse_request(client_request)
            # ---

            if method == 'CONNECT':
                # Route to HttpsTlsInterceptionHandler/HttpsTcpTunnelhandler -
                # depend on client's Prefrence.

                pass
            elif method in HTTP_SUPPORTED_METHODS:
                if host.lower() == "www.neverssl.com" or host.lower() == "neverssl.com":
                    response = self.__http_handler.generate_custom_response(http_version, 403)         
                else:
                    response = self.forward_request_and_get_response(host, port, client_request)
                self.respond_to_client(client_socket, client_address, response)

        except Exception as e:
            logging.warning(f"Unexpected Error:\n{e}", exc_info=True)

    '''send response to the client.'''
    def respond_to_client(self, client_socket: socket, client_address: tuple, response: str | bytes) -> None:
        try:
            if isinstance(response, str):
                response = response.encode('utf-8')
            client_socket.sendall(response)
            logging.info(f"Sent response to client at: {client_address}")
        except Exception as e:
            logging.warning(f"Unexpected Error:\n{e}", exc_info=True)

    '''transfer client's request to webserver and waits for the webserver's response.'''
    def forward_request_and_get_response(self, host: str, port: int, request: str) -> bytes:
        try:
            proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            proxy_socket.connect((host, port))

            #send request
            proxy_socket.sendall(request.encode('utf-8'))

            # wait for response
            response = proxy_socket.recv(BUFFER_SIZE)
            return response
        except Exception as e:
            logging.warning(f"Unexpected Error:\n{e}", exc_info=True)    


