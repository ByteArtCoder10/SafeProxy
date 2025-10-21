import socket
import threading
import logging


BUFFER_SIZE =  4096
HTTP_SUPPORTED_METHODS = ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'PATCH']
class ProxyListener:
    '''
    listens for incoming connections, and handels them based on type of request.
    '''

    def __init__(self, ip: str, port: int):
        self.__ip = ip
        self.__port = port
        self.__server_socket = None
        self.__clients = []
    
    '''starts the server and routes http/s requests.'''
    def start(self, clients_capacity: int, ) -> None:
        try:    
            self.__server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.__server_socket.bind((self.__ip, self.__port))
            logging.info(f"server is up at {self.__ip, self.__port}.")

            self.__server_socket.listen(clients_capacity)
            while True:
                    
                client_socket, client_address = self.__server_socket.accept()
                logging.info(f"client connected - {client_address}.")

                self.__clients.append((client_socket, client_address))
                client_thread = threading.Thread(target=self.handle_client_request, args=(client_socket, client_address))
                client_thread.daemon=True
                client_thread.start()
                logging.info(f"Thread started for client - {client_address}.")

        except Exception as e:
            logging.error(f"Unxpected Error: {e}", exc_info=True)
    
    def handle_client_request(self, client_socket: socket, client_address: tuple):
        try:
            request = client_socket.recv(BUFFER_SIZE)
            if not request:
                raise Exception("client request failed.")
            logging.info(request)
            first_line = request.split('\r\n')[0]

            method = first_line.split(' ')[0]
            if not method:
                raise Exception("Could not get request method.")
            
            if method == 'CONNECT':
                #Route to HttpsTlsInterceptionHandler/HttpsTcpTunnelhandler - 
                #depend on client's Prefrence.
                pass
            if method in HTTP_SUPPORTED_METHODS:
                # Route to HttpHandler - property of this class? or that can be here?
                pass 
        except Exception as e:
            logging.warning(e)

pl1 = ProxyListener('127.0.0.1', 2153)
pl1.start(1000)    
    
