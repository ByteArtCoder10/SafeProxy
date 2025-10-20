import socket
import threading
import logging

logging.basicConfig(level=logging.INFO, filename='D:/SafeProxy/src/logs/safe_proxy.log', filemode='w',
                     format="%(asctime)s - %(levelname)s - %(message)s")

class ProxyListener:
    '''
    listens for incoming connections, and handels them based on type of request.
    '''

    def __init__(self, ip: str, port: int):
        self.__ip = ip
        self.__port = port
        self.__serversocket = None
        self.__clients = []
    
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
        pass

pl1 = ProxyListener('127.0.0.1', 215)
pl1.start(1000)    
    
