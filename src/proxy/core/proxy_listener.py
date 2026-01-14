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
    """
    The primary network listener for SafeProxy.
    
    Responsible for initializing the socket server, accepting incoming 
    TCP connections, and creating a thread for each client.
    It manages the lifecycle of the Certificate Authority and calls 
    Parser, Router in order to parse HTTP/S requests and route them 
    to the appropriate handlers.
    """

    def __init__(self, ip: str, port: int):
        """
        Initializes the listener with network identity and routing components.


        :type ip: str
        :param ip: The local IP address to bind the server to.

        :type port: int
        :param port: The port to listen on
        """
        self._ip = ip
        self._port = port
        self._server_socket = None
        self._clients = []
        self._parser = Parser
        self._router = Router()
        self._ca = CertificateAuthority()


    def setup_and_start_proxy(self):
        """
        A safety measure in case the proxy can't start.
        """

        try:
            self.start()
        except Exception as e:
            core_logger.critical(f"SafeProxy crashed! {e}.", exc_info=True)
    

    def start(self) -> None:
        """
        Binds ans setups the server socket, and responsible for accepting clients.
        Creates a new thread for every successful client connection.
        """
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
            
            # from ...logs.logging_manager import time_list, count_list, word_list
            # for i, time in enumerate(time_list):
            #     core_logger.critical(f"{word_list[i]} - average time - {time/count_list[i]}]")

        except Exception as e:
            core_logger.warning(f"Proxie's listener interuppted: {e}", exc_info=True)
        
        finally:
            if self._server_socket:
                self._server_socket.close()

    '''Handles client requst'''
    def handle_client_request(self, client_socket: socket, client_address: tuple[str, int]) -> None: 
        """
        Responsible for handling a client conn:
        Manages the lifecycle of a single client session.
        Sets up Thread-Local Context, parses the raw data, and routes the request.

        :type client_socket: socket.socket
        :param client_socket: The active socket connection with the client.

        :type client_address: tuple[str, int]
        :param client_address: (IP, Port).
        """
        try:
            # set thread vars - host not parsed yet.
            ProxyContext.set_local(None, client_address[0], client_address[1])
            ProxyContext.set_local(None, client_address[0], client_address[1])

            # set timeout - if client doesn't send data for 10 sec - terminate the connection
            client_socket.settimeout(10)

            client_request = client_socket.recv(BUFFER_SIZE).decode('utf-8', errors='ignore')
            if not client_request:
                core_logger.info("Client's didn't send an intial request.")
                return

            core_logger.debug(f"A request from {client_address}:\n{client_request}")
            
            # parse the request into a Request obj 
            parsed_request = self._parser.parse_request(client_request)
            
            # reset local thread vars -  updating it with host
            ProxyContext.set_local_host(parsed_request.host)
            core_logger.debug(f"Changed local variables: replaced 'PENDING' with {parsed_request.host}")

            # Route based on request
            self._router.route_request(parsed_request, client_socket, self._ca)

        except socket.timeout:
            core_logger.warning("conenction timed-out: Client connected, but never sent a request.")

        except Exception as e:
            core_logger.error(f"Unexpected Error: {e}", exc_info=True)

        finally:
            #clean thrad_vars and gracefully close conn
            ProxyContext.clear_local()
            if client_socket:
                client_socket.close()
    


