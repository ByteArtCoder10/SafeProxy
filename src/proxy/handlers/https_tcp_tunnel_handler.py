import socket
import threading
from .base_handler import BaseHandler
from ..structures.request import Request
from ..structures.connection_status import ConnectionStatus
from ..structures.response import Response
from ...logs.loggers import core_logger
from ...logs.proxy_context import ProxyContext


class HttpsTcpTunnelHandler(BaseHandler):
    """
    Handles HTTPS CONNECT requests by establishing a TCP tunnel. 
    This handler relays raw, encrypted data between a client and a remote 
    server without performing TLS termination or inspection. 
    """

    def __init__(self):
        super().__init__()
        self.running = False

    def process(self, req, client_socket,*, googleSearchRedirect: bool =True):
        """
        Respnsible for tunnel creation and maintnence: checks for blacklited URLS, 
        establishes the tinnel, confirms the tunnel to the 
        client (200 'Connection Established'), and begins bidirectional data relay.

        :type req: Request
        :param req: The parsed CONNECT request containing server's host and port.

        :type client_socket: socket.socket
        :param client_socket: The active client communication socket.

        :type googleSearchRedirect: bool = True
        :param googleSearchRedirect: If true, in case of Connection error, the proxy redirects the client to google search 
        with host as the query.
        """
        self._client_socket = client_socket

        url = req.host + req.path

        if self.url_manager.is_blacklisted(url):
            core_logger.info("URL requested is blacklisted. TLS-Terminating and sending 403 blacklisted.")
            # TLS termination -> send 403 Blacklisted
            return
        if self.url_manager.is_malicious(url):
            core_logger.info("URL requested is malicious. TLS-Terminating and sending 403 malicious.")
            # TLS termination -> send 403 malicious
            return
        
        try:
            conn_status = self._connect_to_server(req, googleSearchRedirect)
            match conn_status:
                case ConnectionStatus.SUCCESS:
                    self._respond_to_client(req, self._client_socket, 200, isConnectionEstablished=True)
                    self._run_tunnel_relay()
                    return
                case ConnectionStatus.REDIRECT_REQUIRED:
                    core_logger.debug(f"Connection failed for {req.host}. Redirecting to Google.")
                    # TLS Termination -> Send Redirection repsponse
                    pass

                case ConnectionStatus.CONNECT_FAILURE:
                    core_logger.info(f"Connection failed for {req.host}. TLS-Terminating and Sending 502.")
                    # TLS Termination -> Send 502 Bad Request.
                    pass

        except Exception as e:
            core_logger.critical(f"Handler Error: {e}", exc_info=True)
            # Safe fallback - try to send to client 502 "Bad Request"
            try:
                # TLS Termination -> send 502
                pass
            except:
                self._close_sockets() # Close connection
    

    def _run_tunnel_relay(self):
        """
        Starts two concurrent threads to handle bidirectional data flow:
        - Thread 1: Client to Server (Upstream)
        - Thread 2: Server to Client (Downstream)
        
        Joins the threads and ensures sockets are cleaned up upon disconnection.
        """
        self.running = True

        t1 = threading.Thread(
            target=self._handle_relay_data,
            args=(self._client_socket, self._server_socket, ProxyContext.get_local()),
            daemon=True)

        t2 = threading.Thread(
            target=self._handle_relay_data,
            args=(self._server_socket, self._client_socket, ProxyContext.get_local()),
            daemon=True)

        t1.start()
        t2.start()

        # wait for both threads ot finish before closing sockets
        t1.join()
        t2.join()

        self._close_sockets()
    

    def _handle_relay_data(self, recv_socket: socket, send_socket: socket, local_thread_vars : dict):
        """wrapper class for handling new threads operations, and relays data"""
        # force local thread variables on thread
        ProxyContext.set_local(local_thread_vars)
        # relay data
        self._relay_data(recv_socket, send_socket)
        
    def _relay_data(self, recv_socket: socket, send_socket: socket):
        """
        The worker method for relay threads. Continuously receives raw bytes 
        from one socket and transmits them to another.

        :type recv_socket: socket.socket
        :param recv_socket: The source socket to read from.

        :type send_socket: socket.socket
        :param send_socket: The destination socket to write to.
        """
        # forcing in this thread the local variables
  
        # setting timeout to 30s in case of keep-alive connection
        recv_socket.settimeout(30)
        send_socket.settimeout(30)

        try:
            peer_name = recv_socket.getpeername()

            while self.running:
                data = recv_socket.recv(BaseHandler.BUFFER_SIZE)

                if not data:
                    break # connection was closed
                send_socket.sendall(data)

        except Exception as e:
            core_logger.debug(f"Negligible relay error ({peer_name}).")

        # stop both threads
        self.running = False





