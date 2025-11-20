import socket
import threading
import logging

from .base_handler import BaseHandler
from ..structures.request import Request
from ..structures.response import Response


class HttpsTcpTunnelHandler(BaseHandler):
    """
    Handles HTTPS CONNECT requests by creating a TCP tunnel
    and relaying encrypted data in both directions. 
    """

    def __init__(self):
        super().__init__()
        self.running = False

    # parnet method routing and calling methods by order.
    def handle(self, req: Request, client_socket: socket):
        self._client_socket = client_socket
        url  = req.host + req.path
        if self.url_validator.is_blacklisted(url) or \
        self.url_validator.is_malicious(url):
            pass
            # need to tls terminate the connection - a response that is not 200
            # Connection Established will result with ERR_TUNNEL_CONNECTION_FAILED
        self._establish_tunnel_server(req)
        self._send_connection_established(req)
        self._run_tunnel_relay()
    
    '''establish a TCP conenction between the given server and the proxy.'''
    def _establish_tunnel_server(self, req: Request):
        try:
            self._server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._server_socket.connect((req.host, req.port))

            logging.info(
                f"Tunnel established: client={self._client_socket.getpeername()} "
                f"server=({req.host}, {req.port})"
            )

        except Exception as e:
            logging.error(f"Failed to connect to server: {e}", exc_info=True)
            raise # raise error to parent method
    
    '''sends to client a 200 Connection Established repsonse after TCP tunnel was successfully established.'''
    def _send_connection_established(self, req: Request):
        try:
            response = Response(
                req.http_version, 
                200,
                reason="Connection Established",
                raw_connect=True).to_raw()

            self._client_socket.sendall(response.encode("utf-8"))
        except Exception as e:
            logging.warning(f"Unexpected error: {e}", exc_info=True)

    '''handles client and server communication in tcp tunneling, allowing both sides to send data simultaneously using threads.'''
    def _run_tunnel_relay(self):
        self.running = True

        t1 = threading.Thread(
            target=self._relay_data,
            args=(self._client_socket, self._server_socket),
            daemon=True)

        t2 = threading.Thread(
            target=self._relay_data,
            args=(self._server_socket, self._client_socket),
            daemon=True)

        t1.start()
        t2.start()

        # wait for both threads ot finish before closing sockets
        t1.join()
        t2.join()

        self._close_sockets()

    '''handles continous sending and recieving data over sockets.'''
    def _relay_data(self, recv_socket: socket, send_socket: socket):
        peer_name = None

        try:
            peer_name = recv_socket.getpeername()

            while self.running:
                data = recv_socket.recv(BaseHandler.BUFFER_SIZE)

                if not data:
                    break #connection was closed
                send_socket.sendall(data)

        except Exception as e:
            logging.debug(f"Relay error ({peer_name}): {e}")

        # stop both threads
        self.running = False

    '''closes socket objects (origin server and client).'''            
    def _close_sockets(self):
        for sock in (self._client_socket, self._server_socket):
            if sock:
                try:
                    sock.close()
                except:
                    pass

        logging.info("Tunnel closed.")

