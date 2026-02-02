import socket
import threading
import os

from ...constants import MAX_CLIENTS, SOCKET_BUFFER_SIZE, HTTP_AUTH_HEADER_NAME, PROXY_SERVER_PORT, INJECT_SERVER_PORT
from .parser import Parser
from .request import Request

class InjectServer:
    """
    A local client-side proxy that intercepts browser requests, 
    injects the 'SafeProxy-Auth' JWT header, and tunnels the traffic 
    to the upstream SafeProxy server.
    """
    
    def __init__(self, proxy_ip: str):
        """
        :param proxy_ip: The IP address of the main SafeProxy server.
        """
        self._bind_ip = "127.0.0.1"
        self._bind_port = INJECT_SERVER_PORT
        self._proxy_ip = proxy_ip
        self._proxy_port = PROXY_SERVER_PORT
        self.token = None
        self._running = False

    def start(self, session_token: str) -> None:
        """
        Starts the Inject Server listener loop.
        """
        self.token = session_token
        self._running = True
        
        try:
            self._server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            
            # Allow reusing the address if the server restarts quickly
            self._server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._server_socket.bind((self._bind_ip, self._bind_port))
            self._server_socket.listen(MAX_CLIENTS)

            print(f"[InjectServer] server up at ({self._bind_ip},{self._bind_port})")
            print(f"[InjectServer] Forwarding to Proxy at ({self._proxy_ip},{self._proxy_port})")

            while self._running:
                try:
                    client_socket, client_address = self._server_socket.accept()
                    # Handle each browser connection in a separate thread
                    client_thread = threading.Thread(
                        target=self.handle_client, 
                        args=(client_socket, client_address)
                    )
                    client_thread.daemon = True
                    client_thread.start()
                except Exception:
                    break

        except Exception as e:
            print(f"[InjectServer] Critical Error: {e}")
        finally:
            self.stop()

    def stop(self):
        self._running = False
        if hasattr(self, '_server_socket'):
            self._server_socket.close()

    def handle_client(self, client_socket: socket.socket, client_addr):
        """
        Handles a single client connection:
        - Reads the initial HTTP request.
        - Injects the auth header.
        - Connects to proxy.
        - Forwards the tokened request.
        - Enters a bidirectional relay loop (tunnel).
        """
        proxy_socket = None
        try:
            # Read Initial Request
            request_data = client_socket.recv(SOCKET_BUFFER_SIZE)
            
            if not request_data:
                client_socket.close()
                return

            request_str = request_data.decode('utf-8', errors='ignore')

            # Parse and inject Token
            try:
                parsed_req = Parser.parse_request(request_str)
                if parsed_req:
                    # Inject the token
                    parsed_req.add_header(HTTP_AUTH_HEADER_NAME, self.token)
                    modified_data = parsed_req.to_raw()
                else:
                    # if failed to parse, send witout auth header
                    modified_data = request_data
            
            except Exception as e:
                print(f"[InjectServer] Parsing error: {e}")
                modified_data = request_data

            # Connect to proxy:
            # Creating a new connection for each new connection allows the proxy
            # to filter requests and connections based on (ip, port, host) for logging porpuses
            proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            proxy_socket.settimeout(10)
            proxy_socket.connect((self._proxy_ip, self._proxy_port))

            # Forward the Initial req
            proxy_socket.sendall(modified_data)

                        
            # incase of keep-alive connection
            client_socket.settimeout(None)
            proxy_socket.settimeout(None)

            # Start Relay
            self._run_tunnel_relay(client_socket, proxy_socket)

        except Exception as e:
            # print(f"[InjectServer] Connection Handler Error: {e}")
            pass
        finally:
            if client_socket: client_socket.close()
            if proxy_socket: proxy_socket.close()
    
    def _run_tunnel_relay(self, client_socket : socket.socket, proxy_socket : socket.socket):
        """
        Starts two concurrent threads to handle bidirectional data flow:
        - Thread 1: Client to Serve
        - Thread 2: Server to Client
        
        Joins the threads and ensures sockets are cleaned up upon disconnection.
        """
        connection_active = True
        
        def _relay_data(self, recv_socket: socket.socket, send_socket: socket.socket):
            while connection_active:
                try:
                    data = recv_socket.recv(SOCKET_BUFFER_SIZE)
                    if not data:
                        break # Connection closed by recv_socket
                    send_socket.sendall(data)
                except (ConnectionResetError, BrokenPipeError, OSError):
                    # If the other peer closed just loop back and try to recv again 
                    # until the socket is actually dead.
                    continue
            
            connection_active = False

        # InjectServer -> Proxy
        t1 = threading.Thread(target=_relay_data, args=(client_socket, proxy_socket,))
        t1.daemon = True
        
        # Proxy -> InjectServer
        t2 = threading.Thread(target=_relay_data, args=(proxy_socket, client_socket,))
        t2.daemon = True

        t1.start()
        t2.start()

        t1.join()
        t2.join()
