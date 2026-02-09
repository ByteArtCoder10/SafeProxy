import socket
import threading
import os
import subprocess
from ...logs.logger import client_logger
from ...client_constants import MAX_CLIENTS, SOCKET_BUFFER_SIZE, HTTP_AUTH_HEADER_NAME, PROXY_SERVER_PORT, INJECT_SERVER_PORT, PROXY_SERVER_IP, CHROME_PROPILE_DATA_PATH, CHROME_EXE_PATH
from .parser import Parser
from .request import Request
class InjectServer:
    """
    A local client-side proxy that intercepts browser requests, 
    injects the 'SafeProxy-Auth' JWT header, and tunnels the traffic 
    to the upstream SafeProxy server.
    """
    
    def __init__(self, token : str):
        """
        :param proxy_ip: The IP address of the main SafeProxy server.
        """
        self._bind_ip  : str = "127.0.0.1"
        self._bind_port : int = INJECT_SERVER_PORT
        self._proxy_ip : str = PROXY_SERVER_IP
        self._proxy_port : int = PROXY_SERVER_PORT
        self.token : str = token
        self._running : bool = False
    
    def start_inject_server(self, change_ui_when_finished):
        """
        Starts the local Inject Server in a background thread 
        using the given JWT.

        :param token: the JWT token to start inject server with

        :return bool: True if setting up injectServer and connecting to
        proxy server successful, otherwise False.
        """
        client_logger.info("Starting Inject Server.")
        
        # Asuming proxy and auth_server sit on same IP, we can use auth_Server ip
        # to connect the inject server to the proxy.
        
        self.inject_server_thread = threading.Thread(
            target=self._start,
            args=(change_ui_when_finished,),
            daemon=True
        )
        self.inject_server_thread.start()

    def _start(self, change_ui_when_finished) -> None:
        """
        Starts the Inject Server listener loop. check if reachable.
        """

        self._running = True
        
        try:
            self._server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            
            # Allow reusing the address if the server restarts quickly
            self._server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._server_socket.bind((self._bind_ip, self._bind_port))
            self._server_socket.listen(MAX_CLIENTS)

            client_logger.info(f"Server up at ({self._bind_ip},{self._bind_port})")
            client_logger.info(f"Forwarding to Proxy at ({self._proxy_ip},{self._proxy_port})")
            
            # Check if proxy is even reachable, in order for the UI to show a suitable status
            try:
                test_socket = socket.create_connection((self._proxy_ip, self._proxy_port), timeout=2)
                test_socket.close()
                client_logger.info("[InjectServer] Test connection to proxy was successfull.")
                change_ui_when_finished(True, "CONNECTED TO PROXY")
     
            except Exception:
                change_ui_when_finished(False, "CONNECTION FAILED")
                self.stop()
                return
            
            # If connection successfull, open a new chrome windowthat set in advance to connect to proxy.
            self._run_new_chrome_proccess()
            
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
            client_logger.critical(f"Critical Error: {e}", exc_info=True)
        finally:
            self.stop()

    def _run_new_chrome_proccess(self):
        try:
            profile_path = r"C:\Temp\SafeProxyBrowser"

            subprocess.Popen([ # popen in bacjgorund
                CHROME_EXE_PATH,
                f"--proxy-server=127.0.0.1:{INJECT_SERVER_PORT}",
                f"--user-data-dir={CHROME_PROPILE_DATA_PATH}"
            ])
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
            client_logger.warning(f"Failed to open a dedicated Chrome browser with proxy configuration: {e.stderr}", exc_info=True)
            
    def stop(self, change_ui_when_finished=None):
        self._running = False
        try:
            if hasattr(self, '_server_socket'):
                self._server_socket.close()

            client_logger.info("[InjectServer] Disconnected from proxy, and shutting off Inject Server.")
            change_ui_when_finished(False, "DISCONNECTED") if change_ui_when_finished else None
        except Exception:
            pass

    # --- PER CLIENT FUNCTIONS ---
    
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
                    client_logger.info("Added Proxy-Auth header to client's request.")

                    modified_data = parsed_req.to_raw()
                else:
                    # if failed to parse, send witout auth header
                    modified_data = request_data
            
            except Exception as e:
                client_logger.critical(f"Parsing error, sending without Proxy-Auth-header: {e}", exc_info=True)
                modified_data = request_data

            # Connect to proxy:
            # Creating a new connection for each new connection allows the proxy
            # to filter requests and connections based on (ip, port, host) for client_logger porpuses
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
            client_logger.error(f"Connection Handler Error: {e}", exc_info=True)
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
        
        def _relay_data(recv_socket: socket.socket, send_socket: socket.socket):
            while True:
                try:
                    data = recv_socket.recv(SOCKET_BUFFER_SIZE)
                    if not data:
                        break # Connection closed by recv_socket
                    send_socket.sendall(data)
                except (ConnectionResetError, BrokenPipeError, OSError):
                    # If recv_socket peer closed just loop back and try to recv again 
                    # until the socket is actually dead.
                    continue
            
            connection_active = False

        # InjectServer -> Proxy
        t1 = threading.Thread(target=_relay_data, args=(client_socket, proxy_socket))
        t1.daemon = True
        
        # Proxy -> InjectServer
        t2 = threading.Thread(target=_relay_data, args=(proxy_socket, client_socket))
        t2.daemon = True

        t1.start()
        t2.start()

        t1.join()
        t2.join()
    
