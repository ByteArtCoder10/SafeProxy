import socket
import threading
import logging
from ..structures.request import Request
from ..structures.response import Response
from ...constants import BUFFER_SIZE

class HttpsTcpTunnelHandler:
    '''
    Creates a TCP tunnel between client and server, 
    allowing bidrectional end-to-end encryption between them.
    '''

    def __init__(self):
        self.client_socket : socket = None

    '''establish a tcp conenction between the given server, and informing the client (successfull/not).'''
    def establish_tunnel_server(self, req: Request, client_socket : socket):
        try:
            self.client_socket = client_socket
            client_address = self.client_socket.getpeername()
            host_ip, host_port = req.host, req.port
            
            # remote connection
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.connect((host_ip, host_port))
            logging.info(f"Successfully established a TCP tunnel: \
            \nweb server: {host_ip}, {host_port} \nclient: {client_address[0]}, {client_address[1]}")
        
            # making 200 ok respnse, and sending it to the client
            response = Response(req.http_version, 200, reason="Connection Established", raw_connect=True).to_raw()
            logging.debug(response)
            client_socket.sendall(response.encode('utf-8'))

            # starting tunnel loop
            self.run_tunnel_realy()
        except Exception as e:
            logging.warning(f"Unexpected error: {e}", exc_info=True)

    '''handles client and server communication in tcp tunneling, allowing both sides to send data simultaneously using threads.'''
    def run_tunnel_realy(self):
        client_to_server_thread = threading.Thread(target=self.recieve_and_send_data, args=(self.client_socket, self.server_socket))
        server_to_client_thread = threading.Thread(target=self.recieve_and_send_data, args=(self.server_socket, self.client_socket))

        client_to_server_thread.daemon = True
        server_to_client_thread.daemon = True

        client_to_server_thread.start()
        server_to_client_thread.start()
    
    '''handles continous sending data over sockets.'''
    def recieve_and_send_data(self, recv_socket : socket, send_socket):
        try:
            while True:
                raw_data = recv_socket.recv(BUFFER_SIZE)
                if raw_data:
                    send_socket.sendall(raw_data)
        except (ConnectionAbortedError, ConnectionResetError):
            logging.info(f"Connection closed by peer {recv_socket.getpeername()}")
        except Exception as e:
            self.end()
            logging.error(f"Unexpected error: {e}", exc_info=True)



    '''ends communication between client and server.'''            
    def end(self):
        if self.client_socket:
            try:
                self.client_socket.close()
            except Exception:
                self.client_socket = None
        if self.server_socket:
            try:
                self.server_socket.close()
            except Exception:
                self.server_socket = None
        logging.info("Closed client and server sockets.")

    
    
    

        
