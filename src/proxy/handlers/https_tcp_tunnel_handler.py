import socket
import threading
import logging
from ..structures.request import Request
class HttpsTcpTunnelHandler:
    
    '''establish a tcp conenction between the given server, and informing the client (successfull/not).'''
    def establish_tunnel_server(self, req: Request, client_socket : socket) -> bool:
        try:
            client_address = client_socket.gethostname()
            host_ip, host_port = req.get_dest_host(), req.get_dest_port()
            
            # remote connection
            proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            proxy_socket.connect((host_ip, host_port))
            logging.info(f"Successfully established a TCP tunnel: \
                         \nweb server: {host_ip}, {host_port} \nclient:\
                           {client_address[0]}, {client_address[1]}")
            return True
        except Exception as e:
            logging.warning(f"Unexpected error: {e}", exc_info=True)
        return False
    
    
    

        
