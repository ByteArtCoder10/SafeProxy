import socket
from ..structures.request import Request
from ..structures.response import Response
from ..handlers.http_handler import HttpHandler
from ..handlers.https_tcp_tunnel_handler import HttpsTcpTunnelHandler
from ..handlers.https_tls_termination_handler import HttpsTlsTerminationHandler

class Router():
    
    def __init__(self):
        self.httpHandler = HttpHandler()
        self.httpsTcpTunnelHandler = HttpsTcpTunnelHandler()
        self.httpsTlsTerminationHandler = HttpsTlsTerminationHandler()

    '''Routes request based on User prefences 
    (only want to hide his IP -> TCP tunnel, wants filtering URL -> TLS termination)
    and also based on request method(CONNECT/GET...)'''
    def RouteRequest(self, req: Request, client_socket: socket) -> None:
        if (req.method == "CONNECT"): 
            #if user wants url-filtering
                # self.httpsTlsTerminationHandler
            # elif user only cares about hiding his IP
            if True:
                if self.httpsTcpTunnelHandler.establish_tunnel_server(req, client_socket):
                    response = Response(req.http_version, "200").to_raw()
                    client_socket.sendall(response.encode('utf-8'))
                

