import socket
from http import HTTPMethod
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
    def route_request(self, req: Request, client_socket: socket) -> None:
        method = req.method
        if method == "CONNECT": 
            #if user wants url-filtering
                # self.httpsTlsTerminationHandler
            # elif user only cares about hiding his IP
            if True:
                self.httpsTcpTunnelHandler.establish_tunnel_server(req, client_socket)
        
        elif self.is_valid_http_method(method):
            self.httpHandler.handle(req, client_socket)
                

    def is_valid_http_method(self, method: str) -> bool:
        if method == "CONNECT":
            # CONNECT is handled seperatly
            return False
        try:
            HTTPMethod[method]
            return True
        except Exception:
            return False
         
        