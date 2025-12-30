import socket
import logging

from http import HTTPMethod
from ..structures.request import Request
from ..structures.response import Response
from ..handlers.http_handler import HttpHandler
from ..handlers.https_tcp_tunnel_handler import HttpsTcpTunnelHandler
from ..handlers.https_tls_termination_handler import HttpsTlsTerminationHandler


class Router():
    
    def __init__(self):
        self.handler = None

    '''Routes request based on User prefences 
    (only want to hide his IP -> TCP tunnel, wants filtering URL -> TLS termination)
    and also based on request method(CONNECT/GET...)'''
    def route_request(self, req: Request, client_socket: socket) -> None:
        try:
            method = req.method
            if method == "CONNECT": 
                #if user wants url-filtering
                    # self.httpsTlsTerminationHandler
                # elif user only cares about hiding his IP
                if True:
                    # self.handler = HttpsTcpTunnelHandler()
                    self.handler = HttpsTlsTerminationHandler()

            elif self.is_valid_http_method(method):
                self.handler = HttpHandler()

            # the handle function will return:
            #   - None, in case of regular http request, or CONNECT request
            #     aiming to establish a TCP tunnel. (HttpHandler/HttpTcpTunnelHandler)
            #
            #   - Request, in case of TLS termination. a return value
            #     is expected in order to establish a secure TCP tunnel between
            #     the proxy and the server requested.
            self.handler.handle(req, client_socket)

        except Exception as e:
            logging.error(f"Unexpected error: {e}", exc_info=True)
                

    def is_valid_http_method(self, method: str) -> bool:
        if method == "CONNECT":
            # CONNECT is handled seperatly
            return False
        try:
            HTTPMethod[method]
            return True
        except Exception:
            return False
         
        