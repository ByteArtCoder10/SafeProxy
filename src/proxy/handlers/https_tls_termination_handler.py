import socket

class HttpsTlsTerminationHandler:
    
    def __init__(self):
        pass

    def process(self):
        clinet_hello = self.get_client_hello()
        sni = self.get_SNI()
    
    def get_client_hello(self):
        pass
    def get_SNI(self):
        pass
