import socket
import ssl
import threading
import os
import datetime

from ...constants import CERTS_DIR
from ..certificate.certificate_authority import CertificateAuthority
from .base_handler import BaseHandler
from ..structures.request import Request
from ..structures.response import Response
from ..core.parser import Parser
from ..handlers.https_tcp_tunnel_handler import HttpsTcpTunnelHandler
from ...logs.loggers import core_logger
from ...logs.proxy_context import ProxyContext


class HttpsTlsTerminationHandlerSSL(BaseHandler):

    def __init__(self, ca : CertificateAuthority):
        super().__init__()
        self._ca_authority = ca
        # create en empty ssl context
        self._server_ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        # get root ca's certifciate's path
        # root_ca_cert_dir = os.getenv("ROOT_CA_DIR")
        # self._root_ca_cert_path = os.path.join(root_ca_cert_dir, "root_ca.crt")
        # self._server_ssl_context.load_verify_locations(self._root_ca_cert_path)
        self._server_ssl_context.load_default_certs()
        # load cert ssl's context

    '''handles the process by routing and calling methods by order.'''
    def process(self, req: Request, client_socket: socket):
        before = datetime.datetime.now()
        self._client_socket = client_socket

        # create a deafult SSL context with client's socket

        # send a 200 Connection Established response to client
        self._respond_to_client(req, self._client_socket, 200, isConnectionEstablished=True)
        

        # get ClientHello SNI
        client_hello_length = self._get_record_length()
        client_hello_data = self._recvall(client_hello_length, msg_peek=True) # msg_peek?
        sni = self._extract_sni_from_client_hello(client_hello_data)
        


        # Create a 'on-the-fly' cert
        cert_path, key_path = self._ca_authority.get_certificate_for_host(sni)
        client_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        client_context.load_cert_chain(certfile=cert_path, keyfile=key_path)
        self._tls_client_connection = client_context.wrap_socket(self._client_socket, server_side=True)

        # check SNI for blacklist or malicious    
        if self.url_manager.is_blacklisted(sni) or \
        self.url_manager.is_malicious(sni):
            self._respond_to_client(req, self._tls_client_connection, 403, addBlackListLabelHTML=True)

        # add cert to ssl's context
        # resume tls handshake
        raw_request = self._resume_tls_conenction()
        if not raw_request:
            core_logger.error("No request from the client.")
            return
        core_logger.debug(f"Raw Request: {raw_request}")
        
        # parse raw request into a Request obj
        client_request = Parser.parse_request(raw_request.decode())
        
        # handshake server
        handshake_success = self._perform_tls_hanshake_with_server(client_request)
        if handshake_success:
            # send first 'push'
            self._tls_server_connection.sendall(client_request.to_raw())
            # Only run relay if we actually have a secure connection
            self._run_relay_data()
        else:
            core_logger.error("Aborting relay due to failed server handshake.")
            self._close_sockets()
        after = datetime.datetime.now()
        core_logger.info(f"TIME IT TOOK TLS_SSL - {after-before}")
        # override Base class method
    
        '''establish a TCP conenction between the given server and the proxy.'''
    
    # PROXY-CLIENT FUNCTIONS
  
    def _resume_tls_conenction(self):
        try:        
            self._tls_client_connection.do_handshake()
            core_logger.info("Handshake Success! Secure TLS connection is enabled.")
            
            # Read decrypted data
            raw_request = self._tls_client_connection.recv(self.BUFFER_SIZE)
            core_logger.debug(f"Cient's request after TLS termination: \n{raw_request.decode()}")
            return raw_request
        except Exception as e:
            raise ConnectionError(f'TLS connection failed: {e}') 
    

    # PROXY-SERVER FUNCTIONS


    def _perform_tls_hanshake_with_server(self, req: Request):
        # create socket obj
        self._server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_socket.settimeout(5)
        self._server_socket.connect((req.host, 443))
        # tlslit-ng connection object
        
        try:
            self._tls_server_connection = self._server_ssl_context.wrap_socket(self._server_socket, server_hostname=req.host)
            core_logger.debug(f"Successfully securely connected to server {req.host}.")
            return True
        # except ssl.ERROR:
        #     core_logger.error("TLS hanshake with server failed. Server requires authentication.")
        #     return False
        except Exception as e:
            core_logger.error(f"TLS connection with server failed: {e}", exc_info=True)
            return False
        

    # PROXY-CLIENT-SERVER FUCNTIONS

    def _run_relay_data(self):
        
        # recv from client -> send to server
        t1 = threading.Thread(
            target=self._handle_relay_data,
            args=(self._tls_client_connection, self._tls_server_connection, ProxyContext.get_local()),
            daemon=True
        )

        # recv from server -> send to client
        t2 = threading.Thread(
            target=self._handle_relay_data,
            args=(self._tls_server_connection, self._tls_client_connection, ProxyContext.get_local()),
            daemon=True
        )

        core_logger.debug("starts relaying data bidervtionally.")
        t1.start()
        t2.start()

        # wait for both threads ot finish before closing sockets
        t1.join()
        t2.join()

        self._close_sockets()
    
    def _handle_relay_data(self, recv_socket: ssl.SSLSocket, send_socket: ssl.SSLSocket, local_thread_vars : dict):
        """wrapper class for handling new threads operations, and relaying data"""
        # force local thread variables on thread
        ProxyContext.set_local(local_thread_vars)
        # relay data
        self._relay_data(recv_socket, send_socket)

    def _relay_data(self, recv_socket: ssl.SSLSocket, send_socket: ssl.SSLSocket):
        recv_socket.settimeout(None)
        send_socket.settimeout(None)
        try:
            peer_name = recv_socket.getpeername()

            while True:
                data = recv_socket.read(self.BUFFER_SIZE)
                if not data:
                    break #connection was closed
                send_socket.write(data)

        except Exception as e:
            core_logger.debug(f"Relay error ({peer_name}): {e}")
    
    '''closes socket objects (origin server and client).'''            
    def _close_sockets(self):
        for sock in (self._client_socket, self._server_socket):
            if sock:
                try:
                    sock.close()
                except:
                    pass

        core_logger.info("closed client's and server's sockets. Connection ended.")

    # HELPERS
    '''get reocrd length of a message'''
    def _get_record_length(self) -> tuple[bytes, int]:
        record_header = self._recvall(5, msg_peek=True)
        record_len = int.from_bytes(record_header[3:5], "big")
        return record_len + 5
    
    '''Extract the Server Name Indication (SNI) hostname
    from a raw TLS ClientHello message.'''
    def _extract_sni_from_client_hello(self, data: bytes) -> str | None:
        # Different protcol versions have different strucutre.
       # the client might send the ClientHello according to TLS 1.3/1.2.
        # some parts must stay the same across versions, in order for the other
        # side to be able to correctly parse the version used and act accordingly.
        # the protcol's identical parts needed for TLS termination are:
        # --Record header - (5 bytes) - {handshake record, protcol version, len of handshake message follows}
        # --Handshake Header - (4 bytes) -  {handshake msg type, len of clientHello msg follows}
        # --Client Version - (2 bytes)
        # --Client Random - (32 bytes) - skipped (content negelible)
        # --Session ID - (dynamic) - skipped
        # --Cipher Suites - (dynamic) - skipped
        # --Compression Methods - (dynamic) - skipped
        # --Extensions (SNI included) - (dynamic) - SNI

        # Notes: 
        # --the client version part is crucial since it represnets the protcol version
        #   that the following ClientHello will be structured by (and all protocol connection from that point on).
        # --every field marked as 'dynamic' has a 1\2 bytes of length field containing length
        #   of following field data ahead in bytes
        # --basically SSl 1.0 - 3.0 and TLS 1.0-1.1 are dead and
        #  webservers reject them so this function handling structure of TLS 1.2\1.3 is completely fine.
        
        # TLS record header must start with handshake type
        if len(data) < 5 or data[0] != 0x16:
            return None

        # Skip TLS record header (5 bytes)
        pos = 5

        # Handshake header must be ClientHello (0x01)
        if data[pos] != 0x01:
            return None
        
        pos += 4  # Skip handshake header (type + length)

        # Skip: version (2), random (32)
        pos += 2 + 32

        # Get length and skip: Session ID
        sess_len = data[pos]
        pos += 1 + sess_len

        # Get length and skip: Cipher Suites
        cs_len = int.from_bytes(data[pos:pos+2], "big")
        pos += 2 + cs_len

        # Get length and skip: Compression Methods
        comp_len = data[pos]
        pos += 1 + comp_len

        # Extensions Length
        ext_total_len = int.from_bytes(data[pos:pos+2], "big")
        pos += 2

        end = pos + ext_total_len

        # Parse each extension
        while pos + 4 <= end:
            ext_type = int.from_bytes(data[pos:pos+2], "big")
            ext_len = int.from_bytes(data[pos+2:pos+4], "big")
            ext_data = data[pos+4:pos+4+ext_len]

            # SNI extension == 0x0000
            if ext_type == 0x0000:
                # ServerNameList length
                sn_list_len = int.from_bytes(ext_data[0:2], "big")
                offset = 2

                # Parse first (usually only) server name entry
                name_type = ext_data[offset] # always DNS host_name
                name_len = int.from_bytes(ext_data[offset+1:offset+3], "big")
                hostname = ext_data[offset+3:offset+3+name_len]
                core_logger.debug(f"SNI :{hostname.decode('utf-8')}")
                return hostname.decode()

            pos += 4 + ext_len

        return None
    
    '''a helper function that ensures recieving exactly 'length' bytes from the socket'''
    def _recvall(self, length: int, *, msg_peek = False):
        data = b''
        remaining_bytes = length
        while remaining_bytes > 0:
            if msg_peek:
                chunk = self._client_socket.recv(remaining_bytes, socket.MSG_PEEK)
            else:
                chunk = self._client_socket.recv(remaining_bytes)

            if not chunk:
                raise ConnectionError(
                    "Socket connection closed unexpectedly - reading TLS Client Hello could not be completed")
            data += chunk
            remaining_bytes -= len(chunk)
        return data
