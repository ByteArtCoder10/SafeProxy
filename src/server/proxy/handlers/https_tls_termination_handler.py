# DEPARCHED - Use HttpsTlsTerminationSSL instead.



import socket
import threading
import datetime

from tlslite.api import X509, TLSConnection, HandshakeSettings, X509CertChain, parsePEMKey
from tlslite.utils.python_rsakey import Python_RSAKey
from tlslite.errors import *

from ..certificate.certificate_authority import CertificateAuthority
from .base_handler import BaseHandler
from ..structures.request import Request
from ..structures.response import Response
from ..core.parser import Parser
from ..handlers.https_tcp_tunnel_handler import HttpsTcpTunnelHandler
from ...logs.loggers import core_logger


class HttpsTlsTerminationHandler(BaseHandler):
    """
    Implements TLS Termination. A handler to preform TLS termination
    on a given client. 
    
    Acts as a Transparent Proxy.
    Intercepting the ClientHello to identify the target host (SNI).
    After that, Generating a made-on-the-fly certificate for that host using the CA.
    If successfull, Terminating the client's TLS connection and establishing a new 
    secure connection to the destination server. After secure tunnel with both peers,
    Relaying decrypted traffic for inspection and filtering.
    """
    
    def __init__(self, ca : CertificateAuthority):
        """
        Initializes the termination handler with a Certificate Authority.

        :type ca: CertificateAuthority
        :param ca: The CA instance used for on-the-fly certificate generation.
        """
        super().__init__()
        self._ca_authority = ca

    '''handles the process by routing and calling methods by order.'''
    def process(self, req: Request, client_socket: socket):
        """
        Executes the TLS termination. Responsible for calling various tasks:
        1. Sending a 200 "Connection Established" to the client.
        2. extracting SNI from client hello.
        3. getting made-on-the-fly cert from CA.
        4. blacklist + malice URL checking.
        5. Resume TLS handshake with client, and establishing secure connection.
        6. Getting Client's request
        7. Establishing a secure connection with server
        8. Relaying data bidrectionally.
        
        :type req: Request
        :param req: Initial CONNECT request.

        :type client_socket: socket.socket
        :param client_socket: The raw TCP socket from the client.
        """
        try:
            before = datetime.datetime.now()
            self._client_socket = client_socket
            # send a 200 Connection Established response to client
            self._respond_to_client(req, 200, isConnectionEstablished=True)
            
            # get ClientHello SNI
            client_hello_length = self._get_record_length()
            client_hello_data = self._recvall(client_hello_length, msg_peek=True) # msg_peek?
            sni = self._extract_sni_from_client_hello(client_hello_data)

            # check SNI for blacklist or malicious    
            if self.url_manager.is_blacklisted(sni, self._username) or \
            self.url_manager.is_malicious(sni):
                self._respond_to_client(req, 403, addBlackListHTML=True)
            
            # 
            else:
                # Create a 'on-the-fly' cert
                cert_pem, priv_key_pem, root_ca_cert_pem = self._ca_authority.get_certificate_for_host(sni)

                # create a tlslite.ng object with cert and private key
                tlslite_cert_chain, tlslite_priv_key =self._set_client_tlslite_object(cert_pem, priv_key_pem, root_ca_cert_pem)

                # resume tls handshake
                raw_request = self._resume_tls_conenction(tlslite_cert_chain, tlslite_priv_key)
                core_logger.info(raw_request)

                # parse raw request into a Request obj
                client_request = Parser.parse_request(raw_request.decode())
                
                # handshake server
                handshake_success = self._perform_tls_hanshake_with_server(client_request)

                if handshake_success:
                    # send first 'push'
                    self._tls_server_connection.send(client_request.to_raw())
                    # Only run relay if we actually have a secure connection
                    self._run_relay_data()
                else:
                    core_logger.error("Aborting relay due to failed server handshake.")
                    self._close_sockets(self._tls_client_connection, self._tls_server_connection)
            after = datetime.datetime.now()
            core_logger.info(f"TIME IT TOOK TLS_TLSLITE-NG - {after}-{before}")
        
        except (ConnectionAbortedError, ConnectionResetError):
            core_logger.info("Client Unexpectedly closed conenction. Handled gracefully.")
        
        finally:
            self._close_sockets(self._tls_client_connection, self._tls_server_connection)

        
    
    # PROXY-CLIENT FUNCTIONS
  
    def _resume_tls_conenction(self, tlslite_cert_chain: X509CertChain, tlslite_priv_key: Python_RSAKey):
        self._tls_client_connection = TLSConnection(self._client_socket)
        core_logger.info("past connection")
        try:
            # explicitly tell the client proxy support http/1.1
            self._tls_client_connection.handshakeServer(
                certChain=tlslite_cert_chain, 
                privateKey=tlslite_priv_key, 
                alpn=[b'http/1.1']
            )
            core_logger.info("Handshake Success! Secure TLS connection is enabled.")
            # Read decrypted data
            request = self._tls_client_connection.read(self.BUFFER_SIZE)
            core_logger.info(f"client's request after tls termination: {request}")
            return request
        except Exception as e:
            core_logger.error(f'TLS connection failed: {e}', exc_info=True) 
    
    def _set_client_tlslite_object(self, cert: bytes, private_key: bytes, root_ca_cert: bytes):
        # Create tlslite-objects for storing private key and cert
        
        # host certifcate
        x509_host_cert = X509()
        x509_host_cert.parse(cert.decode())

        # root ca certificate
        x509_ca_root = X509()
        x509_ca_root.parse(root_ca_cert.decode())

        tlslite_cert_chain = X509CertChain([x509_host_cert, x509_ca_root])
        tlslite_private_key = parsePEMKey(private_key.decode(), private=True)
        return tlslite_cert_chain, tlslite_private_key

    # PROXY-SERVER FUNCTIONS


    def _perform_tls_hanshake_with_server(self, req: Request):
        # create socket obj
        self._server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server_socket.settimeout(5)
        self._server_socket.connect((req.host, 443))
        # tlslit-ng connection object
        self._tls_server_connection = TLSConnection(self._server_socket)
        
        try:
            # securely hahndshake server
            self._tls_server_connection.handshakeClientCert(serverName=req.host)
            core_logger.info("TLS handshake with server was successful!")
            return True
        except TLSAuthenticationError:
            core_logger.error("TLS hanshake with server failed. Server requires authentication.")
            return False
        except Exception as e:
            core_logger.error(f"TLS connection with server failed: {e}", exc_info=True)
            return False
        

    # PROXY-CLIENT-SERVER FUCNTIONS

    def _run_relay_data(self):
        """
        Starts two concurrent threads to handle bidirectional data flow:
        - Thread 1: Client to Serve
        - Thread 2: Server to Client
        
        Joins the threads and ensures sockets are cleaned up upon disconnection.
        """
        # recv from client -> send to server
        t1 = threading.Thread(
            target=self._relay_data,
            args=(self._tls_client_connection, self._tls_server_connection),
            daemon=True
        )

        # recv from server -> send to client
        t2 = threading.Thread(
            target=self._relay_data,
            args=(self._tls_server_connection, self._tls_client_connection),
            daemon=True
        )

        t1.start()
        t2.start()

        # wait for both threads ot finish before closing sockets
        t1.join()
        t2.join()

        self._close_sockets(self._tls_client_connection, self._tls_server_connection)
    
    def _relay_data(self, recv_socket: TLSConnection, send_socket: TLSConnection):
        """
        The worker method for relay threads. Continuously receives raw bytes 
        from one socket and transmits them to another.

        :type recv_socket: ssl.SSLSocket
        :param recv_socket: The source socket to read from.

        :type send_socket: ssl.SSLSocket
        :param send_socket: The destination socket to write to.
        """

        recv_socket.settimeout(None)
        send_socket.settimeout(None)
        while True:
            try:
                data = recv_socket.read(self.BUFFER_SIZE)
                if not data:
                    break #connection was closed
                send_socket.write(data)


            except Exception as e:
                core_logger.debug(f"Neglible relay error.")
    

    # -- HELPERS ---

    def _get_record_length(self) -> int | None:
        """
        Get record length of the ClientHello, without removing the
        data from the buffer.
        
        :rtype: int | None
        :return: The length of the TLS record if found, otherwise None.
        """
        try:
            record_header = self._recvall(5, msg_peek=True)
            record_len = int.from_bytes(record_header[3:5], "big")
            return record_len + 5
        
        except Exception as e:
            core_logger.warning("Couldn't get length ClientHello, TLS record.")
            return None

    def _extract_sni_from_client_hello(self, data: bytes) -> str | None:
        """
        Performs a deep inspecrtion on the raw TLS ClientHello 
        to extract the SNI extension. This allows the CA to 
        generate a specific certificate for the actual domain
        the client is trying to reach, before the client even
        sends an HTTP request.

        :var data: bytes
        :param data: The raw ClientHello data from the client socket.

        :rtype: str | None
        :returns: The SNI if found, otherwise None.
        """

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
        # --every field marked as 'dynamic' has a 1/2 bytes of length field containing length
        #   of following field data ahead in bytes
        # --basically SSl 1.0 - 3.0 and TLS 1.0-1.1 are dead and
        #  webservers reject them so this function handling structure of TLS 1.2/1.3 is completely fine.
        
        # TLS record header must start with handshake type
        try:
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
                    core_logger.debug(f"SNI :{hostname.decode()}")
                    return hostname.decode()

                pos += 4 + ext_len
        
        except Exception as e:
            core_logger.warning(f"Failed extracting SNI from Client Hello: {e}", exc_info=True)
        
        return None
    
    def _recvall(self, length: int, *, msg_peek = False) -> bytes:
        """
        A helper function that ensures recieving exactly 'length' bytes from the socket.

        :type length: Optional[bool]
        :param msg_peek: If true, recieves the data without removing it from the buffer.

        :rtype: bytes
        :returns: the raw data recieved.

        :raises Connection Error: If connection aborted/closed unexpectedly.
        """
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