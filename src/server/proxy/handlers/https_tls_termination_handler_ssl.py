import socket
import ssl
import threading
import os
import datetime

from ...server_constants import CERTS_DIR
from ..certificate.certificate_authority import CertificateAuthority
from .base_handler import BaseHandler
from ..structures.request import Request
from ..structures.response import Response
from ..core.parser import Parser
from ...logs.loggers import core_logger
from ...logs.proxy_context import ProxyContext
from ..security.url_manager import UrlManager


class HttpsTlsTerminationHandlerSSL(BaseHandler):
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
        Initializes the termination handler with a Certificate Authority, and tht 
        cuncurrent thread closing with a running flag.

        :type ca: CertificateAuthority
        :param ca: The CA instance used for on-the-fly certificate generation.
        """

        super().__init__()
        self._ca_authority = ca
        self.running = False
        self._server_ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        self._server_ssl_context.load_default_certs()
        self._tls_client_connection = None
        self._tls_server_connection = None

    def process(self, req: Request, client_socket: socket, googleSearchRedirect: bool):
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
            abs_before = datetime.datetime.now()
            before = datetime.datetime.now()
            self._client_socket = client_socket


            # send a 200 Connection Established response to client
            self._respond_to_client(req, self._client_socket, 200, isConnectionEstablished=True)
            core_logger.debug(f"TIMECHECK0 - {datetime.datetime.now() - before}")
            before=datetime.datetime.now()

            # get ClientHello SNI
            client_hello_length = self._get_record_length()
            if not client_hello_length:
                return
            
            client_hello_data = self._recvall(client_hello_length, msg_peek=True)
            sni = self._extract_sni_from_client_hello(client_hello_data)
            if not sni:
                sni = req.host
            
            core_logger.debug(f"TIMECHECK1 - {datetime.datetime.now() - before}")
            before=datetime.datetime.now()


            # Create a 'on-the-fly' cert
            cert_path, key_path = self._ca_authority.get_certificate_for_host(sni) # if sno wasnt found - host
            core_logger.debug(f"TIMECHECK2 - {datetime.datetime.now() - before}")
            before=datetime.datetime.now()

            client_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            client_context.load_cert_chain(certfile=cert_path, keyfile=key_path)
            core_logger.debug(f"TIMECHECK3 - {datetime.datetime.now() - before}")
            before=datetime.datetime.now()
            
            self._tls_client_connection = client_context.wrap_socket(
                self._client_socket,
                server_side=True
            )
            core_logger.debug(f"TIMECHECK4 - {datetime.datetime.now() - before}")
            before=datetime.datetime.now()
            
            # resume tls handshake
            raw_request = self._resume_tls_conenction()
            core_logger.debug(f"TIMECHECK5 - {datetime.datetime.now() - before}")
            before=datetime.datetime.now()
            
            if not raw_request:
                return
            

            # check SNI for blacklist or malicious. Note we check two places - The initial CONNECT request, and the first request after TLS termination
            if self.url_manager.is_blacklisted([req.host + req.path, sni], self._username):
                self._respond_to_client(req, self._tls_client_connection, 403, addBlackListLabelHTML=True)
                return
            
            # if self.url_manager.is_malicious(sni):
            #     self._respond_to_client(req, self._tls_client_connection, 403, addMaliciousLabelHTML=True)
            
            # parse raw request into a Request obj
            client_request = Parser.parse_request(raw_request.decode())
            
            # check raw request again
            if self.url_manager.is_blacklisted([client_request.host + client_request.path, sni], self._username):
                self._respond_to_client(client_request, self._tls_client_connection, 403, addBlackListLabelHTML=True)
                return
            # if self.url_manager.is_malicious(sni):
            #     self._respond_to_client(client_request, self._tls_client_connection, 403, addMaliciousLabelHTML=True)

            
            # handshake server
            handshake_success = self._perform_tls_hanshake_with_server(client_request, sni)
            core_logger.debug(f"TIMECHECK6 - {datetime.datetime.now() - before}")
            before = datetime.datetime.now()

            if not handshake_success:
                if googleSearchRedirect:
                    core_logger.info(f"Failed connecting to server ({sni}). Redirecting to google search.")
                    self._respond_to_client(req, self._tls_client_connection, 200, redirectURL=UrlManager.get_google_url(sni))
                
                else:
                    core_logger.info(f"Failed connecting to server ({sni}). Sending 502 Bad Request.")
                    self._respond_to_client(req, self._tls_client_connection, 502, addBlackListLabelHTML=True)
                

                # self._close_sockets(self._tls_client_connection, self._tls_server_connection)
            
            # send first 'push'
            self._tls_server_connection.sendall(client_request.to_raw())
            # Only run relay if we actually have a secure connection
            core_logger.debug(f"TIMECHECK7 - {datetime.datetime.now() - before}")
            before=datetime.datetime.now()

            self._run_tunnel_relay()
            core_logger.debug(f"TIMECHECK8 - {datetime.datetime.now() - before}")
            
            after = datetime.datetime.now()
            core_logger.info(f"TIMECHECK9 - {after-abs_before}")
        except (ConnectionAbortedError, ConnectionResetError):
            core_logger.info("Client Unexpectedly closed conenction. Handled gracefully.")
        finally:
            self._close_sockets(self._tls_client_connection, self._tls_server_connection)
    
        '''establish a TCP conenction between the given server and the proxy.'''
    
    # --- PROXY-CLIENT FUNCTIONS ---
  
    def _resume_tls_conenction(self) -> bytes | None:
        """
        Completes the TLS handshake with the client and reads the first 
        decrypted data packet - the intial request.
        
        :rtype: bytes | Nones
        :returns: Decrypted raw bytes (the HTTP request) or None if the 
        connection was closed, or timed-out.

        :raises ConnectionError: If the TLS handshake fails critically
        (and not due to timeout and connection-aborted errors).
        """
        try:        
            self._tls_client_connection.do_handshake()
            core_logger.info("Handshake Success! Secure TLS connection is enabled.")
            
            # Read decrypted data
            raw_request = self._tls_client_connection.recv(self.BUFFER_SIZE)

            if not raw_request:
                core_logger.debug("Client closed TLS connection without sending data")                    
                return None
            
            core_logger.debug(f"Cient's request after TLS termination: \n{raw_request.decode(encoding="utf-8", errors="replace")}")
            return raw_request
            
        # Client/Proxy closed the connection
        except (ConnectionAbortedError, ConnectionResetError) as e:
                core_logger.warning(f"Client closed connection prematurely: {e}")
                return None
        except socket.timeout:
                core_logger.debug("Connection timed out - client didn't send any request.")
                return None
        
        except Exception as e:
            raise ConnectionError(f'TLS connection failed: {e}') 
    
    # --- PROXY-SERVER FUNCTIONS ---

    def _perform_tls_hanshake_with_server(self, req: Request, sni : str) -> bool:
        """
        Establishes a secure TLS connection with dst server.
        
        :type req: Request
        :param req: The Request object containing the destination host.

        :rtype: bool
        :returns: True if the secure connection is established, False otherwise.
        """
        try:
            
            # create socket obj
            self._server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._server_socket.settimeout(5)
            self._server_socket.connect((req.host, 443))
            
            # wrap socket (TLS Hanshake with server)
            self._tls_server_connection = self._server_ssl_context.wrap_socket(self._server_socket, server_hostname=sni)
            core_logger.info(f"Successfully and securely connected to server {req.host}.")
            return True

        except Exception as e:
            core_logger.error(f"TLS connection with server failed: {e}", exc_info=True)
            return False    

    # --- PROXY-CLIENT-SERVER FUCNTIONS ---

    def _run_tunnel_relay(self):
        """
        Starts two concurrent threads to handle bidirectional data flow:
        - Thread 1: Client to Serve
        - Thread 2: Server to Client
        
        Joins the threads and ensures sockets are cleaned up upon disconnection.
        """
        self.running = True

        # recv from client -> send to server
        t1 = threading.Thread(
            target=self._handle_relay_data,
            args=(self._tls_client_connection, self._tls_server_connection, ProxyContext.get_local().__dict__),
            daemon=True
        )

        # recv from server -> send to client
        t2 = threading.Thread(
            target=self._handle_relay_data,
            args=(self._tls_server_connection, self._tls_client_connection, ProxyContext.get_local().__dict__),
            daemon=True
        )

        core_logger.info("Starts relaying data biderctionally.")
        t1.start()
        t2.start()

        # wait for both threads ot finish before closing sockets
        t1.join()
        t2.join()

        self._close_sockets(self._tls_client_connection, self._tls_server_connection)
    
    def _handle_relay_data(self, recv_socket: ssl.SSLSocket, send_socket: ssl.SSLSocket, local_thread_vars : dict):
        """
        Wrapper class for handling new threads operations - setting Local thread vars,
        and executing data relay.

        :type recv_socket: ssl.SSLSocket
        :param recv_socket: The source socket to read from.

        :type send_socket: ssl.SSLSocket
        :param send_socket: The destination socket to write to.
        """

        # force local thread variables on thread
        ProxyContext.set_local(host=local_thread_vars["host"], ip=local_thread_vars["ip"], port=local_thread_vars["port"])

        # relay data
        self._relay_data(recv_socket, send_socket)

    def _relay_data(self, recv_socket: ssl.SSLSocket, send_socket: ssl.SSLSocket):
        """
        The worker method for relay threads. Continuously receives raw bytes 
        from one socket and sends them to another.

        :type recv_socket: socket.socket
        :param recv_socket: The source socket to read from.

        :type send_socket: socket.socket
        :param send_socket: The destination socket to write to.
        """
        try:
            # for keep-alive conenctions
            recv_socket.settimeout(30) 

            while self.running:
                try:
                    data = recv_socket.read(self.BUFFER_SIZE)
                    if not data:
                        break
                    
                    send_socket.write(data)

                except (ConnectionResetError, OSError, BrokenPipeError):
                    # If the other peer closed just loop back and try to recv again 
                    # until the socket is actually dead.
                    continue
            
            core_logger.debug("Escaped relay-data loop.")

            #Kill session

        except Exception as e:
            core_logger.error(f"Failed setting a timeout for the socket: {e}", exc_info=True)

        self.running = False

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
