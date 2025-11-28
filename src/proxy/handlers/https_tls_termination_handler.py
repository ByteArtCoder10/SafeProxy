import socket
import threading
import logging
from OpenSSL import SSL

from .base_handler import BaseHandler
from ..structures.request import Request
from ..structures.response import Response




class HttpsTlsTerminationHandler(BaseHandler):

    def __init__(self):
        super().__init__()
        logging.debug(hasattr(self, 'url_manager'))  # Should print True

    '''handles the process by routing and calling methods by order.'''
    def process(self, req: Request, client_socket: socket):
        self._client_socket = client_socket
        # send a 200 Connection Established response to client
        self._respond_to_client(req, 200, isConnectionEstablished=True)
        
        # get ClientHello SNI
        client_hello_length = self._get_record_length()
        client_hello_data = self._recvall(client_hello_length)
        sni = self._extract_sni_from_client_hello(client_hello_data)

        # check SNI for blacklist or malicious    
        if self.url_manager.is_blacklisted(sni) or \
        self.url_manager.is_malicious(sni):
            self._respond_to_client(req, 403, addBlackListHTML=True)
        
        # 


        # 
    
    '''get reocrd length of a message'''
    def _get_record_length(self) -> tuple[bytes, int]:
        record_header = self._recvall(5, msg_peek=True)
        record_len = int.from_bytes(record_header[3:5], "big")
        return record_len + 5
    
    """Extract the Server Name Indication (SNI) hostname
    from a raw TLS ClientHello message."""
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
                logging.debug(f"SNI RAW:{hostname}, SNI UTF-8:{hostname.decode('utf-8')}")
                return hostname.decode('utf-8')

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
