from ..structures.request import Request
from ...logs.loggers import core_logger

class Parser():
    """
    Provides static methods for parsing, decoding and validating raw HTTP requests.
    
    This class handles the transition from raw byte-strings to high-level 
    Request objects, managing the complexities of URI formats, port defaults, 
    and header-body separation.
    """


    @staticmethod
    def parse_request(request: str) -> Request:
        """
        Parses a raw HTTP request string into a structured Request object.

        The parser handles both:
        1. Origin-form: 'GET /path HTTP/1.1' (Standard HTTP)
        2. Absolute-form: 'GET http://host/path HTTP/1.1' (Proxy-style)
        3. Authority-form: 'CONNECT host:port HTTP/1.1' (TCP Tunneling)

        :type request: str
        :param request: The raw string received from the client socket.

        :rtype: Request
        :returns: A Request object if successful, or None if parsing fails.
        
        :raises ValueError: If essential HTTP components (Method, URI) are missing 
                            or if Host headers contradict the Request-Line.
        """
        try:
            lines = request.split('\r\n')

            # Remove emptyspace list elements because of /r/n/r/n
            lines = [line for line in lines if line]
            
            first_line = lines[0]

            # Parse request line
            method, request_URI, http_version = first_line.split(' ')
            if not method:
                raise ValueError("Could not get request's method.")
            if not request_URI:
                raise ValueError("Could not get request's request_URI.")
            
            # Determine URI type
            http_pos = request_URI.find("://")    
            
            # Conditions explaination:
            # 1. "http_pos == -1":
            #  "://" doesn't exist

            # 2. "http_pos > 5":
            # Max postion of '://' will be 5, since longest pre-uri, 'https', is 5-bytes long
            # therefore req[5:8] is "://".

            # 3. "http_pos < 4"
            # Min postion of '://' will be 4, since shortest pre-uri, 'http', is 4-bytes long
            # therefore req[4:7] is "://".
            
            if http_pos == -1 or http_pos > 5 or http_pos < 4: 
                temp = request_URI
                uri_form = "origin-form"
            else:
                temp = request_URI[(http_pos + 3):] # in order to remove "://"
                uri_form = "absolute-form"

            # extract host, port and path
            port_pos = temp.find(":")
            path_pos = temp.find("/")
            if path_pos == -1:
                path_pos = len(temp)
            
            path = temp[path_pos:] or '/'

            if port_pos == -1 or path_pos < port_pos:
                host = temp[:path_pos]
                port = 443 if method == "CONNECT" else 80 #HTTPS deafult port - 443, HTTP - 80
            else:
                host = temp[:port_pos]
                port = int(temp[(port_pos + 1):path_pos])

            #Parse headers
            headers = {}
            header_name = None
            header_value = None
            body_line_num = None

            for i, line in enumerate(lines[1:]):
                
                # Next line is the start of the body
                if line == "\r\n\r\n":
                    body_line_num = i+1 
                    break

                header_name_pos = line.find(":")
                header_name = line[:header_name_pos]
                header_value = line[header_name_pos+1:].strip()
                headers[header_name] = header_value

            # Parse body
            body = None
            if body_line_num:
                body = lines[body_line_num:]
            
            # Check host header match first-line host (if header exists)
            host_header_value = headers.get("Host", None)
            core_logger.debug(f"Host by first line: {host}, Host by headers: {host_header_value}")

            if uri_form == "origin-form" and not host_header_value:
                raise ValueError("Missing Host header in origin-form request.")

            elif uri_form == "absolute-form" and \
                host_header_value and host_header_value != f"{host}:{port}" and host_header_value != host:
                raise ValueError("Host header does not match request URI host/port.")
            
            # if first-line host is None, and Host header has a value
            if not host:

                # check if host_header value has port in it (example.com:443 / example.com)
                if ":" in host_header_value:
                    host = host_header_value.split(":")[0]
                else:
                    host = host_header_value
                
            # Turning parsed-information to a Request obj
            parsed_request = Request(method, host, port, http_version, path, headers, body)
            core_logger.info(parsed_request.prettify())
            return parsed_request

        except ValueError as e:
            core_logger.warning(f"Request error: {e}", exc_info=True)
        except Exception as e:
            core_logger.warning(f"Unexpected error: {e}", exc_info=True)

