import socket
import logging
from datetime import datetime, timezone
from http import HTTPStatus

STATUS_CODES_DETAILS = {
    # 1xx: Information

    # 2xx: Successful

    # 3xx: Redirection

    # 4xx: Client error
    403: "Access is forbidden to the requested page",
    404: "The server can not find the requested page",

    # 5xx: Server error
    502: "The request was not completed. The server received an invalid response from the upstream server"
}
class HttpHandler:
    "Handle HTTP requests, or HTTPS after decryption."


    '''Splits an HTTP request into method, host, port, requested path, http version'''
    def parse_request(self, request: str) -> list:
            try:         
                lines = request.split('\r\n')
                first_line = lines[0]

                # parse request line
                method, request_URI, http_version = first_line.split(' ')
                if not method:
                    raise ValueError("Could not get request's method.")
                if not request_URI:
                    raise ValueError("Could not get request's request_URI.")
                
                # determine URI type
                http_pos = request_URI.find("://")    
                '''
                conditions exp:
                *1: "://" doesn't exist
                *2: longest pre url - "https" gives
                that the highest postion of "://" will be 5.
                *3: shortest pre url - "http" gives that
                lowest position of  "://" will be 4.
                '''
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
                
                # parse host header & accept-encoding header
                host_header_value = None
                for line in lines[1:]:
                    if not line:  # end of headers or both heders values were found
                        break
                    if line.lower().startswith("host:"):
                        host_header_value = line[5:].strip()
                        break
                
                if uri_form == "origin-form" and not host_header_value:
                    raise ValueError("Missing Host header in origin-form request.")

                if host_header_value and host_header_value != f"{host}:{port}" and host_header_value != host:
                    raise ValueError("Host header does not match request URI host/port.")

                logging.info(
                    f"Parsed request -> \nMethod: {method}, \nHost: {host}, \nPort: {port},\n"
                    f"Path: {path}, \nVersion: {http_version}, \nrequest-uri-form:{uri_form}.\n"
                )
                return method, host, port, path, http_version
            except ValueError as e:
                logging.warning(f"Request error:\n{e}", exc_info=True)
            except Exception as e:
                logging.warning(f"Unexpected error:\n{e}", exc_info=True)
    
    '''Generates a custom HTTP response.'''
    def generate_custom_response(self, http_version: str, status_code: int) -> str:
        try:
            reason = HTTPStatus(status_code).phrase
            details = STATUS_CODES_DETAILS.get(status_code, "Unknown")
            html_body = f"""<!DOCTYPE html>
    <html lang="en">
    <head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{status_code} {reason}</title>
    <style>
        * {{
            color: #1f51ff;
            font-family: 'Poppins', 'sans-serif';
            text-align: center;
        }}
        h1 {{
            font-weight: bolder;
            font-size: 8cm;
            margin-bottom: -12vh;
        }}
        h2 {{
            font-size: 1.2cm;
        }}
        p {{
            margin-top: -2vh;
            font-size: 0.6cm;
        }}
    </style>
    </head>
    <body>
        <div>
            <span>--SafeProxy--</span>
            <h1>{status_code}</h1>
            <h2>{reason}</h2>
            <p>Details: {details}.</p>
        </div>
    </body>
    </html>"""

            content_length = len(html_body.encode("utf-8"))

            response = (
                f"{http_version} {status_code} {reason}\r\n"
                f"Server: SafeProxy\r\n"
                f"Date: {datetime.now(timezone.utc).strftime('%a, %d %b %Y %H:%M:%S GMT')}\r\n"
                f"Content-Length: {content_length}\r\n"
                "Content-Type: text/html; charset=UTF-8\r\n"
                "Connection: close\r\n"
                "\r\n"
                f"{html_body}"
            )

            return response

        except Exception as e:
            logging.warning(f"Failed to generate response:\n{e}", exc_info=True)
                


