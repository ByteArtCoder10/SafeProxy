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

    '''generates a custom HTTP response.'''
    def generate_custom_response(self, http_version: str, status_code: int) -> str:
        code_phrase = HTTPStatus(status_code).phrase
        response = (
                f"{http_version} {status_code} {code_phrase}\r\n"
                f"Server: SafeProxy\r\n"
                f"Date: {datetime.now(timezone.utc).strftime('%a, %d %b %Y %H:%M:%S GMT')}\r\n"
                "Connection: close\r\n"
            )
        return response

    '''Generates a custom HTTP response with HTML in the body.'''
    def generate_custom_visual_response(self, http_version: str, status_code: int) -> str:
        try:
            code_phrase = HTTPStatus(status_code).phrase
            details = STATUS_CODES_DETAILS.get(status_code, "Unknown")
            html_body = f"""<!DOCTYPE html>
    <html lang="en">
    <head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{status_code} {code_phrase}</title>
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
                f"{http_version} {status_code} {code_phrase}\r\n"
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
                

