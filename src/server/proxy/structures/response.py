import logging
from http import HTTPStatus
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional, ClassVar
import socket

from ...logs.loggers import core_logger
from ...server_constants import SECURITY_LOCK_BG_PATH


@dataclass
class Response:
    """
    A representation of an HTTP/HTTPS response. This class is responsible for 
    arranging data received from a remote webserver or generating custom 
    responses locally (for example, for blocked pages or redirects). It handles the 
    automatic generation of HTML bodies and standard-proxy HTTP headers.

    :var str http_version: 
    HTTP version of the Response.

    :var int status_code:

    :var Optional[str] reason:

    :var dict[str, str] headers: 
    headers dictionary.

    :var Optional[str] body:
    Body section of the response.

    :var Optional[bool] raw_connect:
    Flag to indicate if this is a minimal '200 Connection Established' response for tunnel initialization.

    :var Optional[str] redirect_url:
    An optional URL used for generating automatic HTML redirects.
    """

    http_version: str
    status_code: int
    reason: Optional[str] = None
    headers: Optional[dict[str, object]] = field(default_factory=dict)
    body: str = field(default='', init=False)
    raw_connect: Optional[bool] = False
    redirect_url: Optional[str] = None

    def __post_init__(self):
        """
        Handles post-initialization logic:
        - Resolves the 'reason' phrase if missing.
        - Generates redirect HTML if a redirect_url is provided.
        - Appends standard proxy headers for non-CONNECT responses.
        """

        # If no reason was provided. (runs after all fields are intialized)
        if self.reason is None:
            try:
                self.reason = HTTPStatus(self.status_code).phrase
            except ValueError:
                self.reason = ""
        
        # In case of 200 ok response with url redirection in html body
        if self.redirect_url and self.status_code == 200:
            self._add_redirect_html_body()
        
        # Connection Established isn't usually sent with additional headers
        if self.reason != 'Connection Established':
            self._add_proxy_fixed_headers()
    
    def _add_redirect_html_body(self):
        """
        Constructs a simple HTML code that performs a client-side redirect 
        using both a <meta> refresh tag and JS.
        """
        html_body = f"""
            <html>
            <head>
                <meta http-equiv="refresh" content="0;url={self.redirect_url}">
            </head>
            <body>
                <script>window.location.href = "{self.redirect_url}";</script>
                Redirecting to search...
            </body>
            </html> """
        
        self.body = html_body
        self.headers['Content-length'] = len(self.body.encode())
        
    def _add_dynamic_body(self, addMaliciousLabel=False):
        """
        Generates a 'SafeProxy' landing page for errors or blocked sites.

        :type addMaliciousLabel: bool
        :param addMaliciousLabel: If True, adds warning about 
        infected or malicious content.
        """
        if addMaliciousLabel:
            html_body = f"""<!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>SafeProxy – {self.status_code} {self.reason}</title>

                <style>
                    body {{
                        margin: 0;
                        padding: 0;
                        height: 100vh;
                        display: flex;
                        justify-content: center;
                        align-items: center;
                        background: linear-gradient(135deg, #e8efff, #c9d8ff);
                        font-family: 'Poppins', sans-serif;
                        color: #0066ff;
                        overflow: hidden;
                    }}

                    .card {{
                        width: 50vw;
                        height: 70vh;
                        max-width: 800px;
                        max-height: 600px;
                        background: rgba(255, 255, 255, 0.7);
                        border-radius: 20px;
                        position: relative;
                        text-align: center;
                        box-shadow:
                            0 20px 40px rgba(0, 0, 0, 0.1),
                            0 8px 20px rgba(0, 0, 0, 0.05);
                        overflow: hidden;
                        border: 1px solid rgba(255, 255, 255, 0.5);
                    }}

                    .card::before {{
                        content: "";
                        position: absolute;
                        inset: 0;
                        background-image: url(https://cdn-icons-png.flaticon.com/512/8631/8631491.png);
                        background-size: cover;
                        background-position: center;
                        opacity: 0.18;
                        filter: blur(4px);
                    }}

                    .content {{
                        position: relative;
                        z-index: 2;
                    }}

                    .brand {{
                        font-size: 1.3rem;
                        font-weight: 100;
                        letter-spacing: 2px;
                        opacity: 0.9;
                        margin-top: 3vh;
                    }}

                    h1 {{
                        margin-top: 3vh;
                        font-size: 6rem;
                        font-weight: 900;
                        margin-bottom: -20px;
                    }}

                    h2 {{
                        font-size: 1.7rem;
                        margin-bottom: 10px;
                    }}

                    p {{
                        font-size: 1rem;
                        opacity: 0.8;
                        margin-top: 0;
                    }}

                    .line {{
                        width: 100px;
                        height: 4px;
                        background: #1f51ff;
                        border-radius: 2px;
                        margin: 20px auto;
                        opacity: 0.8;
                    }}
                </style>
            </head>

            <body>
                <div class="card">
                    <div class="content">
                        <div class="brand">-- SafeProxy --</div>
                        <h1>{self.status_code}</h1>
                        <div class="line"></div>
                        <h2>{self.reason}</h2>
                        <p>{HTTPStatus(self.status_code).description}</p>
                        <h3 style="color: red;">Warning: The requested URL is infected!</h3>
                    </div>
                </div>
            </body>
            </html>"""
        else:
            html_body = f"""<!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>SafeProxy – {self.status_code} {self.reason}</title>

            <style>
                body {{
                    margin: 0;
                    padding: 0;
                    height: 100vh;
                    display: flex;
                    justify-content: center;
                    align-items: center;
                    background: linear-gradient(135deg, #e8efff, #c9d8ff);
                    font-family: 'Poppins', sans-serif;
                    color: #0066ff;
                    overflow: hidden;
                }}

                .card {{
                    width: 50vw;
                    height: 70vh;
                    max-width: 800px;
                    max-height: 600px;
                    background: rgba(255, 255, 255, 0.7);
                    border-radius: 20px;
                    position: relative;
                    text-align: center;
                    box-shadow:
                        0 20px 40px rgba(0, 0, 0, 0.1),
                        0 8px 20px rgba(0, 0, 0, 0.05);
                    overflow: hidden;
                    border: 1px solid rgba(255, 255, 255, 0.5);
                }}

                .card::before {{
                    content: "";
                    position: absolute;
                    inset: 0;
                    background-image: url(https://cdn-icons-png.flaticon.com/512/8631/8631491.png);
                    background-size: cover;
                    background-position: center;
                    opacity: 0.18;
                    filter: blur(4px);
                }}

                .content {{
                    position: relative;
                    z-index: 2;
                }}

                .brand {{
                    font-size: 1.3rem;
                    font-weight: 100;
                    letter-spacing: 2px;
                    opacity: 0.9;
                    margin-top: 3vh;
                }}

                h1 {{
                    margin-top: 3vh;
                    font-size: 6rem;
                    font-weight: 900;
                    margin-bottom: -20px;
                }}

                h2 {{
                    font-size: 1.7rem;
                    margin-bottom: 10px;
                }}

                p {{
                    font-size: 1rem;
                    opacity: 0.8;
                    margin-top: 0;
                }}

                .line {{
                    width: 100px;
                    height: 4px;
                    background: #1f51ff;
                    border-radius: 2px;
                    margin: 20px auto;
                    opacity: 0.8;
                }}
            </style>
        </head>

        <body>
            <div class="card">
                <div class="content">
                    <div class="brand">-- SafeProxy --</div>
                    <h1>{self.status_code}</h1>
                    <div class="line"></div>
                    <h2>{self.reason}</h2>
                    <p>{HTTPStatus(self.status_code).description}</p>
                </div>
            </div>
        </body>
        </html>"""

        self.body = html_body
        self.headers['Content-length'] = len(self.body.encode('utf-8'))
    
    def _load_lock_image(self):
        try:
            with open(SECURITY_LOCK_BG_PATH, "r") as f:
                base64_img = f.read()
            return base64_img
        except Exception as e:
            core_logger.warning(f"Couldn't load lock image for custom proxy response. proceeding without. {e}", exc_info=True)
    
    def _add_proxy_fixed_headers(self):
        """
        adds proxy required and preffered headers. The proxy's job is 
        to forward webserver response, or to make it's own response to forward.
        the custom response is defined to contain:
        - Body: HTML.
        - Content-Length: Dynamic.
        - Date: Dynamic.
        - Server: proxy's name.
        - Connection: Closed.
        
        distiction: 
        - Required: Content-Type, Content-Length.
        - Not required, but Preffered: Date, Server, Connection.

        If one or more of these headers alredy exist, they remian unchanged.
        """

        required_preffered_headers = {
            "Content-Type": "text/html; charset=utf-8",
            "Content-length": f"{len(self.body.encode('utf-8'))}",
            "Proxy-Agent": "SafeProxy",
            "Date": f"{datetime.now(timezone.utc).strftime('%a, %d %b %Y %H:%M:%S GMT')}",
            "Connection": "Closed"            
        }
        for header, value in required_preffered_headers.items():
            if header not in self.headers:
                self.headers[header] = value
    
    def to_raw(self) -> bytes:
        """
        Arranges the Response object into a raw bytes object compliant with the 
        HTTP protocol specifications.

        :rtype: bytes
        :returns: The raw bytes-like object ready to be sent over a socket.
        """
        
        # Only the minimal 200 "Connection Etablished" response
        if self.raw_connect:
            response = f"{self.http_version} {self.status_code} {self.reason}\r\nProxy-Agent: SafeProxy\r\n\r\n"
            return response.encode()
        
        first_line = f"{self.http_version} {self.status_code} {self.reason}\r\n"
        headers = "".join(f"{h}: {v}\r\n" for h, v in self.headers.items())
        body = f"\r\n\r\n{self.body or ""}"
        
        return (first_line + headers + body).encode()
    
    def prettify(self) -> str:
        """
        Generates a human-readable, formatted string representation of the 
        response object. Used for logging and debugging purposes.

        :rtype: str
        :returns: A multi-line string visualizing the response structure.
        """
        return (
            "\n------RESPONSE------"
            f"\n--Http version: {self.http_version}, \n--Status code: {self.status_code}, \n--Reason: {self.reason},"
            f"\n--Headers: \t{"".join(f"\n{h}: {v}" for h, v in self.headers.items())},"
            f"\n--Body: \n{self.body}\n"
            "----------------------" )

if __name__ == "__main__":
    pr = Response("HTTP/1.1", 404, "Not Found")
    print(pr.prettify())
    print(pr.to_raw())
