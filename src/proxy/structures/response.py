import logging
from http import HTTPStatus
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional, ClassVar
import socket
'''
A response must have:
Http_version
statuscode
reason
Optional:
Headers
Body
'''
@dataclass
class Response:
    '''A representive of an HTTP/S response, with optional fields 
    like headers and body for encrypted HTTPS response. Proxy's job
    is to forward webserver response or to make it's own reponse to forward (e.g due to black-listed URL)'''

    http_version: str
    status_code: str
    reason: Optional[str] = None
    headers: Optional[dict[str, object]] = field(default_factory=dict)
    body: str = field(init=False)

    '''handles newaunces after initialization of all fields'''
    def __post_init__(self):
        # If no reason was provided. runs after all fields are intialized
        if self.reason is None:
            try:
                self.reason = HTTPStatus(self.status_code).phrase
            except ValueError:
                self.reason = ""
    
        # adding html body
        self._add_dynamic_body()
        
        # adding fixed headers
        self._add_proxy_fixed_headers()
    
    #adds dynamic HTML bodt based on status_code, reason.
    def _add_dynamic_body(self):
        html_body = f"""<!DOCTYPE html>
        <html lang="en">
        <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>{self.status_code} {self.reason}</title>
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
                <h1>{self.status_code}</h1>
                <h2>{self.reason}</h2>
                <p>Details: {HTTPStatus(self.status_code).description}.</p>
            </div>
        </body>
        </html>"""
        self.body = html_body

    '''adds proxy required and preffered headers.
    Like said, The proxy's job is to forward webserver response, or to make it's own 
    response to forward. the custom response is defined to have:
    -Body: HTML
    -Content-Length: Dynamic
    -Date: Dynamic
    -Server: proxy's name
    -Connection: Closed
    
    If one or more of these headers alredy exist, they remian unchanged.
    '''
    def _add_proxy_fixed_headers(self):
        '''REQUIRED: Content-Type, Content-Length'''
        '''PREFFERED: Date, Server, Connection'''
        required_preffered_headers = {
            "Content-Type": "text/html; charset=utf-8",
            "Content-length": f"{len(self.body.encode('utf-8'))}",
            "Server": "SafeProxy",
            "Date": f"{datetime.now(timezone.utc).strftime('%a, %d %b %Y %H:%M:%S GMT')}",
            "Connection": "Closed"            
        }
        for header, value in required_preffered_headers.items():
            if header not in self.headers:
                self.headers[header] = value
    
    '''returns a sendable string request (origin-form)'''
    def to_raw(self):
        first_line = f"{self.http_version} {self.status_code} {self.reason}\r\n"
        headers = "".join(f"{h}: {v}\r\n" for h, v in self.headers.items())
        body = f"\r\n\r\n{self.body or ""}"

        return first_line + headers + body
    
    '''returns a pretty request (debugging)'''
    def prettify(self) -> str:
        return (
            "------RESPONSE------"
            f"\n--Http version: {self.http_version}, \n--Status code: {self.status_code}, \n--Reason: {self.reason},"
            f"\n--Headers: \t{"".join(f"\n{h}: {v}" for h, v in self.headers.items())},"
            f"\n--Body: \n{self.body}\n"
            "--------------------" )


pr = Response("HTTP/1.1", 404, "Not Found")
print(pr.prettify())
print(pr.to_raw())
