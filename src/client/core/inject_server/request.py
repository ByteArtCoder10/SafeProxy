from dataclasses import dataclass, field
from typing import Optional

@dataclass
class Request():
    """
    A representation of an HTTP/HTTPS request, designed to hold both 
    connection-level metadata (host, port) and protocol-level data 
    (path, headers, body). This class supports transformation into 
    the raw wire format for transmission.

    :var str method: 

    :var str host: 
    Request's host appears in request's first line and optionally in headers.

    :var int port: 

    :var str http_version: 

    :var Optional[str] path:

    :var dict[str, str] headers: 
    headers dictionary.

    :var Optional[str] body:
    Body section of the request.
    """

    method: str
    host: str
    port: int
    http_version: str
    path: Optional[str] = None
    headers: dict[str, str] = field(default_factory=dict)
    body: Optional[str] = None

    def __post_init__(self):
        """
        Handles post-initialization logic, specifically ensuring that the 
        'Host' header is automatically populated if it was not provided 
        during instantiation.
        """
        self.add_header("Host", self.host)
    
    def add_path(self, path: str):
        """
        Assigns a path to the request if one does not already exist.

        :type path: str
        :param path: The URI path string (example: '/api/v1/resource').
        """
        if self.path is None:
            self.path = path

    def add_header(self, header: str, value: str):      
        """
        Adds a single header key-value pair to the internal headers dictionary.

        :type header: str
        :param header: The name of the HTTP header.

        :type value: str
        :param value: The value to associate with the header.
        """      
        if header not in self.headers:
            self.headers[header] = value

    def add_body(self, body: str):
        """
        Attaches a message body to the request.

        :type body: str
        :param body: The raw string data to be used as the request body.
        """
        if self.body is None:
            self.body = body
    
    def to_raw(self) -> bytes:
        """
        Arranges the Request object into a raw bytes object compliant with the 
        HTTP protocol specifications. Includes the Request Line, 
        Headers, and Body.

        :rtype: bytes
        :returns: The raw bytes-like object ready to be sent over a socket.
        """
        first_line = f"{self.method} {self.path or '/'} {self.http_version}\r\n"
        headers = "".join(f"{h}: {v}\r\n" for h, v in self.headers.items())
        body = f"\r\n\r\n{self.body or ""}"

        return (first_line + headers + body).encode()
    
    def prettify(self) -> str:
        """
        Generates a human-readable, formatted string representation of the 
        request object. Used for logging and debugging purposes.

        :rtype: str
        :returns: A multi-line string visualizing the request structure.
        """
        return (
            "\n------REQUEST------"
            f"\n--Method: {self.method}, \n--Host: {self.host}, \n--Port: {self.port},"
            f"\n--Path: {self.path}, \n--Http version: {self.http_version},"
            f"\n--Headers: \t{"".join(f"\n{h}: {v}" for h, v in self.headers.items())}"
            f"\n--Body: \n{self.body}\n"
            "-------------------"
        )

if __name__ == "__main__":
    req = Request(
        method="GET",
        host="example.com",
        port=803,
        http_version="HTTP/1.1"
    )

    print(req.prettify())
    print(req.to_raw())
    req.add_path("/index.html")
    req.add_header("User-Agent", "SafeProxy/1.0")
    req.add_header("Connection", "Closed")
    print(req.prettify())
    print(req.to_raw())
