import logging
from dataclasses import dataclass, field
from typing import Optional

@dataclass
class Request():
    '''A representive of an HTTP/S request, with optional fields 
    like path, headers, and body for encrypted HTTPS request'''

    method: str
    host: str
    port: int
    http_version: str
    path: Optional[str] = None
    headers: dict[str, str] = field(default_factory=dict)
    body: Optional[str] = None

    '''handles newaunces after initialization of all fields'''
    def __post_init__(self):
        '''adds host to headers if not already in there'''
        self.add_header("Host", self.host)
    
    '''add a path to the request'''
    def add_path(self, path: str) -> None:
        if self.path is None:
            self.path = path
        else:
            logging.info("path field already exsits in the requests")

    '''add a header to the request'''
    def add_header(self, header: str, value: str) -> None:            
        if header not in self.headers:
            self.headers[header] = value

    '''adds a body ot the request'''
    def add_body(self, body: str) -> None:
        if self.body is None:
            self.body = body
        else:
            logging.info(f"Body field already exists in the request")
    
    '''returns a sendable string request (origin-form)'''
    def to_raw(self):
        first_line = f"{self.method} {self.path or '/'} {self.http_version}\r\n"
        headers = "".join(f"{h}: {v}\r\n" for h, v in self.headers.items())
        body = f"\r\n\r\n{self.body or ""}"

        return first_line + headers + body
    
    '''returns a pretty request (debugging)'''
    def prettify(self) -> str:
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
