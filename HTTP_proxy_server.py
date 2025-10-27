import socket
import threading
from email.utils import formatdate

IP = '127.0.0.1'
PORT = 2153

class Proxy_Server:

    def handle_client(self, client_socket, client_address):
        try:
            request = client_socket.recv(1024)
            print(f"req in binary: {request}")
            print(f"request deocded: {request.decode()}")
            if not request:
                return

            first_line = request.split(b'\r\n')[0]
            print(first_line)
            url = first_line.split(b' ')[1]

            http_pos = url.find(b"://") 
            if http_pos == -1:
                temp = url
            else:
                temp = url[(http_pos + 3):]

            port_pos = temp.find(b":")
            webserver_pos = temp.find(b"/")
            if webserver_pos == -1:
                webserver_pos = len(temp)

            webserver = ""
            port = 80  # Default HTTP port

            if port_pos == -1 or webserver_pos < port_pos:
                webserver = temp[:webserver_pos]
            else:
                port = int(temp[(port_pos + 1):webserver_pos])
                webserver = temp[:port_pos]
            print(webserver.decode('utf-8'))
            if webserver.decode('utf-8') == "www.alwayshttp.com":
                body = ("<html><head><title>403 Forbidden</title></head>"
                    "<body><h1>403 Forbidden</h1>"
                    "<p>Access to this site is restricted by the proxy.</p></body></html>")
                response_lines = [
                "HTTP/1.1 403 Forbidden",
                f"Date: {formatdate(usegmt=True)}",
                "Server: SimpleProxy/0.1",
                "Content-Type: text/html; charset=utf-8",
                f"Content-Length: {len(body.encode('utf-8'))}",
                "Connection: close",
                "",  # blank line between headers and body
                body
                ]
                response = "\r\n".join(response_lines)
                client_socket.sendall(response.encode('utf-8'))
                return

            # Connect to the destination server
            remote_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            remote_socket.connect((webserver, port))

            # Forward the client's request to the destination server
            remote_socket.sendall(request)

            # Receive response from the destination server and send back to client
            while True:
                data = remote_socket.recv(1024)
                if not data:
                    break
                client_socket.sendall(data)

        except Exception as e:
            print(f"Error handling client {client_address}: {e}")
        finally:
            client_socket.close()
            if 'remote_socket' in locals() and remote_socket:
                remote_socket.close()
        
    def start_proxy_server(self):
        proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        proxy_socket.bind((IP, PORT))
        proxy_socket.listen(100)
        print("proxy server is listening.")

        while True:
            client_socket, client_address = proxy_socket.accept()
            print(f"Accepted connection from {client_address[0]}: {client_address[1]}.")
            client_handler = threading.Thread(target=self.handle_client, args=(client_socket, client_address))
            client_handler.daemon = True
            client_handler.start()

p= Proxy_Server()
p.start_proxy_server()