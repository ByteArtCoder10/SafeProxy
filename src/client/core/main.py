from src.client.core.authentication.auth_handler import AuthHandler

def main():
    # connect to auth-server
    auth_handler = AuthHandler("127.0.0.1")
    if auth_handler.connect():
        rsp = auth_handler.login("ByteArt", "1qa2ws")
        rsp = auth_handler.login("ByteArtsssdsd", "1qa2ws")
        rsp = auth_handler.login("ByteArtsssdsd", "ws")
        rsp = auth_handler.login("ByteArtsssdsd", "ws")

        rsp = auth_handler.signup("ByteArtsssdsd", "ws")
        rsp = auth_handler.signup("ByteArt", "1qa2ws")
        rsp = auth_handler.signup("By", "1qa2ws")
    
        rsp = auth_handler.delete("Byteq", "1qa2ws")

if __name__ == "__main__":
    main()