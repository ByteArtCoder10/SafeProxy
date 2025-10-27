from src.logs.logging_config import setup_logging
setup_logging()
from src.proxy.proxy_listener import ProxyListener

def main():
    pl1 = ProxyListener('127.0.0.1', 2153)
    pl1.start(1000)  

if __name__ == "__main__":
    main()