import os
from dotenv import load_dotenv
from src.logs.logging_config import setup_logging
from src.constants import MAX_CLIENTS

def main():

    setup_logging()
    load_dotenv('.env')

    from src.proxy.core.proxy_listener import ProxyListener

    pl1 = ProxyListener('127.0.0.1', int(os.getenv('PROXY_PORT')))
    pl1.start(MAX_CLIENTS)  
    

if __name__ == "__main__":
    main()