import os
from dotenv import load_dotenv
from src.logs.logging_manager import LoggingManager

def main():

    load_dotenv('SafeProxy/.env')
    LoggingManager.setup_logging()

    from src.proxy.core.proxy_listener import ProxyListener

    print(os.getenv("PROXY_PORT"))
    pl1 = ProxyListener(os.getenv('PROXY_BIND'), int(os.getenv('PROXY_PORT')))
    pl1.setup_and_start_proxy()
    

if __name__ == "__main__":
    main()