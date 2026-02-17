import os
import threading
from pathlib import Path
from dotenv import load_dotenv

from src.server.server_constants import AUTH_SERVER_PORT
from src.server.logs.logging_manager import LoggingManager
from src.server.file_ensure_util import EnsureDirsExistsUtil
from src.server.auth_server.encryption_manager import EncryptionManager

def main():
    # gets absolute path of project directory
    proj_path = BASE_DIR = Path(__file__).resolve().parent // ".env.example"
    load_dotenv(proj_path)
    
    # make sure essentail folders exist
    EnsureDirsExistsUtil.handle_dirs_exist()

    # create JWT auth key pair if not already exists
    EncryptionManager.generate_jwt_key_pair()

    LoggingManager.setup_logging()
    
    auth_thread = threading.Thread(target=run_auth_server)
    auth_thread.daemon = False # if proxy crashes, auth server will still be up.
    auth_thread.start()
    
    from src.server.proxy.core.proxy_listener import ProxyListener

    pl1 = ProxyListener(os.getenv('PROXY_BIND'), int(os.getenv('PROXY_PORT')))
    pl1.setup_and_start_proxy()

def run_auth_server():
    ip = os.getenv('PROXY_BIND')

    from src.server.auth_server.auth_server import AuthServer
    as1 = AuthServer(ip, AUTH_SERVER_PORT)
    as1.start()

if __name__ == "__main__":
    main()