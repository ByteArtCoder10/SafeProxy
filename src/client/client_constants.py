from pathlib import Path
import os

# gets absulte path of prject's cwd
proj_path = Path(__file__).resolve().parent.parent.parent
temp_dir = Path(os.environ.get('TEMP', 'C:/Temp'))
program_files_dir = Path(os.environ.get('ProgramFiles', 'C:/Program Files'))

# --- Network traffic details ---
SOCKET_BUFFER_SIZE =16384
MAX_CLIENTS = 1000

# -- Servers & proxy details ---
AUTH_SERVER_PORT = 2985
INJECT_SERVER_PORT = 5860
PROXY_SERVER_IP = "127.0.0.1"
PROXY_SERVER_PORT = 2153

# --- Logging details ---
LOG_FORMAT = "%(asctime)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s \n"
CLIENT_LOG_FILE_PATH = str(proj_path / "src" / "client" / "logs" / "client.log")

# --- Cryptogrpahy stuff ---
AUTH_KEYS_SIZE = 2048

# ---JWT, authentication and verification details---
HTTP_AUTH_HEADER_NAME = "X-SafeProxy-Auth-Token"

# --- Certs ---
ROOT_CA_CERT_PATH = str(proj_path / "src" / "client" / "resources" / "root_ca.crt")

# --- Chorme Config ---
CHROME_PROPILE_DATA_PATH = str(temp_dir / "SafeProxyBrowser")
CHROME_EXE_PATH = str(program_files_dir / "Google" / "Chrome" / "Application" / "chrome.exe")
CERT_STORE_PATH = r"cert:\LocalMachine\Root"


# # --- Logging details ---
# LOG_FORMAT = "%(asctime)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s \n"
# CLIENT_LOG_FILE_PATH = r"D:\SafeProxy\src\client\logs\client.log"

# # --- Cryptogrpahy stuff ---
# AUTH_KEYS_SIZE = 2048

# # ---JWT, authentication and verification details---
# HTTP_AUTH_HEADER_NAME = "X-SafeProxy-Auth-Token"

# # --- Certs ---
# ROOT_CA_CERT_PATH = r"D:\SafeProxy\src\client\resources\root_ca.crt"

# # --- Chorme Config ---
# CHROME_PROPILE_DATA_PATH = r"C:\Temp\SafeProxyBrowser"
# CHROME_EXE_PATH = r"C:\Program Files\Google\Chrome\Application\chrome.exe"
# CERT_STORE_PATH = r"cert:\LocalMachine\Root"