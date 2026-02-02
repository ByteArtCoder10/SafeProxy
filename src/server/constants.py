# ---Network traffic details---
SOCKET_BUFFER_SIZE =16384
MAX_CLIENTS = 100

# ---CA cert details---
COUNTRY_NAME="IL"
LOCALITY_NAME="Rehovot"
ORGANIZTION_NAME="SafeProxy"
COMMON_NAME="SafeProxy Root CA"

# ---General certificate details---
CA_KEY_SIZE = 2048
CA_ROOT_VALIDITY_DAYS = 3650  # 10 years
CA_VALIDITY_DAYS = 365  # 1 year

# ---Certificates Locations and Storage---
CA_CERT_AND_KEY_DIR = r"D:\SafeProxy\.safeproxy\root_ca"
CERTS_DIR = r"D:\SafeProxy\certs"
MAX_MEMORY_CERTS = 100
MAX_DISK_CERTS = 100000 #100,000
MAX_CERT_DAYS_ON_DISK = 365 # 1 year

# ---Logging details---
LOG_FORMAT = "%(asctime)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s \n"
CORE_CLIENTS_LOG_DIR_PATH = r"D:\SafeProxy\src\server\logs\output\clients"
CORE_MAIN_LOG_FILE_PATH = r"D:\SafeProxy\src\server\logs\output\core.log"
DB_MAIN_LOG_FILE_PATH = r"D:\SafeProxy\src\server\logs\output\DB.log"
GUI_MAIN_LOG_FILE_PATH = r"D:\SafeProxy\src\server\logs\output\GUI.log"

# ---response details---
SECURITY_LOCK_BG_PATH = r"D:\SafeProxy\assets\security_lock_bg.txt"

# ---JWT, authentication and verification details---
AUTH_SERVER_PORT = 2985
AUTH_KEYS_SIZE = 2048
HTTP_AUTH_HEADER_NAME = "X-SafeProxy-Auth-Token"