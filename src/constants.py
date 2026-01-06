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
CERTS_DIR = "D:/SafeProxy/certs"
MAX_MEMORY_CERTS =20
MAX_DISK_CERTS =100000 #100,000
MAX_CERT_DAYS_ON_DISK = 365 # 1 year

# ---Logging details---
LOG_FORMAT = "%(asctime)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s \n"
CORE_CLIENTS_LOG_DIR_PATH = "D:/SafeProxy/src/logs/output/clients"
CORE_MAIN_LOG_FILE_PATH = "D:/SafeProxy/src/logs/output/core.log"
DB_MAIN_LOG_FILE_PATH = "D:/SafeProxy/src/logs/output/DB.log"
GUI_MAIN_LOG_FILE_PATH = "D:/SafeProxy/src/logs/output/GUI.log"

# ---response details---
SECURITY_LOCK_BG_PATH = "D:/SafeProxy/assets/security_lock_bg.txt"