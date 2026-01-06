import logging
import os 
import shutil
import threading
from ..constants import LOG_FORMAT,CORE_MAIN_LOG_FILE_PATH, \
DB_MAIN_LOG_FILE_PATH, GUI_MAIN_LOG_FILE_PATH, CORE_CLIENTS_LOG_DIR_PATH
from .proxy_context import ProxyContext

class LoggingManager():
    
    @staticmethod
    def setup_logging():
        LoggingManager.cleanup_client_logs()
        # set root logger level
        root_logger = logging.getLogger()
        root_logger.setLevel(logging.DEBUG)
        # General formatter
        formatter = logging.Formatter(LOG_FORMAT)
        
        # Create core logger
        core_logger = logging.getLogger("proxy.core")

        # log to console
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        core_logger.addHandler(console_handler)
        
        # log to file - main "core" log file
        core_handler = logging.FileHandler(CORE_MAIN_LOG_FILE_PATH, mode="w")
        core_handler.setFormatter(formatter)
        core_handler.addFilter(MainFilter())
        # core_handler.setLevel(logging.DEBUG)
        core_logger.addHandler(core_handler)
        core_logger.propagate = False

        # create per client file handler
        per_client_handler = DynamicPerClientFileHandler()
        per_client_handler.setLevel(logging.DEBUG)
        per_client_handler.setFormatter(formatter)
        core_logger.addHandler(per_client_handler)
    
    def cleanup_client_logs():
        file_names = os.listdir(CORE_CLIENTS_LOG_DIR_PATH)
        file_paths = [os.path.join(CORE_CLIENTS_LOG_DIR_PATH, file_name) for file_name in file_names]
        for file_path in file_paths:
            os.remove(file_path)
            

class DynamicPerClientFileHandler(logging.Handler):
    
    def __init__(self):
        super().__init__()
        os.makedirs(CORE_CLIENTS_LOG_DIR_PATH, exist_ok=True)
    
    def emit(self, record: logging.LogRecord):
        # Get current state
        host = getattr(ProxyContext.thread_local, "host", None)
        ip = getattr(ProxyContext.thread_local, "ip", None)
        port = getattr(ProxyContext.thread_local, "port", None)

        if not ip or not port:
            return

        pending_name = f"PENDING_{ip}_{port}.log"
        pending_path = os.path.join(CORE_CLIENTS_LOG_DIR_PATH, pending_name)

        # option 1: gost is still unknown
        if host is None:
            self._write_to_file(self.format(record), pending_path)
            return

        # option 2: host is known
        final_name = f"{host}_{ip}_{port}.log"
        final_path = os.path.join(CORE_CLIENTS_LOG_DIR_PATH, final_name)

        # Check if we need to "Merge" an old PENDING file into the new Host file
        if os.path.exists(pending_path):
            self._merge_files(pending_path, final_path)

        # Write the current log to the final path
        self._write_to_file(self.format(record), final_path)

    def _merge_files(self, src  :str, dst : str):
        """Safely moves content from PENDING to the final log file."""
        try:
            with open(src, 'r', encoding='utf-8') as f_src:
                content = f_src.read()
            with open(dst, 'a', encoding='utf-8') as f_dst:
                f_dst.write(content)
            os.remove(src) # Delete the PENDING file after merging
        except Exception:
            pass
    
    def _write_to_file(self, msg : str, path : str):
        with open(path, mode="a", encoding="utf-8") as f:
            f.write(msg + "\n")
    


class MainFilter(logging.Filter):

    def filter(self, record : logging.LogRecord):
        
        # check severity
        if record.levelno >= logging.WARNING:
            return True
        if any(hasattr(ProxyContext.thread_local, attr) for attr in ["ip", "port", "host"]):
            return False # not the main Thread
        
        return True # Main thread



        


        