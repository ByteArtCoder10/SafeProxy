import logging
import os 
import datetime
import shutil
import threading
import sys
from ..constants import LOG_FORMAT,CORE_MAIN_LOG_FILE_PATH, \
DB_MAIN_LOG_FILE_PATH, GUI_MAIN_LOG_FILE_PATH, CORE_CLIENTS_LOG_DIR_PATH
from .proxy_context import ProxyContext

class LoggingManager():
    """
    Manages the logging infrastructure for the Proxy system.
    Handles the initialization of:
    * db proxy logger (proxy.db)
    * ui proxy logger (proxy.ui)
    * core proxy logger (proxy.core)
    * console output
    * automated cleanup of previous client session logs.
    """

    @staticmethod
    def setup_logging():
        """
        Initializes the global logging configuration. Configures the root logger 
        and sets up specialized handlers for core logic, per-client logs,
        UI logs, and DB logs. 
        """
        try:

            LoggingManager.cleanup_client_logs()
            
            # set root logger level
            root_logger = logging.getLogger()
            root_logger.setLevel(logging.DEBUG)
            formatter = logging.Formatter(LOG_FORMAT) # global formatter

            # Create Loggers
            core_logger = logging.getLogger("proxy.core")
            ui_logger = logging.getLogger("proxy.ui")
            db_logger = logging.getLogger("proxy.db")

            # !propogate 
            core_logger.propagate = False
            ui_logger.propagate = False
            db_logger.propagate = False


            # Console (sys.stdout)
            console_handler = logging.StreamHandler(sys.stdout)
            console_handler.setFormatter(formatter)
            core_logger.addHandler(console_handler) # REQUIRES CHNAGE

            # Main core log file - (core.log)
            core_handler = logging.FileHandler(CORE_MAIN_LOG_FILE_PATH, mode="w")
            core_handler.setFormatter(formatter)
            core_handler.addFilter(MainFilter())
            core_logger.addHandler(core_handler)

            # Dynamic per-client Handler
            per_client_handler = DynamicPerClientFileHandler()
            per_client_handler.setLevel(logging.DEBUG)
            per_client_handler.setFormatter(formatter)
            core_logger.addHandler(per_client_handler)
        
        except Exception as e:
            print(f"CRITICAL ERROR: could not intalize logging system: {e}", file=sys.stderr)
    
    @staticmethod
    def cleanup_client_logs():
        """
        cleans up the per-client log directory to ensure a clean state 
        at startup.
        """
        if os.path.exists(CORE_CLIENTS_LOG_DIR_PATH):
            try:
                for file_name in os.listdir(CORE_CLIENTS_LOG_DIR_PATH):
                    file_path = os.path.join(CORE_CLIENTS_LOG_DIR_PATH, file_name)
                    if os.path.isfile(file_path):
                        os.remove(file_path)
            except OSError as e:
                print(f"NON-CRITICAL ERROR: Failed to cleanup client logs: {e}", file=sys.stderr)

            
word_list = ["200 Connection established","get SNI","get Cert","Load client's cert to SSL","Wrap socket with SSLSocket","Resume TLS connection and get request","connect to server - TLS handsake","send request to server","Relay data", "OVERALL TIME"]
time_list = [datetime.timedelta(), datetime.timedelta(), datetime.timedelta(), datetime.timedelta(), datetime.timedelta(), datetime.timedelta(), datetime.timedelta(), datetime.timedelta(), datetime.timedelta(), datetime.timedelta()]
count_list : list[int] = [0,0,0,0,0,0,0,0,0, 0]

class DynamicPerClientFileHandler(logging.Handler):
    """
    A specialized logging handler that routes log records to files based on 
    the active thread's vars (ProxyContext -> host, IP, Port).
    
    The handlers captures logs from a thread before the host could be determined - 
    no request proccessed and parsed. Such file recieves the prefix "PENDING", and
    after a host is accoiated with the client, host's attribute of thread_vars is
    changed -> and "PENDING...log" and "{host}...log" files are merged.
    """

    def __init__(self):
        super().__init__()
        try:
            os.makedirs(CORE_CLIENTS_LOG_DIR_PATH, exist_ok=True)
        except OSError as e:
            print(f"CRITICAL ERROR: per-client initialization failed: {e}", file=sys.stderr)

    def emit(self, record: logging.LogRecord):
        """
        Intercepts log records, updates performance metrics if prefixed with 
        'TIMECHECK', and routes the log message to the appropriate file.

       :type record: logging.LogRecord
        :param record: The log event to be processed.
        """
        try:
            # Metric Extraction
            if isinstance(record.msg, str) and record.msg.startswith("TIMECHECK"):
                self._process_metrics(record.msg)
            
            # Thread vars context 
            host = getattr(ProxyContext.thread_local, "host", None)
            ip = getattr(ProxyContext.thread_local, "ip", None)
            port = getattr(ProxyContext.thread_local, "port", None)

            if not ip or not port:
                return

            pending_name = f"PENDING_{ip}_{port}.log"
            pending_path = os.path.join(CORE_CLIENTS_LOG_DIR_PATH, pending_name)
            formatted_msg = self.format(record)


            if host is None:
                self._write_to_file(formatted_msg, pending_path)
            else:
                final_name = f"{host}_{ip}_{port}.log"
                final_path = os.path.join(CORE_CLIENTS_LOG_DIR_PATH, final_name)
                
                if os.path.exists(pending_path):
                    self._merge_files(pending_path, final_path)
                
                self._write_to_file(formatted_msg, final_path)

        except Exception as e:
            print(f"NON-CRITICAL ERROR: logg emission failed: {e}", file=sys.stderr)

    def _process_metrics(self, msg: str):
        """Parses "TIMECHECK" messages and adds time metrics to analytics objects."""
        try:
            parts = msg.split(" ")
            index = int(parts[0][-2])
            h, m, s = parts[1].split(':')
            duration = datetime.timedelta(hours=int(h), minutes=int(m), seconds=float(s))
            time_list[index] += duration
            count_list[index] += 1
        except (ValueError, IndexError) as e:
            print(f"Metric parsing error: {e}", file=sys.stderr)

    def _merge_files(self, src: str, dst: str):
        """Merges "PENDING"-prefix log file into host-identified log file."""
        try:
            with open(src, 'r', encoding='utf-8') as f_src:
                content = f_src.read()
            with open(dst, 'a', encoding='utf-8') as f_dst:
                f_dst.write(content)
            os.remove(src)
        except (OSError, IOError, FileExistsError) as e:
            self._handle_internal_error(f"Merge failed from {src} to {dst}", e)

    def _write_to_file(self, msg: str, path: str):
        """Writes a single log line to a log file."""
        try:
            with open(path, mode="a", encoding="utf-8") as f:
                f.write(msg + "\n")
        except (OSError, IOError) as e:
            print(f"NON-CRITICAL ERROR: Write failed to {path}", file=sys.stderr)

        
    

class MainFilter(logging.Filter):
    """
    Filter used to isolate 'Proxy' level logs from 'Per-client' level logs.
    Ensures that main-thread logs stay in the core log file, while client-traffic 
    logs are seperated.
    """
    def filter(self, record : logging.LogRecord):
        
        if record.levelno >= logging.WARNING:
            return True
        
        # If any client-specific context exists, it's not a 'record from the main thread.
        if any(hasattr(ProxyContext.thread_local, attr) for attr in ["ip", "port", "host"]):
            return False # not the main Thread
        
        return True # Main thread



        


        