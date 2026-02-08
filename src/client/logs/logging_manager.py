import logging
import sys
import os

from ..constants import LOG_FORMAT, CLIENT_LOG_FILE_PATH

class LoggingManager:

    @staticmethod
    def setup_logging():
        try:

            LoggingManager._cleanup_log()

            # set root logger level
            formatter = logging.Formatter(LOG_FORMAT) # global formatter
            client_logger = logging.getLogger("client") 
            client_logger.setLevel(logging.INFO)
            client_logger.propagate = False

            # Console (sys.stdout)
            console_handler = logging.StreamHandler(sys.stdout)
            console_handler.setFormatter(formatter)
            client_logger.addHandler(console_handler)

            # Main core log file - (client.log)
            client_file_handler = logging.FileHandler(CLIENT_LOG_FILE_PATH, mode="w")
            client_file_handler.setLevel(logging.INFO)
            client_file_handler.setFormatter(formatter)
            client_logger.addHandler(client_file_handler)

        
        except Exception as e:
            print(f"CRITICAL ERROR: could not intalize logging system: {e}", file=sys.stderr)

    @staticmethod
    def _cleanup_log():
        try:
            if os.path.exists(CLIENT_LOG_FILE_PATH):
                with open(CLIENT_LOG_FILE_PATH, "w"):
                    pass # delete the contetns of it
        except Exception as e:
            print(F"NON-CRITICAL ERROR: Failed cleaning up log file: {e}", file=sys.stderr)
