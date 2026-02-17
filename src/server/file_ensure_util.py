import os 
import sys
from .server_constants import FOLDERS_EXISTS_CHECK
class EnsureDirsExistsUtil:
    
    @staticmethod
    def handle_dirs_exist() -> bool:
        for folder_path in FOLDERS_EXISTS_CHECK:
            try:
                os.makedirs(folder_path, exist_ok=True)
            except Exception as e:
                raise RuntimeError(f"CRITICAL ERROR: failed creating folder: {e}.")