import os 
import sys
from .server_constants import FOLDERS_EXISTS_CHECK as server_list
from ..client.client_constants import FOLDERS_EXISTS_CHECK as client_list
class EnsureDirsExistsUtil:
    
    @staticmethod
    def handle_dirs_exist() -> bool:
        for folder_path in server_list + client_list:
            try:
                os.makedirs(folder_path, exist_ok=True)
            except Exception as e:
                raise RuntimeError(f"CRITICAL ERROR: failed creating folder: {e}.")