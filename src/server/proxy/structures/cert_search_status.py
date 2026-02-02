from enum import Enum, auto

class CertSearchStatus(Enum):
        """
        Represents the result of a certificate lookup within the Certificate 
        Authority's local dictionary or Disk.
        """
        
        VALID = auto() # Found and not expired
        EXPIRED = auto() # Found but exprired
        NOT_FOUND = auto() # Not found - doesn't exist