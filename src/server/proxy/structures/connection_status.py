from enum import Enum, auto

class ConnectionStatus(Enum):
    """
    Represents the possible states of a proxy-to-server or proxy-to-client 
    connection attempt. Used by the handler to decide the next action 
    (relay data, redirect, drop etc..).
    """

    SUCCESS = auto() 
    CONNECT_FAILURE = auto() # Could not identify Address/Host
    REDIRECT_REQUIRED = auto()  
    BLACKLISTED = auto() 
    MALICOUS = auto() 