import threading


class ProxyContext():
    """
    Provides a thread-local storage (per thread variables) to track context-specific logs 
    (Host, IP, and Port).
    
    This class ensures that logging and analytics can identify which client 
    session a specific log message or metric belongs to without passing 
    context objects through every function call.
    """

    thread_local = threading.local()

    @staticmethod
    def get_local():
        return ProxyContext.thread_local

    @staticmethod
    def set_local(host=None, ip=None, port=None, thread_local=None):
        if thread_local is not None:
            ProxyContext.thread_local = thread_local
        else:
            ProxyContext.thread_local.host = host
            ProxyContext.thread_local.ip = ip
            ProxyContext.thread_local.port = port


    @staticmethod
    def set_local_host(host : str):
        ProxyContext.thread_local.host = host
    
    @staticmethod
    def set_local_ip(ip : str):
        ProxyContext.thread_local.ip = ip
    
    @staticmethod
    def set_local_port(port : str):
        ProxyContext.thread_local.port = port
    
    @staticmethod
    def clear_local():
        """
        Resets the context variables to None. 
        Should be called when a thread is returned to a pool or a connection is closed
        to prevent 'context leaking' between sessions.
        """
        ProxyContext.thread_local.host = None
        ProxyContext.thread_local.ip = None
        ProxyContext.thread_local.port = None     