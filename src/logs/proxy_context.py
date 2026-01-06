import threading


class ProxyContext():

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
        ProxyContext.thread_local.host = None
        ProxyContext.thread_local.ip = None
        ProxyContext.thread_local.port = None     