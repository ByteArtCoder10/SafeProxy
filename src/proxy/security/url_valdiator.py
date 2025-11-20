black_list = ['www.neverssl.com', 'www.hello.com', 'www.youtube.com']
class UrlValidator:
    pass
    
    def __init__(self):
        pass
    
    '''checks if a given url is in the proxy's blacklist.'''
    def is_blacklisted(self, url: str) -> bool:
        url = url.lower()
        if not url.startswith("www."):
            url = "www." + url

        '''there are 2 types blacklisted urls allowed:
        -general: only host, no path
        -explicit: path included (in this case, the proxy will only
        block the explicit url, but allow other paths for the same host.)
        '''
        '''Check if URL starts with any blacklist entry'''
        for bl in black_list:
            if url.startswith(bl):
                return True
        return False
    
    '''checks if a given url is malicious.'''
    def is_malicious(self, url: str) -> bool:
        return False