import urllib.parse

black_list = ['www.hello.com', 'www.youtube.com']
class UrlManager:
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
    
    '''returns a valid google search url from a given string'''
    def get_google_url(self, search_str: str) -> str:
        try:
            search_query = urllib.parse.quote_plus(search_str)
            return f"https://www.google.com/search?q={search_query}"

        except Exception as e:
            raise Exception(f"Failed generating google search url for {search_str} - {e}") from e