from ..structures.request import Request
from ...logs.loggers import core_logger

class Parser():
    '''Handles HTTP(S) raw requests + responses, and parses them accordingly. 
    '''

    '''parses an HTTP request and returns an a Request obj wtih the following: 
        -Method
        -Host + Port
        -path
        -Http_version
        -Headers
        -Body
    '''
    @staticmethod
    def parse_request(request: str) -> Request:
            
            try:
                lines = request.split('\r\n')

                # remove emptyspace list elements because of /r/n/r/n
                lines = [line for line in lines if line]
                
                first_line = lines[0]

                # parse request line
                method, request_URI, http_version = first_line.split(' ')
                if not method:
                    raise ValueError("Could not get request's method.")
                if not request_URI:
                    raise ValueError("Could not get request's request_URI.")
                
                # determine URI type
                http_pos = request_URI.find("://")    
                '''
                conditions exp:
                *1: "://" doesn't exist
                *2: longest pre url - "https" gives
                that the highest postion of "://" will be 5.
                *3: shortest pre url - "http" gives that
                lowest position of  "://" will be 4.
                '''
                if http_pos == -1 or http_pos > 5 or http_pos < 4: 
                    temp = request_URI
                    uri_form = "origin-form"
                else:
                    temp = request_URI[(http_pos + 3):] # in order to remove "://"
                    uri_form = "absolute-form"
    
                # extract host, port and path
                port_pos = temp.find(":")
                path_pos = temp.find("/")
                if path_pos == -1:
                    path_pos = len(temp)
                
                path = temp[path_pos:] or '/'

                if port_pos == -1 or path_pos < port_pos:
                    host = temp[:path_pos]
                    port = 443 if method == "CONNECT" else 80 #HTTPS deafult port - 443, HTTP - 80
                else:
                    host = temp[:port_pos]
                    port = int(temp[(port_pos + 1):path_pos])

                #parse headers
                headers = {}
                header_name = None
                header_value = None
                body_line_num = None
                for i, line in enumerate(lines[1:]):
                    if line == "\r\n\r\n":
                        body_line_num = i+1 #Next line is the start of the body
                        break
                    header_name_pos = line.find(":")
                    header_name = line[:header_name_pos]
                    header_value = line[header_name_pos+1:].strip()
                    headers[header_name] = header_value

                # parse body
                body = None
                if body_line_num:
                    body = lines[body_line_num:]
                
                # Check host header match first-line host (if header exists)
                host_header_value = headers.get("Host", None)
                core_logger.debug(f"Host by first line: {host}, Host by headers: {host_header_value}")

                if uri_form == "origin-form" and not host_header_value:
                    raise ValueError("Missing Host header in origin-form request.")

                elif uri_form == "absolute-form" and \
                    host_header_value and host_header_value != f"{host}:{port}" and host_header_value != host:
                    raise ValueError("Host header does not match request URI host/port.")
                
                # if first-line host is None, and Host header has a value
                if not host:
                    # check if host_header value has port in it
                    if ":" in host_header_value:
                        host = host_header_value.split(":")[0]
                    else:
                        host = host_header_value
                    
                # turnning Parsing information to a Request obj
                parsed_request = Request(method, host, port, http_version, path, headers, body)
                core_logger.info(parsed_request.prettify())
                return parsed_request
    
            except ValueError as e:
                core_logger.warning(f"Request error:\n{e}", exc_info=True)
            except Exception as e:
                core_logger.warning(f"Unexpected error:\n{e}", exc_info=True)

# req = Parser()
# reqe = '''POST /web-reports?context=eJwNz19M1XUYx3F-vJXh7xzO7_x-z7dl0qYS2Fadw5-lzTG9iDwi7iBzlc5Tg4BzGBt_9HjOCaZeNGSrZjWngoBQdgFO0DmbbsYYNUvTLBzCKMJi3hhlkW7yLxW_F6-r5_l8nj3md0urvq81wou1RmZhnXHuwB7jnRejxqahvcahQMyY6Y4ZZ_pjxr1VCSOUkTCOjyaMmj8ajC7vzuSGFTuT-3eZRCImD9tM7k-YNE6bhF52cavIxb1iFxd7XPSfd3H7rot4yM1_ZW5ejbupn3EzVZLGQFsar7zp4dQlDyVXPRzW_n3sYU2uxboNFmc3WyTCFq6ERftHFrmtFqknLZ69bjGQ6SW1zIupDXd4mZj1kr_g5V2xOfGWze1Sm2CVzf79Nge1rc02r39qs7HFZvC0TfpZGxmxeX7K5s6cjWeZQ2G2w3jAYbHIIRhyWJ5wcFocqnscLg86bPjZIX_YYfWoQ9aYns85fPzEYSxFGHEJ2c8IJSuEYLrQu1KQDKEgUyjMEiq1Hr_gWyv8mi_sLhAqgkJ8mzCndezSuyEhIywUaX1VglkvHNF-3yOoqNCsmU1C5EMhdEzfaxUutAsHOwXPF0LnSeGzL3W2W9jXI3zbKyT3Cde0ga-EyUtC2dfCucvC_BXh82t650fh5g1h-0-6e0QwxoTAL0Kjtvw3YYs2pkUmhKRJnbkjfHJXyPpbeGNaOPpA_zojpM3pTi0wLwxqU9rQgvDX_8Ijzf9IiC4Kby9R4FYspik-8CjGtZitOPWcIuUFRXCNovslxfnXFP71isMbFU2bFN8EFP9oarMiKai4UKxo36HYl56U4rhTZ5u6fkjx_tl5YzY5w9dYH4_Fy8P-98Plvki0vi7mC9dV-iqi1bHqivdqSvNy8tbm5uSt9-fmlO7OeQrpBdwN HTTP/2\r\nHost: www.youtube.com\r\nCookie: __Secure-YENID=10.YTE=QeLt5FeQyTm_Svbsno3oHTh9dVXFNuH8PGfqV4uO16cyuNstkqCo2YSWFpsWEkfbmYJnPFT4DG66C62W2DoO6f6VaCuow3anyTLVP2g_OhWQIdnxfJ9e-EoCuJON8R7J2hj3_xJhgI6_CNLDV0GMxMouLOiXOHlZ3L1-HBBpaRyf3GJsb3ls-JY4uYj9Kukbae9dp55dGKa5Qx3EW6CKa6sDb0gJPmYeeFeE44nJfXzgNvffLcUERzeYsJ435ShdnBSWuJq-CmMRuESRR9q9HkFQUJLrZiCktt5BhBNY1MG_bNFvB-57G_MUcN5_aTVJz5XMYPRahAZp-vMe8kjShA; VISITOR_INFO1_LIVE=vHyeTozDjvk; VISITOR_PRIVACY_METADATA=CgJJTBIEGgAgUA%3D%3D; PREF=f6=40000000&tz=Asia.Jerusalem; GPS=1; YSC=aRVIBO-CLo4; __Secure-ROLLOUT_TOKEN=CKa7sM7dnPiOAhDSv76BgLSQAxiR75n37NOQAw%3D%3D\r\nContent-Length: 498\r\nContent-Type: application/reports+json\r\nOrigin: https://www.youtube.com\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36\r\nAccept-Encoding: gzip, deflate, br\r\nAccept-Language: en-US,en;q=0.9\r\nPriority: u=4, i\r\n\r\n[{"age":0,"body":{"columnNumber":8,"id":"UnloadHandler","lineNumber":13770,"message":"Unload event listeners are deprecated and will be removed.","sourceFile":"https://www.youtube.com/s/_/ytmainappweb/_/js/k=ytmainappweb.kevlar_base.en_US.5qNAiOopdFM.es5.O/am=AAAAAg/d=0/br=1/rs=AGKMywFvZxRtSPvDBcC9_Whxj0s1bggFrA"},"type":"deprecation","url":"https://www.youtube.com/","user_agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36"}]\r\n
# '''
# req.parse_request(reqe)