import socket 
import logging
import ipaddress

class NetworkUtils:
    
    @staticmethod
    def is_valid_ip(ip_addr: str) -> bool:
        """
        Checks if a given str is a valid IPv4/IPv6.

        :rtype: bool
        :returns: True if valid, False otherwise.
        """
        try:
            ipaddress.ip_address(ip_addr)
            return True
        except ValueError:
            return False

    @staticmethod
    def get_hostname_from_ip(ip_addr : str) -> str | None:
        '''
        Attempts to find an IP's matching hostname.

        :rtype: str | None
        :returns: hostname if found, None otherwise.
        '''
        # check if IP given is valid
        if not NetworkUtils.is_valid_ip(ip_addr):
            # not an IP, but a host, return the host
            return ip_addr

        # Check if the ip has a corresponding hostname
        try:
            hostname, _, _ = socket.gethostbyaddr(ip_addr)
            logging.debug(f"Resolved {ip_addr} to {hostname}")
            return hostname.lower()
        except (socket.error, socket.gaierror):
            logging.debug(f"No matches found for {ip_addr}")
            return None
        except Exception as e:
            logging.warning(f"DNS hostname lookup failed for {ip_addr}" ,exc_info=True)
        return None

    @staticmethod
    def get_ip_obj(ip : str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | ipaddress.IPv4Network | ipaddress.IPv6Network | None:
        try:
            return ipaddress.ip_address(ip)
        except:
            return None

if __name__ == "__main__":
    print(NetworkUtils.get_hostname_from_ip('8.8.8.8'))
    print(NetworkUtils.get_hostname_from_ip('10.100.102.1'))