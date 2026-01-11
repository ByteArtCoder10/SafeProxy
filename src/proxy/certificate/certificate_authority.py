from ...constants import ORGANIZTION_NAME, COUNTRY_NAME, LOCALITY_NAME, \
COMMON_NAME, CA_VALIDITY_DAYS, CA_ROOT_VALIDITY_DAYS, CA_KEY_SIZE, CERTS_DIR, MAX_MEMORY_CERTS
from dotenv import load_dotenv
import os
import shutil
from datetime import datetime, timedelta, timezone
import fnmatch
from dataclasses import dataclass
from typing import Tuple, Optional
from collections import OrderedDict
import threading
import ipaddress

# Cryptography imports
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from ..utils.network_utils import NetworkUtils
from ..structures.cert_bundle import CertBundle
from ..structures.cert_search_status import CertSearchStatus

from ...logs.loggers import core_logger



class CertificateAuthority:
    """
    Represents the 'SafeProxy' Root CA. 
    This class handles:
    * Root CA generation. 
    * memory caching of active certificates using an LRU (Least Recently Used) style dictionary.
    * disk storage of certificates
    * automatic cleanup of expired certificates.

    :var OrderedDict active_certs: 
    An a LRU-style dict containing max 100 certs in run-time. 

    :var list[str] _known_on_disk: 
    A container of known valid certificates's names in the disk storage

    :var str _ca_key_path:
    The location on the disk of CA's private key.

    :var str _ca_cert_path:
    The location on the disk of the directory of certificates' storage.

    :var CertBundle _ca_bundle:
    Wrapper CertBundle obj representing the CA.

    :var threading.RLock _lock:
    A thrading lock used to restrict resources to one thread at a time.
    """

    def __init__(self):
        """
        Initializes the Certificate Authority by loading configuration, 
        ensuring directory structures exist, and preparing the Root CA bundle.
        """

        self._active_certs: OrderedDict[str, CertBundle] = OrderedDict()
        
        self._lock = threading.RLock()

        self._known_on_disk = self._update_or_load_known_on_disk()
        
        self._cleanup_disk()

        ca_dir = os.getenv('ROOT_CA_DIR')

        # ensure dirs exist
        os.makedirs(ca_dir, exist_ok=True)
        os.makedirs(CERTS_DIR, exist_ok=True)

        self._ca_key_path = os.path.join(ca_dir, "root_ca.key")
        self._ca_cert_path = os.path.join(ca_dir, "root_ca.crt")

        # load or generate the root CA
        self._ca_bundle = self._load_or_generate_root_ca()

    # --- PUBLIC USE ---

    def get_certificate_for_host(self, host: str, * , ECDSA=True) -> Tuple[str | None, str | None]:
        """
        Main entry point for obtaining a certificate bundle for a specific host.
        Coordinates between memory cache, disk cache, and generation logic.

        :type host: str
        :param host: The target hostname or IP address

        :type ECDSA: bool
        :param ECDSA: If True, uses Elliptic Curve keys. otherwise, defaults to RSA.

        :rtype: Tuple[bytes, bytes, bytes]
        :returns: A tuple containing (path_to_PEM_encoded_cert, path_to_PEM_encoded_privkey).
        """

        # Check memory
        memory_status, memory_matching_host, memory_bundle = self._check_memory(host)
        core_logger.debug(f"memory matching host: {memory_matching_host}")
        
        match memory_status:

            case CertSearchStatus.VALID:
                res_bundle = memory_bundle

            case CertSearchStatus.EXPIRED:
                core_logger.info(f"Certificate for {memory_matching_host} expired. Regenerating...")
                res_bundle = self._issue_host_certificate(memory_matching_host, cert_bundle=memory_bundle, KeepPrivKey=True)

            # Not found in memory
            case _:

                # Check disk
                disk_status, disk_matching_host, disk_bundle = self._check_disk(host)
                core_logger.info(f"disk matching host: {disk_matching_host}")
                
                match disk_status:

                    case CertSearchStatus.VALID:
                        res_bundle = disk_bundle

                    case CertSearchStatus.EXPIRED:
                        core_logger.info(f"Certificate for {disk_matching_host} expired. Regenerating...")
                        res_bundle = self._issue_host_certificate(disk_matching_host, cert_bundle=disk_bundle, KeepPrivKey=True)
                    
                    case _:
                        core_logger.info(f"Certificate for {host} wasn't found. Generating a new one...")
                        res_bundle = self._issue_host_certificate(host, ecdsa=ECDSA)
        
        
        # Memory host (if found), if not -> Disk host (....) -> given host
        target_host = memory_matching_host or disk_matching_host or host 

        # update memory, disk, and known hosts list on memory.
        self._update_or_add_to_memory(target_host, res_bundle)
        status, cert_path, key_path = self._update_or_add_to_disk(target_host, res_bundle)
        
        if status:
            core_logger.info(f"Added {target_host} to memory.")
            self._known_on_disk = self._update_or_load_known_on_disk()
            return cert_path, key_path

        return None, None


    # --- CORE, LOGIC FUNCTIONS ---
    

    def _cleanup_disk(self) -> None:
        """
        Scans the certificates directory and removes subdirectories containing 
        expired certificates or those not modified within the threshold defined 
        by MAX_MEMORY_CERTS.
        """

        # threshold setting
        threshold = datetime.now(timezone.utc) - timedelta(days=MAX_MEMORY_CERTS)
        for cert_dir in self._known_on_disk:
            dir_path = os.path.join(CERTS_DIR, cert_dir)
            try:
                # cert and priv_key files
                files = os.listdir(dir_path)
                
                # get cert path
                for file in files:
                    if file.endswith(".crt"):
                        cert_path = os.path.join(dir_path, file)
                        
                        # float value (since epoch)
                        cert_modification_time_float = os.path.getmtime(cert_path)
                        break

                # conversion to datetime obj
                cert_modification_time = datetime.fromtimestamp(cert_modification_time_float, tz=timezone.utc)
                
                # if the threshold is later than cert and key last modfied date
                if cert_modification_time < threshold:
                    core_logger.info(f"Cleaning up expired certificate for {dir_path}")
                    shutil.rmtree(dir_path) # remove directory + files inside
            
            except Exception as e:
                core_logger.error(f"Failed to delete expired certifcate for {dir_path}: {e}", exc_info=True)
                
    def _check_disk(self, host: str) -> tuple[CertSearchStatus, str | None, CertBundle | None]:
        """
        Performs a search on the disk to find a matching certificate 
        for the requested host. Optimized with checking SAN matches as well.
        Safe against parellal use of threads (possible RuntimeError), 
        with the use of an RLock.
        
        :type host: str
        :param host: The hostname to search for.

        :rtype: tuple[CertSearchStatus, str | None, CertBundle | None]
        :returns: A search status, the matching hostname found, and the CertBundle object.
        """

        with self._lock:
            try:
                for cert_host in self._known_on_disk:
                    if self._host_matches_sans(host, cert_host):
                        
                        # Cert, priv key paths
                        host_dir_path = os.path.join(CERTS_DIR, host)
                        cert_path = os.path.join(host_dir_path, f"{host}.crt")
                        priv_key_path = os.path.join(host_dir_path, f"{host}.key")

                        if os.path.exists(cert_path) and os.path.exists(priv_key_path):
                            pem_cert = self._read_from_file(cert_path)
                            pem_key = self._read_from_file(priv_key_path)

                            # create cryptography objects for CertBundle creation
                            cert = x509.load_pem_x509_certificate(pem_cert)
                            priv_key = serialization.load_pem_private_key(pem_key,password=None)

                            bundle = CertBundle(priv_key, cert, pem_key, pem_cert)

                            if not self._is_valid(bundle.certificate):
                                return CertSearchStatus.EXPIRED, cert_host, bundle

                            if bundle is None: # not expected to happen
                                return CertSearchStatus.NOT_FOUND, cert_host, None
                            
                            return CertSearchStatus.VALID, cert_host,  bundle
        
            except Exception as e:
                core_logger.warning(f"Couldn't check disk properly for certificate's host: {host}. {e}", exc_info=True)

            return CertSearchStatus.NOT_FOUND, None, None # Not found
  
    def _check_memory(self, host: str) -> tuple[CertSearchStatus, str | None, CertBundle | None]: 
        """
        Performs a search in the OrderedDict (memory cache) to find a matching certificate 
        for the requested host. Optimized with checking SAN matches as well.
        Safe against parellal use of threads (possible RuntimeError), 
        with the use of an RLock.

        :type host: str
        :param host: The hostname to search for.

        :rtype: tuple[CertSearchStatus, str | None, CertBundle | None]
        :returns: A search status, the matching hostname found, and the CertBundle object.
        """

        with self._lock:

            for cert_host in self._active_certs:
                if self._host_matches_sans(host, cert_host):
                    bundle = self._active_certs[cert_host]
                    
                    if not self._is_valid(bundle.certificate):
                        return CertSearchStatus.EXPIRED, cert_host, bundle
                    
                    if bundle is None: # not expected to happen.
                        return CertSearchStatus.NOT_FOUND, cert_host, None

                    return CertSearchStatus.VALID, cert_host, bundle

            return CertSearchStatus.NOT_FOUND, None,  None 
    
    def _update_or_add_to_disk(self, host: str, bundle: CertBundle) -> tuple[bool, str | None, str | None]:
        """
        Adds or updates a CertBundle to disk. Creates a new folder 
        for the host if it does not exist. Safe against parellal use of 
        threads (possible RuntimeError), with the use of an RLock.

        :type host: str
        :param host: The hostname of the certificate.
        
        :type bundle: CertBundle
        :param bundle: The certificate and key data to save.

        :rtype: tuple[bool, str | None, str | None]
        :returns: Success status, path to the .crt file, and path to the .key file.
        """
        with self._lock:
            try:
                folder_path = os.path.join(CERTS_DIR, host)
                pem_cert_path = os.path.join(folder_path, f"{host}.crt")
                pem_key_path = os.path.join(folder_path, f"{host}.key")

                if not os.path.exists(folder_path): # folder doesn't exist
                    os.mkdir(folder_path)
                
                # saving proccess
                self._save_to_file(pem_cert_path, bundle.pem_cert)
                self._save_to_file(pem_key_path, bundle.pem_key)

                core_logger.info(f"Successfully saved/updated to disk {host}'s cert and private key.")
                return True, pem_cert_path, pem_key_path
            
            except Exception as e:
                core_logger.warning(f"Failed saving/updating to disk {host}'s Cert and private key: {e}", exc_info=True)
                return False, None, None
    
    def _update_or_add_to_memory(self, host: str, bundle: CertBundle):
        """
        Adds or updates a CertBundle to the memory cache. LRU 
        CertBundle is deleted if the dict size exceeds MAX_MEMORY_CERTS.
        Safe against parellal use of  threads (possible RuntimeError), 
        with the use of an RLock.

        :type host: str
        :param host: Hostname key for the cache.
        
        :type bundle: CertBundle
        :param bundle: The bundle object to cache.
        """
        with self._lock:
            for key, value in self._active_certs.items():
                if key == host: 
                    self._active_certs.move_to_end(key)
                    if value != bundle:
                        self._active_certs[key] = bundle
                    
                    # check if passed max size.
                    if len(self._active_certs) > MAX_MEMORY_CERTS:
                        self._active_certs.popitem(last=False) # pop the first value - least used
                    return
    
        # wasn't found on dict, add to dict + check if passed max size.
        self._active_certs[host] = bundle

        if len(self._active_certs) > MAX_MEMORY_CERTS:
            self._active_certs.popitem(last=False) # pop the first value - least used

    def _update_or_load_known_on_disk(self) -> list[str]:
        """
        Reads the certificate directory on disk, and returns existing
        certificates' hostnames. Safe against parellal use of  
        threads (possible RuntimeError), with the use of an RLock.

        :rtype: list[str]
        :returns: A list of directory names representing known hosts on disk.
        """
        with self._lock:

            try:
                return [dir_name for dir_name in os.listdir(CERTS_DIR)]
            
            except FileNotFoundError as e:
                core_logger.warning(f"Directory {CERTS_DIR} wasn't found.")
                return []
            
            except Exception as e:
                core_logger.warning(f"Unexpected error: \
                couldn't load dirs names from {CERTS_DIR} - {e}", exc_info=True)
                return []

    def _load_or_generate_root_ca(self) -> CertBundle:
        """
        Attempts to load the Root CA files (certificate, private key) from disk.
        If missing or expired, triggers a new generation of the Root CA.

        :rtype: CertBundle
        :returns: The Root CA certificate and private key bundle.
        """

        if os.path.exists(self._ca_key_path) and os.path.exists(self._ca_cert_path):
            try:
                core_logger.info("Loading existing root CA...")
                
                #load ca's priv key and decrypt it
                pem_ca_key = self._read_from_file(self._ca_key_path)
                priv_key_password = os.getenv("ROOT_CA_PRIVATE_KEY_PASSWORD").encode()
                priv_key = serialization.load_pem_private_key(pem_ca_key, password=priv_key_password)
                
                #load ca's cert
                pem_ca_cert = self._read_from_file(self._ca_cert_path)
                cert = x509.load_pem_x509_certificate(pem_ca_cert)

                
                if not self._is_valid(cert):
                    core_logger.warning("Root CA is expired. Regenerating...")
                    return self._generate_root_ca()
                
                return CertBundle(
                    private_key=priv_key, certificate=cert,
                    pem_key=pem_ca_key, pem_cert=pem_ca_cert
                )
            except Exception as e:
                core_logger.error(f"Failed to load CA: {e}. Be aware: Root CA cert would need to be re-installed on client's machine.\
                              Regenerating...", exc_info=True)
        
        return self._generate_root_ca()

    def _generate_root_ca(self) -> CertBundle:
        """
        Creates a new self-signed Root CA certificate using ECDSA. 
        Sets the CA bit to True in BasicConstraints.

        WARNING: This function is intended for one-time use, or occasional use
        only when exisiting CA's certificate/private key was expired or not found.
        Gnereating a new self-signed CA's cert with a new key requires re-installation
        of the cert on client's machine.

        :rtype: CertBundle
        :returns: The newly generated Root CA bundle.
        """
        
        core_logger.info("Generating new Self-Signed Root CA...")
        private_key = self._generate_private_key()


        # subject is also the issuer since the root ca self-signs it's cert.
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, COUNTRY_NAME),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, ORGANIZTION_NAME),
            x509.NameAttribute(NameOID.COMMON_NAME, COMMON_NAME),
        ])

        builder = x509.CertificateBuilder()
        builder = builder.subject_name(subject)
        builder = builder.issuer_name(issuer) 
        builder = builder.public_key(private_key.public_key())
        builder = builder.serial_number(x509.random_serial_number())
        builder = builder.not_valid_before(datetime.now(timezone.utc))
        builder = builder.not_valid_after(datetime.now(timezone.utc) + timedelta(days=CA_ROOT_VALIDITY_DAYS)) 
        
        # CA Constraint: This cert is allowed to sign other certs (=the entity it belongs to is a CA),
        #  and unlimited CA's can be signed under it. 
        builder = builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True,)
        
        # self-sign the cert
        cert = builder.sign(private_key=private_key, algorithm=hashes.SHA256())
        
        pem_ca_key = self._priv_key_to_pem(private_key, EncryptKeyCaPw=True)
        pem_ca_cert = self._cert_to_pem(cert)
        
        # create a CertBundle obj with CA's priv key and pr
        bundle = CertBundle(
            private_key=private_key, certificate=cert,
            pem_key=pem_ca_key, pem_cert= pem_ca_cert
        )

        # Persist CA
        try:
            self._save_to_file(self._ca_key_path, bundle.pem_key)
            self._save_to_file(self._ca_cert_path, bundle.pem_cert)
        except OSError as e:
            core_logger.error("Couldn't save CA's cert and priv key to disk", exc_info=True)
        
        return bundle

    def _issue_host_certificate(self, host: str, *, cert_bundle:CertBundle = None, KeepPrivKey=False, ecdsa=True) -> CertBundle:
        """
        Issues a new end-entity certificate for a specific host/IP, signed by Root CA.
        Correctly handles IP SANs vs DNS SANs for browser compatibility.
        Handles expired certs as well -> only changes the not_Valid_before/after fields,
        while keeping the private key as it is.

        :type host: str
        :param host: The target domain or IP.

        :type cert_bundle: CertBundle
        :param cert_bundle: Existing bundle to reuse if regenerating an expired cert.

        :type KeepPrivKey: bool
        :param KeepPrivKey: If True, reuses the existing private key instead of generating a new one.

        :type ecdsa: bool
        :param ecdsa: Determines if the key pair should be ECDSA or RSA.

        :rtype: CertBundle
        :returns: The signed end-entity certificate bundle.
        """
        if KeepPrivKey and cert_bundle:
            private_key = cert_bundle.private_key
        else:
            private_key = self._generate_private_key(ecdsa=ecdsa)
        
        # Host Subject - details are the same as Root ca's certifcate (neglible)
        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, COUNTRY_NAME),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, ORGANIZTION_NAME),
            x509.NameAttribute(NameOID.COMMON_NAME, host),
        ])

        # Issuer is Root CA
        issuer = self._ca_bundle.certificate.subject

        builder = x509.CertificateBuilder()
        builder = builder.subject_name(subject)
        builder = builder.issuer_name(issuer)
        builder = builder.public_key(private_key.public_key())
        builder = builder.serial_number(x509.random_serial_number())

        # Safety measure - computers aren't always time synced. a delay of couple seconds is possible.
        # in order to prevent cases where the clients refuse certifcates because of delay in time,
        # the not_valid_before is set 10 minutes earlier.
        now = datetime.now(timezone.utc) - timedelta(minutes=10) 
        builder = builder.not_valid_before(now)
        builder = builder.not_valid_after(now + timedelta(days=CA_VALIDITY_DAYS))

        
        # SAN extension - mandatory for modern browsers
        # generate optimizations for SANS
        san_list = self._wildcard_san_optimazition(host)

        # Optimizations were'nt aplied -> the host is an IP
        if len(san_list) == 1: 
            
            core_logger.debug(f"san_list for cert: {san_list}")
            
            builder = builder.add_extension(
                x509.SubjectAlternativeName([
                x509.IPAddress(NetworkUtils.get_ip_obj(host))
                ]),
                critical=False
            )

        else:
            
            core_logger.debug(f"SAN list for  {host}: {san_list}.")

            builder = builder.add_extension(
                x509.SubjectAlternativeName(
                [x509.DNSName(san_host) for san_host in san_list]
                ),
            critical=False
            )
        
        # Basic constraints -> not a CA
        builder = builder.add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True,
        )

        # Sign with CA's priv_key
        certificate = builder.sign(
            private_key=self._ca_bundle.private_key,
            algorithm=hashes.SHA256()
        )

        return CertBundle(
            private_key=private_key, certificate=certificate,
            pem_key=self._priv_key_to_pem(private_key), pem_cert=self._cert_to_pem(certificate)
        )


    # --- HELPER FUNCTIONS ---
    

    def _wildcard_san_optimazition(self, host: str) -> list[str]:
        """
        Generates a list of SANs including 
        wildcards ( *.example.com) to increase certificate reuse potential.
        if the host is an IP, retruns [IP].

        :type host: str
        :param host: The base host string.

        :rtype: list[str]
        :returns: A list of DNS/IP strings for the SAN extension.
        """
        san_list = [host] 
        
        # If the host is an IP, don't try to optimize.
        hostname_match = NetworkUtils.get_hostname_from_ip(host)
        if not hostname_match:
            return san_list
 
        # add IP's matching hostname to dictionary
        if hostname_match not in san_list:
            san_list.append(hostname_match)
        
        host  = hostname_match
        
        parts = host.split('.')
        
        # Check if it's a standard domain (has at least 1 dot: example.com)
        if len(parts) >= 2:
            
            #  If it starts with www, get the root
            if parts[0] == "www":
                base_domain = ".".join(parts[1:])
                if base_domain not in san_list:
                    san_list.append(base_domain)
            else:
                base_domain = ".".join(parts)

            # Add the wildcard for the base domain (*.google.com)
            # allows the cert to be reused for mail.google.com, drive.google.com...
            wildcard = f"*.{base_domain}"
            if wildcard not in san_list:
                san_list.append(wildcard)

        return san_list
    
    def _host_matches_sans(self, requested_host: str, base_host: str) -> bool:
        """
        Checks if a requested hostname is covered by a base host's certificate scope of SAN's.
        This includes exact matches and valid wildcard matches.
        
        Logic:
        - Exact: 'example.com' matches 'example.com'
        - Wildcard: 'www.example.com' matches '*.example.com'
        *Note: Wildcards are only valid for one subdomain level. 
        'mail.il.example.com' doesn't match '*.example.com'

        :type requested_host: str
        :param requested_host: The host requested by the client.

        :type base_host: str
        :param base_host: a given host of a certificate (subject name).

        :rtype: bool
        :returns: True if the certificate covers the requested host
        """
        requested_parts = requested_host.split(".")
        base_parts= base_host.split(".")

        # if last or previous-to-last parts of the hosts don't match, accordingly.
        # for example, "www.example.com", "www.example.il"
        if requested_parts[-1] != base_parts[-1] or \
                requested_parts[-2] != base_parts[-2]:
            return False
        
        # exact match
        if requested_host == base_host:
            return True
        
        base_host_sans = self._wildcard_san_optimazition(base_host)
        for san_host in base_host_sans:
            core_logger.debug(f"host check: opt - {san_host}, req - {requested_host}")
            if san_host.startswith("*") and san_host.count(".") == requested_host.count("."):

                # a wildcard (*) matches only ONE single label within a domain name.
                # It cannot span across multiple dots.

                # Ex: san_host = "*.gstatic.com" (2 dots), requested_host = "www.gstatic.com" (2 dots)
                # Match: yes. The '*' replaces 'www'. 
                # Count check: 3 == 2 + 1 (Valid)

                # Ex: san_host = "*.gstatic.com" (2 dots), requested_host = "gstatic.com" (1 dot)
                # Match: no. A wildcard at the beginning requires a label before it to exist. 

                if fnmatch.fnmatch(requested_host, san_host):
                    core_logger.debug(f"{san_host} matched to {requested_host}")
                    return True
        
        return False # No match found

    def _is_valid(self, cert: x509.Certificate) -> bool:
        """
        Checks if a certificate is within its valid time scope (not_before/not_after).
        Includes a 1 hour safety buffer for expiration.

        :type cert: x509.Certificate
        :param cert: The cryptography certificate object to check.

        :rtype: bool
        :returns: True if valid, False if expired or not yet active.
        """
        now = datetime.now(timezone.utc)
        # For saftey, - the not_valid_after timestamp is moved back 1 hour in case the certificate 
        # is only seconds or minutes away from becoming invalid
        return cert.not_valid_before_utc <= now < cert.not_valid_after_utc - timedelta(hours=1)
    
    def _get_root_ca_cert(self) -> bytes:
        """
        :rtype: bytes
        :returns: Root CA's certificate in PEM format.
        """
        return self._ca_bundle.pem_cert
    
    def _generate_private_key(self, *, ecdsa=True) -> rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey:
        """
        Generates a secure asymmetric private key.

        :type ecdsa: bool
        :param ecdsa: If True, generates a SECP256R1 elliptic curve key. If False, generates RSA-SIZE=[KEY_SIZE].

        :rtype: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey
        :returns: A private key object.
        """
        if ecdsa:
            return ec.generate_private_key(ec.SECP256R1())
        
        return rsa.generate_private_key(public_exponent=65537, key_size=CA_KEY_SIZE)

    def _priv_key_to_pem(self, key: rsa.RSAPrivateKey, EncryptKeyCaPw=False) -> bytes:
        """
        Turns a private key object to PEM format.

        :type key: rsa.RSAPrivateKey | ec.EllipticCurvePrivateKey
        :param key: Key object to create from

        :type EncryptKey: bool
        :param EncryptKey: If True, encrypts the PEM with the Root CA's password.

        :rtype: bytes
        :returns: PEM encoded private key.
        """

        if EncryptKeyCaPw:
            # Protect the private key with password
            enc_algorithm = serialization.BestAvailableEncryption(
                os.getenv("ROOT_CA_PRIVATE_KEY_PASSWORD").encode()
                )
        else:
            enc_algorithm = serialization.NoEncryption()
        return key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm= enc_algorithm
        )

    def _cert_to_pem(self, cert: x509.Certificate) -> bytes:
        """
        Turns a certificate object to PEM format.

        :type cert: x509.Certificate
        :param cert: Certificate object to create from.

        :rtype: bytes
        :returns: PEM encoded certificate.
        """
        return cert.public_bytes(serialization.Encoding.PEM)

    def _save_to_file(self, path: str, data: bytes):
        """
        Helper func to write bytes to a file.

        :type path: str
        :param path: Destination file path.
        
        :type data: bytes
        :param data: Binary data to write.

        :raises OSError: If saving failed
        """
        try:
            with open(path, "wb") as f:
                f.write(data)
        except OSError as e:
            raise OSError(f"Failed to save {path}: {e}") from e

    def _read_from_file(self, path: str) -> bytes:
        """
        Helper func to read bytes from a file.

        :type path: str
        :param path: dst file path.
        
        :type data: bytes
        :param data: Binary data to write.

        :raises OSError: If reading failed
        """
        try:
            with open(path, "rb") as f:
                raw_data = f.read()
                return raw_data
        except OSError as e:
            raise OSError(f"Failed to load {path}: {e}") from e



if "__main__" == __name__:
    ca = CertificateAuthority()
    core_logger.info(f"ROOT PK AFTER ENC: {ca._ca_bundle.pem_key}")
    for i in range(30):
        ca.get_certificate_for_host(f"Google{i}.com")
    for cert in ca._active_certs:
        core_logger.info(f'CertBundle: {cert}')
    core_logger.info("ACTIVE CERTS (hosts): %s", list(ca._active_certs.keys()))
    core_logger.info(f"KNOWN ON DISK: {ca._known_on_disk}")