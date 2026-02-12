import subprocess
import os        
from cryptography import x509 
from cryptography.hazmat.primitives import hashes
import base64

from ...logs.logger import client_logger
from ...client_constants import ROOT_CA_CERT_PATH, CERT_STORE_PATH, UPDATED_ROOT_CA_CERT_PATH
class CAHandler():

    @staticmethod
    def is_ca_cert_installed(cert: str) -> bool:
        
        # First, neeed to fetch Trusted Root CA's on the local machine, using powershell.
        '''
        
        Command explaination:
        This is a powershell command, allowing the proxy to view all trusted root CA's on a machine,
        and filter them by wildcard, for example - all root CA certs that ther common name has Safeproxy {"*SafeProxy*"}
        1. Get-ChildItem: kind of an alias for linux's ls and windows dir
        2. -Path Cert://LocalMachine/Root: this is the path-  a certifcate provider for windows.
        3. | pipe into
        4. Where-Object - Where-Object allows filtering - pipe only if the next condition is True
        5. {$_.Subject -like "*SafeProxy*"} - the condition, 
            {} is like () in python,
            $_ is a variable prefix,
            .Thumbprint is the thumbprint field in the cert - a unique identifier
            -eq - check exact match

        So, that way we can know if the cert is installed or not.
        '''

        try:
            # get unique fingerprint from given cert
            cert_thumbprint_hex = CAHandler.get_thumbprint(cert)
            client_logger.debug(f"Given certificate thumbprint: {cert_thumbprint_hex}")

            powershell_script = f"Get-ChildItem -Path {CERT_STORE_PATH} | Where-Object {{ $_.Thumbprint -eq '{cert_thumbprint_hex}' }}"

            result = subprocess.run(["powershell", "-NoProfile", "-Command", powershell_script], timeout=60, capture_output=True, text=True, check=True)

            client_logger.info(
                f"Args:{result.args}" \
                f"RetrunCode: {result.returncode}" \
                f"stdout: {result.stdout}" \
                f"stderr: {result.stderr}" \
            )
            is_found = cert_thumbprint_hex in result.stdout.upper()
            if is_found:
                client_logger.info(f"Match found! CA certifcate installed is up to date.")
            else:
                client_logger.info(f"No match found. Most recent CA cert is not installed - will need to be installed.")
            return is_found
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
            client_logger.error(f"Failed to check if SafeProxy root CA cert is installed: {e}", exc_info=True)
            return False

# ... other imports ...

    @staticmethod
    def install_ca_cert() -> bool:
        """
        Installs the CA certificate into the Trusted Root Certification Authorities store.
        Uses Base64 encoding to avoid PowerShell quoting/escaping errors during the RunAs elevation.
        """
        try:
            # 1. Define the exact script we want to run inside the elevated PowerShell.
            inner_script = f"""
            # Stop when encounrting an error - from https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_preference_variables?view=powershell-7.5#erroractionpreference
            $ErrorActionPreference = 'Stop'

            # vars
            $certPath = "{ROOT_CA_CERT_PATH}"
            $storePath = "{CERT_STORE_PATH}"

            # delete old certs where Subject matches *SafeProxy*. uses SilentlyContinue in case finds not files to delete and rasies an error.
            # becuase we set the ErrorActionPre.. to Stop
            Get-ChildItem -Path $storePath | Where-Object {{ $_.Subject -like '*SafeProxy*' }} | Remove-Item -Force -ErrorAction SilentlyContinue

            # install cert
            Import-Certificate -FilePath $certPath -CertStoreLocation $storePath
            """

            # because we are using nested strings and "" and '', powershell intreprets the complex cmd wrong
            # and raises an error. Because of that we encode the inner script to Base64.
            # UTF-16-LE (little endian) is required by PowerShell, as of to docs https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_powershell_exe?view=powershell-5.1#-encodedarguments-base64encodedarguments
            # after that we need to deocde it back with utf-8 n order to pass it to the f string
            encoded_bytes = base64.b64encode(inner_script.encode('utf-16-le'))
            encoded_str = encoded_bytes.decode('utf-8')


            args_for_powershell = f"-NoProfile -EncodedCommand {encoded_str}"


            outer_command = [
                "powershell",
                "-Command",
                f"Start-Process powershell -ArgumentList '{args_for_powershell}' -Verb RunAs -Wait"
            ]

            result = subprocess.run(
                outer_command,
                timeout=60,
                capture_output=True,
                text=True,
                check=True
            )
            client_logger.info(
                "--- REMOVE AND INSTALL CERTIFICATE PROCCESS ---\n" \
                f"Args:{result.args}" \
                f"RetrunCode: {result.returncode}" \
                f"stdout: {result.stdout}" \
                f"stderr: {result.stderr}" \
            )

            # Check if installation actually worked by verifying the cert exists now
            # (Start-Process returns returncode 0 even if the inner script failed, so this is a good safety measure)
            verify_cmd = [
                "powershell", 
                "-Command", 
                f"Get-ChildItem -Path {CERT_STORE_PATH} | Where-Object {{ $_.Subject -like '*SafeProxy*' }}"
            ]
            verify_result = subprocess.run(verify_cmd, capture_output=True, text=True)
            client_logger.info(
                "--- VERIFY ACTUALLY INSTALLED ---\n" \
                f"Args:{verify_result.args}" \
                f"RetrunCode: {verify_result.returncode}" \
                f"stdout: {verify_result.stdout}" \
                f"stderr: {verify_result.stderr}" \
            )
            if "SafeProxy" in verify_result.stdout:
                client_logger.info("CA Certificate installed successfully.")
                return True
            else:
                client_logger.error("Installation command finished, but certificate was not found in store - fail.")
                return False

        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
            # Note: e.stderr might be empty if the error happened inside the elevated window (which closes on error)
            client_logger.error(f"Failed to install certificate : {e}", exc_info=True)
            return False
          
       
    @staticmethod
    def update_local_file(cert_pem : str) -> bool:
        try:
            raw_cert = cert_pem.encode("utf-8")
            with open(ROOT_CA_CERT_PATH, "wb") as f:
                f.write(cert_pem.encode("utf-8"))
            client_logger.info("Successfully Updated local root CA cert file.")
            return True
        except Exception as e:
            client_logger.error(f"Falied updating local root CA cert: {e}", exc_info=True)
            return False

    @staticmethod
    def get_thumbprint(cert_pem: str) -> str:
        cert_obj = x509.load_pem_x509_certificate(cert_pem.encode("utf-8", errors="ignore"))
        return cert_obj.fingerprint(hashes.SHA1()).hex().upper()