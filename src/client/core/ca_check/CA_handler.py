import subprocess
import os

from ...logs.logger import client_logger
from ...client_constants import ROOT_CA_CERT_PATH, CERT_STORE_PATH
class CAHandler():

    @staticmethod
    def is_ca_installed() -> bool:
        
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
            .Subject is the subject name field in the cert - for who it was privded
            -like - is the wilcard keyword in powershell (for example -like return True for "nono*" and "nonorffsddf")
            "*SafeProxy*" - the str to check in subjec tname in the certifcate
        
        So, that way we can know if the cert is installed or not.
        Note, we ar enot checking content-match, while technically it could happen that a root CA subject has "SafeProxy"
        in it, however it is VERY unlikely.
        '''

        try:

            cmd = 'Get-ChildItem -Path Cert://LocalMachine/Root | Where-Object {$_.Subject -like "*SafeProxy*"}'

            result = subprocess.run(["powershell", "-Command", cmd], timeout=60, capture_output=True, text=True, check=True)

            client_logger.info(
                f"Args:{result.args}\n" \
                f"RetrunCode: {result.returncode}\n" \
                f"stdout: {result.stdout}\n" \
                f"stderr: {result.stderr}\n" \
            )
            return "SafeProxy" in result.stdout
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
            client_logger.error(f"Failed to check if SafeProxy root CA cert is installed: {e}", exc_info=True)
            return False

    @staticmethod
    def install_ca() -> bool:
        """
        By deafult, in order to install a cert in a system's RootTrustStore, admin privilages
        are needed. When trying to install a root-cert using powershell as a restricted user,
        i got this error:
        -------Import-Certificate : Access is denied. (Exception from HRESULT: 0x80070005 (E_ACCESSDENIED))
        -------At line:1 char:1
        -------+ Import-Certificate -FilePath {Censord path} ...
        -------+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
        -------    + CategoryInfo          : NotSpecified: (:) [Import-Certificate], UnauthorizedAccessException
        -------    + FullyQualifiedErrorId : System.UnauthorizedAccessException,Microsoft.CertificateServices.Commands.ImportCertific 
        -------ateCommand

        command explaination:
        -Start-Process powershell: starts a new powershell process 
        -ArgumentList: the specified arguments in the following"..." are arguments for the powershell process.
        
        -"-Command Import-Certifcate -FilePath {ROOT_CA_CERT_PATH} -Cert-Store-Location cert:/LocalMachine/Root":
            -Command: tells powershell the following arguments should be executed as a command
            -Import-Certifcate: the function/command for installing a certificate somewhere
            - -FilePath filepath: the path to the cert
            - -Cert-Store-Location filepath - in which Cert Store to instal this cert, in our case we need the
            "Trusted Root Certification Authorites" which's path is: cert://LocalMachine//Root
            --Verb RunAs: -Verb a keyowrd for specifying Verb, some kind of action. RunAs means ask for permission from the user to run 
            this proccess as an Administrator (like the dialog u often see when installing a new desktop-app)
        So, we need to ask the user for admin privilages using -Verb RunAs
        
        :return: True if the installation was successfull, otherwise False.
        :rtype: bool
        """
        if CAHandler.is_ca_installed():
            client_logger.info("SafeProxy certifcate already Installed.", exc_info=True)
            return

        try:        
            # get cert from resources
            install_command = f'Start-Process powershell -ArgumentList "-Command Import-Certificate -FilePath {ROOT_CA_CERT_PATH} -Cert-Store-Location {CERT_STORE_PATH}" -Verb RunAs -Wait'
            inner_command = f"Import-Certificate -FilePath '{ROOT_CA_CERT_PATH}' -CertStoreLocation {CERT_STORE_PATH}"
            install_command = f'Start-Process powershell -ArgumentList " -Command {inner_command}" -Verb RunAs -Wait'
            result = subprocess.run(
                ["powershell", "-Command", install_command],
                timeout=60,
                capture_output=True,
                text=True,
                check=True
            )

            client_logger.info(
                f"Args:{result.args}" \
                f"RetrunCode: {result.returncode}" \
                f"stdout: {result.stdout}" \
                f"stderr: {result.stderr}" \
            )
            return True
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as e:
            client_logger.error(f"Failed to installed SafeProxy root CA cert: {e.stderr}", exc_info=True)
            return False            
