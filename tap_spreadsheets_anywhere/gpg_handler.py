import gnupg
import tempfile
import os
import logging
from contextlib import contextmanager

LOGGER = logging.getLogger(__name__)


class GPGDecryptionError(Exception):
    def __init__(self, message="GPG decryption failed"):
        self.message = message
        super().__init__(self.message)


@contextmanager
def decrypt_gpg_file(encrypted_stream, gpg_home=None, passphrase=None, gpg_binary='gpg'):
    """
    Decrypt a GPG-encrypted file and return a file-like object with the decrypted content.
    
    Args:
        encrypted_stream: File-like object containing encrypted data
        gpg_home: Path to GPG home directory containing keyrings
        passphrase: Passphrase for the private key (if required)
        gpg_binary: Path to the GPG binary (default: 'gpg')
    
    Yields:
        File-like object containing decrypted data
    """
    gpg = gnupg.GPG(gnupghome=gpg_home, gpgbinary=gpg_binary)
    
    # Create a temporary file to store the decrypted data
    with tempfile.NamedTemporaryFile(mode='w+b', delete=False) as temp_file:
        temp_filename = temp_file.name
    
    try:
        # Read the encrypted data
        encrypted_data = encrypted_stream.read()
        
        # Decrypt the data
        LOGGER.info("Decrypting GPG file...")
        decrypted_data = gpg.decrypt(encrypted_data, passphrase=passphrase, output=temp_filename)
        
        if not decrypted_data.ok:
            error_msg = f"GPG decryption failed: {decrypted_data.status}"
            if decrypted_data.stderr:
                error_msg += f" - {decrypted_data.stderr}"
            raise GPGDecryptionError(error_msg)
        
        LOGGER.info("GPG decryption successful")
        
        # Open the decrypted file for reading
        with open(temp_filename, 'rb') as decrypted_file:
            yield decrypted_file
            
    finally:
        # Clean up the temporary file
        if os.path.exists(temp_filename):
            os.unlink(temp_filename)


def is_gpg_encrypted(uri):
    """
    Check if a file is likely GPG-encrypted based on its extension.
    
    Args:
        uri: File URI/path
        
    Returns:
        bool: True if file appears to be GPG-encrypted
    """
    lowered_uri = uri.lower()
    return lowered_uri.endswith('.gpg') or lowered_uri.endswith('.pgp') or lowered_uri.endswith('.asc')