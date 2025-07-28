import gnupg
import tempfile
import os
import logging
from contextlib import contextmanager, nullcontext

LOGGER = logging.getLogger(__name__)


class GPGDecryptionError(Exception):
    def __init__(self, message="GPG decryption failed"):
        self.message = message
        super().__init__(self.message)


@contextmanager
def use_temp_key(gpg: gnupg.GPG, key_data, passphrase=None):
    """
    Decrypt a GPG-encrypted file and return a file-like object with the decrypted content.

    Args:
        gpg: GPG process wrapper
        key_data: String containing the private key data
        passphrase: Passphrase for the private key (if required)

    Yields:
        File-like object containing decrypted data
    """
    import_result: gnupg.ImportResult = gpg.import_keys(key_data, passphrase=passphrase)
    yield
    gpg.delete_keys(import_result.fingerprints, passphrase=passphrase)


@contextmanager
def decrypt_gpg_file(encrypted_stream, gpg_home=None, passphrase=None, gpg_binary="gpg", key_data=None):
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
    # Handle GPG home directory - create if it doesn't exist or use temp directory
    if gpg_home:
        if not os.path.exists(gpg_home):
            try:
                os.makedirs(gpg_home, mode=0o700, exist_ok=True)
                LOGGER.info(f"Created GPG home directory: {gpg_home}")
            except (OSError, PermissionError) as e:
                LOGGER.warning(f"Could not create GPG home directory {gpg_home}: {e}. Using temporary directory.")
                gpg_home = None

    # Use temporary directory if no gpg_home specified or creation failed
    use_temp_gpg_home = gpg_home is None
    temp_gpg_home = None

    if use_temp_gpg_home:
        temp_gpg_home = tempfile.mkdtemp(prefix="gnupg_")
        # Set secure permissions for GPG home directory
        os.chmod(temp_gpg_home, 0o700)
        actual_gpg_home = temp_gpg_home
        LOGGER.info(f"Using temporary GPG home directory: {actual_gpg_home}")
    else:
        actual_gpg_home = gpg_home
        LOGGER.info(f"Using GPG home directory: {actual_gpg_home}")

    # Use options to avoid lock file issues in containers
    gpg_options = ["--lock-never", "--no-default-keyring"]
    gpg = gnupg.GPG(gnupghome=actual_gpg_home, gpgbinary=gpg_binary, options=gpg_options)

    if key_data is not None:
        key_data_context = use_temp_key(gpg, key_data)
    else:
        key_data_context = nullcontext

    # Create a temporary file to store the decrypted data
    with tempfile.NamedTemporaryFile(mode="w+b", delete=False) as temp_file:
        temp_filename = temp_file.name

    try:
        # Read the encrypted data
        encrypted_data = encrypted_stream.read()

        # Decrypt the data
        LOGGER.info("Decrypting GPG file...")
        with key_data_context:
            decrypted_data = gpg.decrypt(encrypted_data, passphrase=passphrase, output=temp_filename)

        if not decrypted_data.ok:
            error_msg = f"GPG decryption failed: {decrypted_data.status}"
            if decrypted_data.stderr:
                error_msg += f" - {decrypted_data.stderr}"
            raise GPGDecryptionError(error_msg)

        LOGGER.info("GPG decryption successful")

        # Open the decrypted file for reading
        with open(temp_filename, "rb") as decrypted_file:
            yield decrypted_file

    finally:
        # Clean up the temporary file
        if os.path.exists(temp_filename):
            os.unlink(temp_filename)

        # Clean up temporary GPG home directory if we created one
        if use_temp_gpg_home and temp_gpg_home and os.path.exists(temp_gpg_home):
            import shutil

            try:
                shutil.rmtree(temp_gpg_home)
                LOGGER.info(f"Cleaned up temporary GPG home directory: {temp_gpg_home}")
            except Exception as e:
                LOGGER.warning(f"Could not clean up temporary GPG home directory {temp_gpg_home}: {e}")


def is_gpg_encrypted(uri):
    """
    Check if a file is likely GPG-encrypted based on its extension.

    Args:
        uri: File URI/path

    Returns:
        bool: True if file appears to be GPG-encrypted
    """
    lowered_uri = uri.lower()
    return lowered_uri.endswith(".gpg") or lowered_uri.endswith(".pgp") or lowered_uri.endswith(".asc")
