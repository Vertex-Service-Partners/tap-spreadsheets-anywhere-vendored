import unittest
import tempfile
import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

import tap_spreadsheets_anywhere.gpg_handler as gpg_handler
import tap_spreadsheets_anywhere.format_handler as format_handler
from unittest.mock import patch, MagicMock
import io


class TestGPGDecryption(unittest.TestCase):
    
    def test_is_gpg_encrypted(self):
        """Test GPG file detection based on extension"""
        self.assertTrue(gpg_handler.is_gpg_encrypted('file.csv.gpg'))
        self.assertTrue(gpg_handler.is_gpg_encrypted('FILE.CSV.GPG'))
        self.assertTrue(gpg_handler.is_gpg_encrypted('file.pgp'))
        self.assertTrue(gpg_handler.is_gpg_encrypted('file.asc'))
        self.assertFalse(gpg_handler.is_gpg_encrypted('file.csv'))
        self.assertFalse(gpg_handler.is_gpg_encrypted('file.xlsx'))
    
    @patch('gnupg.GPG')
    def test_decrypt_gpg_file_success(self, mock_gpg_class):
        """Test successful GPG decryption"""
        # Mock GPG instance
        mock_gpg = MagicMock()
        mock_gpg_class.return_value = mock_gpg
        
        # Mock decrypt result
        mock_decrypt_result = MagicMock()
        mock_decrypt_result.ok = True
        mock_decrypt_result.data = b'decrypted content'
        mock_gpg.decrypt.return_value = mock_decrypt_result
        
        # Create a mock encrypted stream
        encrypted_stream = io.BytesIO(b'encrypted content')
        
        # Test decryption
        with gpg_handler.decrypt_gpg_file(encrypted_stream, gpg_home='/tmp/gpghome', passphrase='secret') as decrypted:
            # The decrypted file should be readable
            self.assertIsNotNone(decrypted)
            # In the real implementation, we write to a temp file, so we can't directly check content
            # but we can verify the mock was called correctly
            
        mock_gpg.decrypt.assert_called_once()
        
    @patch('gnupg.GPG')
    def test_decrypt_gpg_file_failure(self, mock_gpg_class):
        """Test failed GPG decryption"""
        # Mock GPG instance
        mock_gpg = MagicMock()
        mock_gpg_class.return_value = mock_gpg
        
        # Mock failed decrypt result
        mock_decrypt_result = MagicMock()
        mock_decrypt_result.ok = False
        mock_decrypt_result.status = 'decryption failed'
        mock_decrypt_result.stderr = 'no secret key'
        mock_gpg.decrypt.return_value = mock_decrypt_result
        
        # Create a mock encrypted stream
        encrypted_stream = io.BytesIO(b'encrypted content')
        
        # Test that decryption failure raises an exception
        with self.assertRaises(gpg_handler.GPGDecryptionError) as context:
            with gpg_handler.decrypt_gpg_file(encrypted_stream):
                pass
        
        self.assertIn('decryption failed', str(context.exception))
        self.assertIn('no secret key', str(context.exception))
    
    @patch('tap_spreadsheets_anywhere.format_handler.get_streamreader')
    @patch('tap_spreadsheets_anywhere.gpg_handler.decrypt_gpg_file')
    def test_get_row_iterator_with_gpg(self, mock_decrypt, mock_get_streamreader):
        """Test that get_row_iterator handles GPG files correctly"""
        # Set up test data
        table_spec = {
            'name': 'test_table',
            'path': 's3://bucket',
            'pattern': 'test.csv.gpg',
            'format': 'detect',
            'gpg': {
                'home': '/tmp/gpghome',
                'passphrase': 'secret'
            }
        }
        
        # Mock encrypted stream
        mock_encrypted_stream = io.BytesIO(b'encrypted content')
        mock_get_streamreader.return_value = mock_encrypted_stream
        
        # Create a mock file object with a name attribute
        mock_decrypted_file = MagicMock()
        mock_decrypted_file.name = '/tmp/decrypted_file'
        mock_decrypted_file.read.return_value = b'header1,header2\nvalue1,value2\n'
        
        # Set up the context manager mock
        mock_decrypt.return_value.__enter__.return_value = mock_decrypted_file
        mock_decrypt.return_value.__exit__.return_value = None
        
        # We need to mock the recursive call to get_row_iterator
        # Since it will be called with the file:// URI
        with patch('tap_spreadsheets_anywhere.csv_handler.get_row_iterator') as mock_csv_handler:
            mock_csv_handler.return_value = iter([{'header1': 'value1', 'header2': 'value2'}])
            
            # Call get_row_iterator
            iterator = format_handler.get_row_iterator(table_spec, 's3://bucket/test.csv.gpg')
            
            # Verify it returns an iterator
            self.assertIsNotNone(iterator)
            
            # Verify GPG decryption was called
            mock_decrypt.assert_called_once_with(
                mock_encrypted_stream,
                gpg_home='/tmp/gpghome',
                passphrase='secret',
                gpg_binary='gpg'
            )


if __name__ == '__main__':
    unittest.main()