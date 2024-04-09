import unittest
from ctypes import *
from aes.aes import AES, encrypt, decrypt
import secrets

# Load the shared library
rijndael = CDLL("./rijndael.so")
# Define the function prototype
rijndael.aes_encrypt_block.argtypes = [POINTER(c_ubyte), POINTER(c_ubyte)]
rijndael.aes_encrypt_block.restype = POINTER(c_ubyte)
#Write above for decrypt as well
rijndael.aes_decrypt_block.argtypes = [POINTER(c_ubyte), POINTER(c_ubyte)]
rijndael.aes_decrypt_block.restype = POINTER(c_ubyte)


random_plainText = secrets.token_bytes(16)
random_key = secrets.token_bytes(16)

class TestBlock(unittest.TestCase):
    """
    A test case for the block encryption and decryption functionality.
    """

    def setUp(self):
        self.aes = AES(bytes(random_key))
        
    def test_encrypt(self):
        """
        Test the success scenario for block encryption.
        """
        py_ciphertext = self.aes.encrypt_block(random_plainText)        

        plain_text = (c_ubyte * len(random_plainText))(*random_plainText)
        key = (c_ubyte * len(random_key))(*random_key)

        # Call the C function
        c_ciphertext = rijndael.aes_encrypt_block(plain_text, key)               
        c_ciphertext_block_bytes = bytes(c_ciphertext[:16])

        self.assertEqual(py_ciphertext, c_ciphertext_block_bytes)

    def test_decrypt(self):
        """
        Test the success scenario for block encryption and decryption.
        """
        ciphertext = self.aes.encrypt_block(random_plainText)        
        py_plaintext = self.aes.decrypt_block(ciphertext)            
        plain_text = (c_ubyte * len(random_plainText))(*random_plainText)
        key = (c_ubyte * len(random_key))(*random_key)    

        # Call the C function
        c_ciphertext = rijndael.aes_encrypt_block(plain_text, key)             
        decrypted_block = rijndael.aes_decrypt_block(c_ciphertext, key)        
        c_ciphertext_block_bytes = bytes(decrypted_block[:16])
        
        self.assertEqual(py_plaintext, c_ciphertext_block_bytes)
        


def run():
    unittest.main()

if __name__ == '__main__':
    run()

