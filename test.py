import unittest
from ctypes import *
from aes.aes import AES, encrypt, decrypt
# Load the shared library
rijndael = CDLL("./rijndael.so")
# Define the function prototype
rijndael.aes_encrypt_block.argtypes = [POINTER(c_ubyte), POINTER(c_ubyte)]
rijndael.aes_encrypt_block.restype = POINTER(c_ubyte)
#Write above for decrypt as well
rijndael.aes_decrypt_block.argtypes = [POINTER(c_ubyte), POINTER(c_ubyte)]
rijndael.aes_decrypt_block.restype = POINTER(c_ubyte)



class TestBlock(unittest.TestCase):
    def setUp(self):
        self.aes = AES(bytes([50, 20, 46, 86, 67, 9, 70, 27,
         75, 17, 51, 17, 4,  8, 6,  99]))
        
    def test_success(self):
        py_plain_text = bytes([1, 2,  3,  4,  5,  6,  7,  8,
                                  9, 10, 11, 12, 13, 14, 15, 16])
        py_ciphertext = self.aes.encrypt_block(py_plain_text)
        print("Python encrypted block in hex:")
        for i in range(16):
            print(hex(py_ciphertext[i]), end=" ")

        #C
        c_plain_text_bytes = bytes([1, 2,  3,  4,  5,  6,  7,  8,
                    9, 10, 11, 12, 13, 14, 15, 16])
        c_key_bytes = bytes([50, 20, 46, 86, 67, 9, 70, 27,
                75, 17, 51, 17, 4,  8, 6,  99])

        plain_text = (c_ubyte * len(c_plain_text_bytes))(*c_plain_text_bytes)
        key = (c_ubyte * len(c_key_bytes))(*c_key_bytes)
        print("\n")        

        # # Call the C function
        c_ciphertext = rijndael.aes_encrypt_block(plain_text, key)
        print("C encrypted block in hex:")
        for i in range(16):
            print(hex(c_ciphertext[i]), end=" ")            
        print("\n")
        
        c_ciphertext_block_bytes = bytes(c_ciphertext[:16])
        self.assertEqual(py_ciphertext, c_ciphertext_block_bytes)

    def test_success(self):
        

        ciphertext = [0x4b, 0x95, 0x86, 0x93, 0xb4, 0xe9, 0xc4, 0xeb, 0x92, 0xb3, 0xe8, 0x69, 0xaf, 0x40, 0xe0, 0xce]        
        py_plaintext = self.aes.decrypt_block(ciphertext)

        for i in range(16):
            print(hex(py_plaintext[i]), end=" ")


        c_plain_text_bytes = bytes([1, 2,  3,  4,  5,  6,  7,  8,
                    9, 10, 11, 12, 13, 14, 15, 16])
        c_key_bytes = bytes([50, 20, 46, 86, 67, 9, 70, 27,
                75, 17, 51, 17, 4,  8, 6,  99])

        plain_text = (c_ubyte * len(c_plain_text_bytes))(*c_plain_text_bytes)
        key = (c_ubyte * len(c_key_bytes))(*c_key_bytes)
        print("\n")        

        # Call the C function
        c_ciphertext = rijndael.aes_encrypt_block(plain_text, key)
        
        print("C encrypted block in hex:")
        for i in range(16):
            print(hex(c_ciphertext[i]), end=" ")            
        print("\n")        

        decrypted_block = rijndael.aes_decrypt_block(c_ciphertext, key)

        print("C decrypted block in hex:",decrypted_block)
        for i in range(16):
            print(hex(decrypted_block[i]), end=" ")            
        print("\n")

        c_ciphertext_block_bytes = bytes(decrypted_block[:16])
        self.assertEqual(py_plaintext, c_ciphertext_block_bytes)
        


def run():
    unittest.main()

if __name__ == '__main__':
    run()

