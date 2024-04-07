#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "rijndael.h"

/**
 * Prints the hexadecimal representation of the given data.
 *
 * @param data The data to be printed.
 * @param length The length of the data.
 */
void print_hex(unsigned char *data, int length) {
  for (int i = 0; i < length; i++) {
    printf("%02x ", data[i]);
  }
  printf("\n");
}

/**
 * Test function for AES decryption of a single block.
 * Decrypts the given ciphertext using the provided key and compares the output
 * with the expected output.
 * @return void
 */
void test_aes_decrypt_block() {
  unsigned char ciphertext[16] = {0x4b, 0x95, 0x86, 0x93, 0xb4, 0xe9,
                                  0xc4, 0xeb, 0x92, 0xb3, 0xe8, 0x69,
                                  0xaf, 0x40, 0xe0, 0xce};
  unsigned char key[16] = {50, 20, 46, 86, 67, 9, 70, 27,
                           75, 17, 51, 17, 4,  8, 6,  99};
  unsigned char expected_output[16] = {1, 2,  3,  4,  5,  6,  7,  8,
                                       9, 10, 11, 12, 13, 14, 15, 16};

  unsigned char *output = aes_decrypt_block(ciphertext, key);

  if (memcmp(output, expected_output, 16) == 0) {
    printf("Test passed!\n");
  } else {
    printf("Test failed!\n");
  }

  free(output);
}

/**
 * @brief Entry point of the program.
 *
 * This function calls the test functions for AES encryption and decryption
 * blocks.
 *
 * @return 0 indicating successful execution of the program.
 */
int main() {
  test_aes_decrypt_block();
  return 0;
}