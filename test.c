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
 * Compares two arrays of unsigned characters and checks if they are equal.
 *
 * @param arr1 The first array to compare.
 * @param arr2 The second array to compare.
 * @param size The size of the arrays.
 * @return 1 if the arrays are equal, 0 otherwise.
 */
int compare_arrays(unsigned char *arr1, unsigned char *arr2, int size) {
  for (int i = 0; i < size; i++) {
    if (arr1[i] != arr2[i]) {
      return 0;  // Arrays are not equal
    }
  }
  return 1;  // Arrays are equal
}

/**
 * Function to test the AES encryption of a single block.
 *
 * This function initializes the plain_text, key, and expected_output arrays.
 * It then calls the aes_encrypt_block function to encrypt the plain_text using
 * the key. The output is compared with the expected_output array using memcmp.
 * If the output matches the expected_output, the test is considered passed.
 * Otherwise, the test is considered failed.
 *
 * @return void
 */
void test_aes_encrypt_block() {
  unsigned char plain_text[16] = {1, 2,  3,  4,  5,  6,  7,  8,
                                  9, 10, 11, 12, 13, 14, 15, 16};
  unsigned char key[16] = {50, 20, 46, 86, 67, 9, 70, 27,
                           75, 17, 51, 17, 4,  8, 6,  99};
  unsigned char expected_output[16] = {0x4b, 0x95, 0x86, 0x93, 0xb4, 0xe9,
                                       0xc4, 0xeb, 0x92, 0xb3, 0xe8, 0x69,
                                       0xaf, 0x40, 0xe0, 0xce};

  unsigned char *output = aes_encrypt_block(plain_text, key);

  if (memcmp(output, expected_output, 16) == 0) {
    printf("Test passed!\n");
  } else {
    printf("Test failed!\n");
  }

  free(output);
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
  test_aes_encrypt_block();
  return 0;
}