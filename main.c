#include <stdio.h>
#include <stdlib.h>

#include "rijndael.h"

enum key_size
{
    SIZE_16 = 16,    
};

void print_128bit_block(unsigned char *block) {
  for (int i = 0; i < 4; i++) {
    for (int j = 0; j < 4; j++) {
      unsigned char value = BLOCK_ACCESS(block, i, j);
      // Print spaces before small numbers to ensure that everything is aligned
      // and looks nice
      if (value < 10) printf(" ");
      if (value < 100) printf(" ");
      printf("%d   ", value);
    }
    printf("\n");
  }
}

int main() {

  int expanded_key_size = 176;
  unsigned char expanded_key[expanded_key_size];
  enum key_size key_size = SIZE_16;
  unsigned char cipher_text[16] ;
  unsigned char decrypted_text[16];

  unsigned char plain_text[16] = {1, 2,  3,  4,  5,  6,  7,  8,
                                 9, 10, 11, 12, 13, 14, 15, 16};
  unsigned char key[16] = {50, 20, 46, 86, 67, 9, 70, 27,
                           75, 17, 51, 17, 4,  8, 6,  99};


  expand_key(expanded_key, key);

  printf("\nExpanded Key :\n");
  for (int i = 0; i < expanded_key_size; ++i)
  {
      printf("%2.2x%c", expanded_key[i], ((i + 1) % 16) ? ' ' : '\n');
  }

  unsigned char *ciphertext = aes_encrypt_block(plain_text, key);
  unsigned char *recovered_plaintext = aes_decrypt_block(ciphertext, key);

  printf("############ ORIGINAL PLAINTEXT ###########\n");
  print_128bit_block(plain_text);

  printf("\n\n################ CIPHERTEXT ###############\n");
  print_128bit_block(ciphertext);

  printf("\n\n########### RECOVERED PLAINTEXT ###########\n");
  print_128bit_block(recovered_plaintext);

  free(ciphertext);
  free(recovered_plaintext);

  return 0;
}
