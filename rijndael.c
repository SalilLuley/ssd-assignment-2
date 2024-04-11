/**
 *  Salil Luley - D23124871
 * This is a library in C that that implements a 128 bit varient of AES.
 */

#include "rijndael.h"

#include <stdlib.h>

#include "stdio.h"

/**
 * @brief Enumeration representing different key sizes.
 *
 * This enumeration defines the possible key sizes for the Rijndael algorithm.
 * The key sizes are represented by the values SIZE_16
 * corresponding to key sizes of 16 bytes
 */
enum key_size { SIZE_16 = 16 };

/**
 * @brief The S-Box lookup table used in the Rijndael algorithm.
 *
 * The S-Box is a substitution table used in the Rijndael algorithm for byte
 * substitution during encryption and decryption. It is a 256-byte table that
 * maps each possible byte value to another byte value. This lookup table is
 * used in the Rijndael algorithm to perform the SubBytes transformation.
 *
 * @note The values in the S-Box table are in hexadecimal format.
 */
unsigned char s_box[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b,
    0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26,
    0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2,
    0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
    0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed,
    0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f,
    0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec,
    0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14,
    0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
    0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d,
    0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f,
    0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
    0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11,
    0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f,
    0xb0, 0x54, 0xbb, 0x16};

/**
 * @brief The Rijndael S-Box lookup table.
 *
 * This lookup table is used in the Rijndael algorithm for SubBytes
 * transformation. It maps each input byte to a corresponding output byte using
 * a predefined substitution pattern. The table is a 256-byte array where each
 * element represents the output byte for a specific input byte. The values in
 * the table are in hexadecimal format.
 *
 * @note This table is used for encryption and decryption operations in the
 * Rijndael algorithm.
 *
 * @see https://en.wikipedia.org/wiki/Rijndael_S-box
 */
unsigned char rs_box[256] = {
    // Values of the Rijndael S-Box lookup table
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e,
    0x81, 0xf3, 0xd7, 0xfb, 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87,
    0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb, 0x54, 0x7b, 0x94, 0x32,
    0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49,
    0x6d, 0x8b, 0xd1, 0x25, 0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16,
    0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92, 0x6c, 0x70, 0x48, 0x50,
    0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05,
    0xb8, 0xb3, 0x45, 0x06, 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02,
    0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b, 0x3a, 0x91, 0x11, 0x41,
    0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8,
    0x1c, 0x75, 0xdf, 0x6e, 0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89,
    0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b, 0xfc, 0x56, 0x3e, 0x4b,
    0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59,
    0x27, 0x80, 0xec, 0x5f, 0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d,
    0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef, 0xa0, 0xe0, 0x3b, 0x4d,
    0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63,
    0x55, 0x21, 0x0c, 0x7d};

/**
 * @brief The Rijndael round constant array.
 *
 * This array contains the round constants used in the Rijndael algorithm.
 * Each element represents a round constant value.
 *
 * @note The Rijndael algorithm uses these round constants during the key
 * expansion process.
 *
 * @see https://en.wikipedia.org/wiki/Rijndael_key_schedule#Round_constants
 */
unsigned char r_con[255] = {
    // Round constants values
    0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c,
    0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a,
    0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd,
    0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a,
    0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80,
    0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6,
    0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72,
    0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc,
    0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04, 0x08, 0x10,
    0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e,
    0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5,
    0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94,
    0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02,
    0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d,
    0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d,
    0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f,
    0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb,
    0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c,
    0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a,
    0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd,
    0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a,
    0x74, 0xe8, 0xcb};

/**
 * Rotates the elements in the given word array.
 *
 * @param word The array of unsigned characters to be rotated.
 */
void rotate(unsigned char *word) {
  unsigned char c;
  int i;

  c = word[0];
  for (i = 0; i < 3; i++) word[i] = word[i + 1];
  word[3] = c;
}

/**
 * Retrieves the value from the S-box lookup table based on the given input
 * number.
 *
 * @param num The input number for which the S-box value needs to be retrieved.
 * @return The value from the S-box lookup table corresponding to the input
 * number.
 */
unsigned char get_s_box_value(unsigned char num) { return s_box[num]; }

/**
 * Retrieves the Rcon value for the given number.
 *
 * @param num The number for which to retrieve the Rcon value.
 * @return The Rcon value corresponding to the given number.
 */
unsigned char get_rcon_value(unsigned char num) { return r_con[num]; }

/**
 * Performs the core key schedule operation for AES encryption.
 *
 * This function takes an input word and performs the following operations:
 * 1. Rotates the word.
 * 2. Applies S-box substitution on all 4 parts of the word.
 * 3. XORs the output of the r_con operation with the first part (leftmost) of
 * the word.
 *
 * @param word The input word to be processed.
 * @param iteration The current iteration of the key schedule.
 */
void aes_key_schedule_core(unsigned char *word, int iteration) {
  // Rotate the word
  rotate(word);

  // Apply S-box substitution on all 4 parts
  for (int i = 0; i < 4; ++i) {
    word[i] = get_s_box_value(word[i]);
  }

  // XOR the output of the r_con operation with i to the first part (leftmost)
  // only
  word[0] = word[0] ^ get_rcon_value(iteration);
}

/**
 * Creates a round key from an expanded key.
 *
 * This function takes an expanded key and generates a round key by rearranging
 * the bytes in a specific pattern. The round key is used in the Rijndael
 * encryption algorithm.
 *
 * @param expanded_key The expanded key from which the round key will be
 * created.
 * @param roundKey The output array where the round key will be stored.
 */
void create_round_key(unsigned char *expanded_key, unsigned char *roundKey) {
  int i, j;
  for (i = 0; i < 4; i++) {
    for (j = 0; j < 4; j++) roundKey[(i + (j * 4))] = expanded_key[(i * 4) + j];
  }
}

/**
 * XORs each byte of the state with the corresponding byte of the round key.
 *
 * @param state The state array containing the data to be modified.
 * @param roundKey The round key array used for XOR operation.
 */
void add_round_key(unsigned char *state, unsigned char *roundKey) {
  int i;
  for (i = 0; i < 16; i++) state[i] = state[i] ^ roundKey[i];
}

/**
 * Substitutes all the values in the state array with the corresponding values
 * from the SBox. Each value in the state array is used as an index to retrieve
 * the corresponding value from the SBox.
 *
 * @param state The state array to be substituted.
 */
void sub_bytes(unsigned char *state) {
  int i;
  for (i = 0; i < 16; i++) state[i] = get_s_box_value(state[i]);
}

/**
 * Shifts the rows of the state array to the left by a specified number of
 * positions.
 *
 * @param state The state array to be modified.
 * @param nbr The number of positions to shift the rows.
 */
void shift_row(unsigned char *state, unsigned char nbr) {
  int i, j;
  unsigned char tmp;
  // each iteration shifts the row to the left by 1
  for (i = 0; i < nbr; i++) {
    tmp = state[0];
    for (j = 0; j < 3; j++) state[j] = state[j + 1];
    state[3] = tmp;
  }
}

/**
 * Shifts the rows of the state matrix in the Rijndael encryption algorithm.
 *
 * @param state The state matrix to be modified.
 */
void shift_rows(unsigned char *state) {
  int i;
  for (i = 0; i < 4; i++) shift_row(state + i * 4, i);
}

/**
 * Multiplies two bytes using the Galois Field (GF) multiplication algorithm.
 *
 * @param a The first byte to be multiplied.
 * @param b The second byte to be multiplied.
 * @return The result of multiplying the two bytes using the GF multiplication
 * algorithm.
 */
unsigned char aes_galois_multiply(unsigned char a, unsigned char b) {
  unsigned char p = 0;
  unsigned char counter;
  unsigned char hi_bit_set;
  for (counter = 0; counter < 8; counter++) {
    if ((b & 1) == 1) p ^= a;
    hi_bit_set = (a & 0x80);
    a <<= 1;
    if (hi_bit_set == 0x80) a ^= 0x1b;
    b >>= 1;
  }
  return p;
}

/**
 * Mixes the columns of the AES state matrix using the Rijndael MixColumns
 * operation.
 *
 * @param column The column to be mixed, represented as an array of 4 unsigned
 * characters.
 */
void mix_column(unsigned char *column) {
  unsigned char cpy[4];
  int i;
  for (i = 0; i < 4; i++) {
    cpy[i] = column[i];
  }
  column[0] = aes_galois_multiply(cpy[0], 2) ^ aes_galois_multiply(cpy[3], 1) ^
              aes_galois_multiply(cpy[2], 1) ^ aes_galois_multiply(cpy[1], 3);

  column[1] = aes_galois_multiply(cpy[1], 2) ^ aes_galois_multiply(cpy[0], 1) ^
              aes_galois_multiply(cpy[3], 1) ^ aes_galois_multiply(cpy[2], 3);

  column[2] = aes_galois_multiply(cpy[2], 2) ^ aes_galois_multiply(cpy[1], 1) ^
              aes_galois_multiply(cpy[0], 1) ^ aes_galois_multiply(cpy[3], 3);

  column[3] = aes_galois_multiply(cpy[3], 2) ^ aes_galois_multiply(cpy[2], 1) ^
              aes_galois_multiply(cpy[1], 1) ^ aes_galois_multiply(cpy[0], 3);
}

/**
 * Mixes the columns of the state matrix using the MixColumns operation.
 *
 * @param state The state matrix to be modified.
 */
void mix_columns(unsigned char *state) {
  int i, j;
  unsigned char column[4];
  for (i = 0; i < 4; i++) {
    for (j = 0; j < 4; j++) {
      column[j] = state[(j * 4) + i];
    }
    mix_column(column);
    for (j = 0; j < 4; j++) {
      state[(j * 4) + i] = column[j];
    }
  }
}
/**
 * Performs the AES encryption algorithm on the given state using the expanded
 * key.
 *
 * @param state The state array to be encrypted.
 * @param expanded_key The expanded key array.
 * @param nbr_rounds The number of rounds to be performed.
 */
void aes_main(unsigned char *state, unsigned char *expanded_key,
              int nbr_rounds) {
  int i = 0;
  unsigned char roundKey[16];
  create_round_key(expanded_key, roundKey);
  add_round_key(state, roundKey);
  for (i = 1; i < nbr_rounds; i++) {
    create_round_key(expanded_key + 16 * i, roundKey);
    sub_bytes(state);
    shift_rows(state);
    mix_columns(state);
    add_round_key(state, roundKey);
  }
  create_round_key(expanded_key + 16 * nbr_rounds, roundKey);
  sub_bytes(state);
  shift_rows(state);
  add_round_key(state, roundKey);
}

/**
 * This function should expand the round key. Given an input,
 * which is a single 128-bit key, it should return a 176-byte
 * vector, containing the 11 round keys one after the ot
 * Expands the given key to generate an expanded key.
 *
 * @param expanded_key The expanded key to be generated.
 * @param key The input key.
 * @return The expanded key.
 */
unsigned char *expand_key(unsigned char *expanded_key, unsigned char *key) {
  int expanded_key_size = 176;
  enum key_size size = SIZE_16;
  int currentSize = 0;
  int rconIteration = 1;
  int i;
  unsigned char t[4] = {0};

  for (i = 0; i < size; i++) expanded_key[i] = key[i];
  currentSize += size;

  while (currentSize < expanded_key_size) {
    for (i = 0; i < 4; i++) {
      t[i] = expanded_key[(currentSize - 4) + i];
    }

    if (currentSize % size == 0) {
      aes_key_schedule_core(t, rconIteration++);
    }

    for (i = 0; i < 4; i++) {
      expanded_key[currentSize] = expanded_key[currentSize - size] ^ t[i];
      currentSize++;
    }
  }
  return expanded_key;
}

/**
 * Encrypts a single block of plain_text using the AES algorithm.
 *
 * @param plain_text The plain_text block to be encrypted.
 * @param key The encryption key.
 * @return The encrypted block.
 */
unsigned char *aes_encrypt_block(unsigned char *plain_text,
                                 unsigned char *key) {
  unsigned char *output =
      (unsigned char *)malloc(sizeof(unsigned char) * BLOCK_SIZE);

  int nbr_rounds = 10;

  int expanded_key_size = (16 * (nbr_rounds + 1));

  unsigned char *expanded_key =
      (unsigned char *)malloc(expanded_key_size * sizeof(unsigned char));
  unsigned char block[16];
  int i, j;

  for (i = 0; i < 4; i++) {
    for (j = 0; j < 4; j++) block[(i + (j * 4))] = plain_text[(i * 4) + j];
  }
  expand_key(expanded_key, key);
  aes_main(block, expanded_key, nbr_rounds);

  for (i = 0; i < 4; i++) {
    for (j = 0; j < 4; j++) output[(i * 4) + j] = block[(i + (j * 4))];
  }
  free(expanded_key);
  expanded_key = NULL;

  return output;
}

// Decrypt

/**
 * Performs the inverse mix column operation on a given column.
 *
 * @param column The column to perform the inverse mix column operation on.
 */
void inv_mix_column(unsigned char *column) {
  unsigned char cpy[4];
  int i;
  for (i = 0; i < 4; i++) {
    cpy[i] = column[i];
  }
  column[0] = aes_galois_multiply(cpy[0], 14) ^ aes_galois_multiply(cpy[3], 9) ^
              aes_galois_multiply(cpy[2], 13) ^ aes_galois_multiply(cpy[1], 11);
  column[1] = aes_galois_multiply(cpy[1], 14) ^ aes_galois_multiply(cpy[0], 9) ^
              aes_galois_multiply(cpy[3], 13) ^ aes_galois_multiply(cpy[2], 11);
  column[2] = aes_galois_multiply(cpy[2], 14) ^ aes_galois_multiply(cpy[1], 9) ^
              aes_galois_multiply(cpy[0], 13) ^ aes_galois_multiply(cpy[3], 11);
  column[3] = aes_galois_multiply(cpy[3], 14) ^ aes_galois_multiply(cpy[2], 9) ^
              aes_galois_multiply(cpy[1], 13) ^ aes_galois_multiply(cpy[0], 11);
}

/**
 * Inverts the MixColumns operation on the given state array.
 *
 * @param state The state array to perform the operation on.
 */
void invert_mix_columns(unsigned char *state) {
  int i, j;
  unsigned char column[4];

  // iterate over the 4 columns
  for (i = 0; i < 4; i++) {
    // construct one column by iterating over the 4 rows
    for (j = 0; j < 4; j++) {
      column[j] = state[(j * 4) + i];
    }

    // apply the inv_mix_column on one column
    inv_mix_column(column);

    // put the values back into the state
    for (j = 0; j < 4; j++) {
      state[(j * 4) + i] = column[j];
    }
  }
}

/**
 * Retrieves the inverse of a given number from the Rijndael S-Box.
 *
 * @param num The number to be inverted.
 * @return The inverse of the given number from the Rijndael S-Box.
 */
unsigned char get_s_box_invert(unsigned char num) { return rs_box[num]; }

/**
 * Inverts the SubBytes operation on the given state array.
 *
 * This function applies the inverse S-box substitution to each byte in the
 * state array. The inverse S-box substitution is performed by calling the
 * `get_s_box_invert` function.
 *
 * @param state The state array to be modified.
 */
void invert_sub_bytes(unsigned char *state) {
  int i;
  for (i = 0; i < 16; i++) state[i] = get_s_box_invert(state[i]);
}

/**
 * Shifts the rows of the state matrix to the right by a specified number of
 * positions.
 *
 * @param state The state matrix to be shifted.
 * @param nbr The number of positions to shift the rows.
 */
void inv_shift_row(unsigned char *state, unsigned char nbr) {
  int i, j;
  unsigned char tmp;
  for (i = 0; i < nbr; i++) {
    tmp = state[3];
    for (j = 3; j > 0; j--) state[j] = state[j - 1];
    state[0] = tmp;
  }
}

/**
 * Inverts the shift rows operation on the given state array.
 *
 * @param state The state array to perform the operation on.
 */
void invert_shift_rows(unsigned char *state) {
  int i;
  for (i = 0; i < 4; i++) inv_shift_row(state + i * 4, i);
}

/**
 * Performs the inverse AES encryption algorithm on the given state using the
 * provided expanded key.
 *
 * @param state The state array to be decrypted.
 * @param expanded_key The expanded key array used for decryption.
 * @param nbr_rounds The number of rounds to be performed during decryption.
 */
void aes_inv_main(unsigned char *state, unsigned char *expanded_key,
                  int nbr_rounds) {
  int i = 0;
  unsigned char roundKey[16];
  create_round_key(expanded_key + 16 * nbr_rounds, roundKey);
  add_round_key(state, roundKey);
  for (i = nbr_rounds - 1; i > 0; i--) {
    create_round_key(expanded_key + 16 * i, roundKey);
    invert_shift_rows(state);
    invert_sub_bytes(state);
    add_round_key(state, roundKey);
    invert_mix_columns(state);
  }
  create_round_key(expanded_key, roundKey);
  invert_shift_rows(state);
  invert_sub_bytes(state);
  add_round_key(state, roundKey);
}

/**
 * Decrypts a single AES block using the Rijndael algorithm.
 *
 * @param ciphertext The input ciphertext block to be decrypted.
 * @param key The encryption key used for decryption.
 * @return The decrypted plain_text block.
 */
unsigned char *aes_decrypt_block(unsigned char *ciphertext,
                                 unsigned char *key) {
  int nbr_rounds = 10;
  int expanded_key_size = (16 * (nbr_rounds + 1));
  unsigned char block[16];
  int i, j;
  unsigned char *expanded_key =
      (unsigned char *)malloc(expanded_key_size * sizeof(unsigned char));

  unsigned char *output =
      (unsigned char *)malloc(sizeof(unsigned char) * BLOCK_SIZE);
  for (i = 0; i < 4; i++) {
    for (j = 0; j < 4; j++) block[(i + (j * 4))] = ciphertext[(i * 4) + j];
  }
  expand_key(expanded_key, key);
  aes_inv_main(block, expanded_key, nbr_rounds);

  for (i = 0; i < 4; i++) {
    for (j = 0; j < 4; j++) output[(i * 4) + j] = block[(i + (j * 4))];
  }

  free(expanded_key);
  expanded_key = NULL;
  return output;
}