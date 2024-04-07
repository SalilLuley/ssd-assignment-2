/*
 * Salil Luley - D23124871
 * This file, rijndael.h, contains function declarations that are used for both
 * encryption and decryption processes. The file starts with an include guard,
 * #ifndef RIJNDAEL_H, #define RIJNDAEL_H, and #endif at the end. This is a
 * common idiom used in C and C++ to prevent the same header file from being
 * included more than once in a compilation unit. The #define
 * BLOCK_ACCESS(block, row, col) (block[(row * 4) + col]) and #define BLOCK_SIZE
 * 16 are macro definitions. The first one, BLOCK_ACCESS, is a utility macro to
 * access a specific element in a 4x4 block. The second one, BLOCK_SIZE, defines
 * the size of a block in AES, which is always 16 bytes. The function
 * declarations that follow are the main components of the AES algorithm:
 * aes_encrypt_block and aes_decrypt_block are the main entry points for
 * encrypting and decrypting a block of data, respectively. expand_key is used
 * to expand the encryption key to be used in the encryption and decryption
 * processes. aes_key_schedule_core is a part of the key expansion process.
 * get_s_box_value and get_rcon_value are used to retrieve values from the S-box
 * and Rcon arrays, respectively, which are part of the AES algorithm. aes_main
 * is the main function that performs the AES encryption. create_round_key,
 * add_round_key, sub_bytes, shift_rows, shift_row, and mix_columns are all
 * steps in the AES encryption process. invert_shift_rows, invert_sub_bytes, and
 * invert_mix_columns are the inverse operations of shift_rows, sub_bytes, and
 * mix_columns, respectively, and are used in the decryption process.
 */

#ifndef RIJNDAEL_H
#define RIJNDAEL_H

#define BLOCK_ACCESS(block, row, col) (block[(row * 4) + col])
#define BLOCK_SIZE 16

/*
 * These should be the main encrypt/decrypt functions (i.e. the main
 * entry point to the library for programmes hoping to use it to
 * encrypt or decrypt data)
 */
unsigned char *aes_encrypt_block(unsigned char *plain_text, unsigned char *key);
unsigned char *expand_key(unsigned char *expanded_key, unsigned char *key);
void aes_key_schedule_core(unsigned char *word, int iteration);
unsigned char get_s_box_value(unsigned char num);
unsigned char get_rcon_value(unsigned char num);

void aes_main(unsigned char *state, unsigned char *expanded_key,
              int nbr_rounds);
void create_round_key(unsigned char *expanded_key, unsigned char *roundKey);
void add_round_key(unsigned char *state, unsigned char *roundKey);
void sub_bytes(unsigned char *state);
void shift_rows(unsigned char *state);
void shift_row(unsigned char *state, unsigned char nbr);

void mix_columns(unsigned char *state);
void mix_column(unsigned char *column);

// Decrypt
void invert_shift_rows(unsigned char *state);
unsigned char *aes_decrypt_block(unsigned char *ciphertext, unsigned char *key);
void invert_shift_rows(unsigned char *state);
void invert_sub_bytes(unsigned char *state);
void invert_mix_columns(unsigned char *state);
void inv_mix_column(unsigned char *column);

#endif
