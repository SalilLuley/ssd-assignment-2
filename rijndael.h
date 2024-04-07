/*
 * TODO: Add your name and student number here, along with
 *       a brief description of this code.
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
