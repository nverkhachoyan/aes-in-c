#ifndef AES_NVERK_H
#define AES_NVERK_H

void key_expansion(unsigned char* input_key, unsigned char* expanded_keys);
void sub_bytes(unsigned char* state);
void shift_rows(unsigned char* state);
void mix_columns(unsigned char* state);
void add_round_key(unsigned char* state, unsigned char* round_key);
void inv_sub_bytes(unsigned char* state);
void inv_shift_rows(unsigned char* state);
void inv_mix_columns(unsigned char* state);
unsigned char* aec_encrypt(unsigned char* message, unsigned char* key);
unsigned char* aes_decrypt(unsigned char* cipher, unsigned char* key);

#endif // AES_NVERK_H