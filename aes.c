#include <stdio.h>
#include <stdlib.h>

// Project specific header files
#include "aes.h"
#include "aes_constants.h"

void key_expansion(unsigned char* input_key, unsigned char* expanded_keys) {
    int bytes_generated = 16;
    int rconIteration = 0;
    unsigned char temp[4];

    for (int i = 0; i < 16; i++) {
        expanded_keys[i] = input_key[i];
    }

    while (bytes_generated < 176) {
        for (int i = 0; i < 4; i++) {
            temp[i] = expanded_keys[i + bytes_generated - 4];
        }

        if (bytes_generated % 16 == 0) {
            unsigned char a = temp[0];
            temp[0] = temp[1];
            temp[1] = temp[2];
            temp[2] = temp[3];
            temp[3] = a;

            for (int i = 0; i < 4; i++) {
                temp[i] = s_box[temp[i]];
            }

            temp[0] ^= Rcon[rconIteration++];
        }

        for (unsigned char a = 0; a < 4; a++) {
            expanded_keys[bytes_generated] = expanded_keys[bytes_generated - 16] ^ temp[a];
            bytes_generated++;
        }
    }
}

void sub_bytes(unsigned char* state) {
    for (int i = 0; i < 16; i++) {
        state[i] = s_box[state[i]];
    }
}

void shift_rows(unsigned char* state) {
    unsigned char temp[16];
    temp[0] = state[0];
    temp[1] = state[5];
    temp[2] = state[10];
    temp[3] = state[15];

    temp[4] = state[4];
    temp[5] = state[9];
    temp[6] = state[14];
    temp[7] = state[3];

    temp[8] = state[8];
    temp[9] = state[13];
    temp[10] = state[2];
    temp[11] = state[7];

    temp[12] = state[12];
    temp[13] = state[1];
    temp[14] = state[6];
    temp[15] = state[11];

    for (int i = 0; i < 16; i++) {
        state[i] = temp[i];
    }
}

void mix_columns(unsigned char* state) {
    unsigned char temp[16];

    temp[0] = (unsigned char)(mul2[state[0]] ^ mul3[state[1]] ^ state[2] ^ state[3]);
    temp[1] = (unsigned char)(state[0] ^ mul2[state[1]] ^ mul3[state[2]] ^ state[3]);
    temp[2] = (unsigned char)(state[0] ^ state[1] ^ mul2[state[2]] ^ mul3[state[3]]);
    temp[3] = (unsigned char)(mul3[state[0]] ^ state[1] ^ state[2] ^ mul2[state[3]]);

    temp[4] = (unsigned char)(mul2[state[4]] ^ mul3[state[5]] ^ state[6] ^ state[7]);
    temp[5] = (unsigned char)(state[4] ^ mul2[state[5]] ^ mul3[state[6]] ^ state[7]);
    temp[6] = (unsigned char)(state[4] ^ state[5] ^ mul2[state[6]] ^ mul3[state[7]]);
    temp[7] = (unsigned char)(mul3[state[4]] ^ state[5] ^ state[6] ^ mul2[state[7]]);

    temp[8] = (unsigned char)(mul2[state[8]] ^ mul3[state[9]] ^ state[10] ^ state[11]);
    temp[9] = (unsigned char)(state[8] ^ mul2[state[9]] ^ mul3[state[10]] ^ state[11]);
    temp[10] = (unsigned char)(state[8] ^ state[9] ^ mul2[state[10]] ^ mul3[state[11]]);
    temp[11] = (unsigned char)(mul3[state[8]] ^ state[9] ^ state[10] ^ mul2[state[11]]);

    temp[12] = (unsigned char)(mul2[state[12]] ^ mul3[state[13]] ^ state[14] ^ state[15]);
    temp[13] = (unsigned char)(state[12] ^ mul2[state[13]] ^ mul3[state[14]] ^ state[15]);
    temp[14] = (unsigned char)(state[12] ^ state[13] ^ mul2[state[14]] ^ mul3[state[15]]);
    temp[15] = (unsigned char)(mul3[state[12]] ^ state[13] ^ state[14] ^ mul2[state[15]]);

    for (int i = 0; i < 16; i++) {
        state[i] = temp[i];
    }
}

void add_round_key(unsigned char* state, unsigned char* round_key) {
    for (int i = 0; i < 16; i++) {
        state[i] ^= round_key[i];
    }
}

void inv_sub_bytes(unsigned char* state) {
    for (int i = 0; i < 16; i++) {
        state[i] = inv_s_box[state[i]];
    }
}

void inv_shift_rows(unsigned char* state) {
    unsigned char temp;

    temp = state[13];
    state[13] = state[9];
    state[9] = state[5];
    state[5] = state[1];
    state[1] = temp;

    temp = state[2];
    state[2] = state[10];
    state[10] = temp;
    temp = state[6];
    state[6] = state[14];
    state[14] = temp;

    temp = state[3];
    state[3] = state[7];
    state[7] = state[11];
    state[11] = state[15];
    state[15] = temp;
}

void inv_mix_columns(unsigned char* state) {
    unsigned char temp[16];
    for (int i = 0; i < 4; i++) {
        int j = i * 4;
        temp[j] = (unsigned char)(mul14[state[j]] ^ mul11[state[j + 1]] ^ mul13[state[j + 2]] ^ mul9[state[j + 3]]);
        temp[j + 1] = (unsigned char)(mul9[state[j]] ^ mul14[state[j + 1]] ^ mul11[state[j + 2]] ^ mul13[state[j + 3]]);
        temp[j + 2] = (unsigned char)(mul13[state[j]] ^ mul9[state[j + 1]] ^ mul14[state[j + 2]] ^ mul11[state[j + 3]]);
        temp[j + 3] = (unsigned char)(mul11[state[j]] ^ mul13[state[j + 1]] ^ mul9[state[j + 2]] ^ mul14[state[j + 3]]);
    }

    for (int i = 0; i < 16; i++) {
        state[i] = temp[i];
    }
}

unsigned char* aec_encrypt(unsigned char* message, unsigned char* key) {
    unsigned char* state = (unsigned char*)malloc(16 * sizeof(unsigned char));
    unsigned char expanded_keys[176];
    int num_of_rounds = 10;

    for (int i = 0; i < 16; i++) {
        state[i] = message[i];
    }

    

    key_expansion(key, expanded_keys);
    add_round_key(state, expanded_keys);

    for (int i = 1; i < num_of_rounds; i++) {
        sub_bytes(state);
        shift_rows(state);
        mix_columns(state);
        add_round_key(state, &expanded_keys[i * 16]);
    }

    sub_bytes(state);
    shift_rows(state);
    add_round_key(state, &expanded_keys[num_of_rounds * 16]);

    return state;
}

unsigned char* aes_decrypt(unsigned char* cipher, unsigned char* key) {
    unsigned char* state = (unsigned char*)malloc(17 * sizeof(unsigned char));
    unsigned char expanded_keys[176];
    int numOfRounds = 10;

    for (int i = 0; i < 16; i++) {
        state[i] = cipher[i];
    }

    key_expansion(key, expanded_keys);    
    add_round_key(state, &expanded_keys[numOfRounds * 16]);

    for (int round = numOfRounds - 1; round > 0; round--) {
        inv_shift_rows(state);
        inv_sub_bytes(state);
        add_round_key(state, &expanded_keys[round * 16]);
        inv_mix_columns(state); 
    }

    inv_shift_rows(state);
    inv_sub_bytes(state);
    add_round_key(state, expanded_keys);

    state[16] = '\0'; // just so it is null terminated

    return state;
}