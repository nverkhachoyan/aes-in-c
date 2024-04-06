#include <stdio.h>
#include <stdlib.h>
#include "aes_constants.h"
#include "aes.h"

void print_aes_128_banner();
void print_chars(unsigned char* msg);
void print_cipher_hex(unsigned char *cipher);

int main(int argc, char *argv[]) {
    const char* key = "xRkNimuaRXk8v61g";
    unsigned char message[] = "I am big secret!"; // The 16 byte message that will be encrypted
    unsigned char* cipher = aec_encrypt(message, (unsigned char*)key);
    unsigned char* decrypted_message = aes_decrypt(cipher, (unsigned char*)key);

    // Printing a banner that says AES-128
    print_aes_128_banner();

    // Print original message
    printf("Original Message: ");
    print_chars(message);
    printf("\n");

    // Print cipher
    printf("\t[ cipher ] ");
    print_cipher_hex(cipher);
    printf("\n");

    // Print decrypted text
    printf("\t[ decrypted ] ");
    print_chars(decrypted_message);
    printf("\n");

    // Cleanup
    free(cipher);
    free(decrypted_message);
    return 0;
}

void print_aes_128_banner() {
    printf("    _     _____ ____        _ ____  ___\n");
    printf("   / \\  | ____/ ___|      / |___ \\( _ )\n");
    printf("  / _ \\ |  _| \\___ \\ _____| | __) / _ \\\n");
    printf(" / ___ \\| |___ ___\\ |_____| |/ __/ (_) |\n");
    printf("/_/   \\_\\_____|____/      |_|_____\\___/\n\n");
}

void print_chars(unsigned char* msg) {
    for (int i = 0; msg[i] != '\0'; i++) {
        printf("%c", msg[i]);
    }
}

void print_cipher_hex(unsigned char *cipher) {
    for (int i = 0; i < 16; i++) {
        printf("%02x", cipher[i]);
    }
}