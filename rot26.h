#include <stdint.h>

extern const char* rot26_free(const char* input);
extern const char* rot26_encrypt(const char* input);
extern const char* rot26_decrypt(const char* input);
extern const char* rot26_encrypt_rot13(const char* input);
extern const char* rot26_decrypt_rot13(const char* input);
extern const char* rot26_encrypt_any(const char* input, uint32_t amount);
extern const char* rot26_decrypt_any(const char* input, uint32_t amount);
