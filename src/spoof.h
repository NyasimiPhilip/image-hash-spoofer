#ifndef SPOOF_H
#define SPOOF_H

#include <stdbool.h>
#include <openssl/sha.h>

// Expose functions for testing
bool hex_prefix_match(const unsigned char* hash, const char* prefix);
void calculate_sha512(const unsigned char* data, size_t len, unsigned char* hash);
bool spoof_image_hash(const char* input_path, const char* output_path, const char* prefix);

#endif // SPOOF_H