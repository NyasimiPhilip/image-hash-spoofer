#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <openssl/sha.h>
#include <magick/MagickCore.h>
#include "spoof.h"

#define MAX_ATTEMPTS 10000000
#define MAX_PREFIX_LEN 16
#define MAX_HASH_STR_LEN 129

bool hex_prefix_match(const unsigned char* hash, const char* prefix) {
    // If prefix is empty, always match
    if (prefix == NULL || *prefix == '\0') {
        return true;
    }

    // Convert hash to hex string
    char hash_str[MAX_HASH_STR_LEN] = {0};
    for (int i = 0; i < SHA512_DIGEST_LENGTH; i++) {
        sprintf(hash_str + (i * 2), "%02x", hash[i]);
    }

    // Check if hash starts with the given prefix
    return strncmp(hash_str, prefix, strlen(prefix)) == 0;
}

void calculate_sha512(const unsigned char* data, size_t len, unsigned char* hash) {
    SHA512_CTX sha512;
    SHA512_Init(&sha512);
    SHA512_Update(&sha512, data, len);
    SHA512_Final(hash, &sha512);
}

typedef struct {
    unsigned char* data;
    size_t size;
    Image* image;
    ImageInfo* image_info;
} ImageContext;

static void free_image_context(ImageContext* ctx) {
    if (ctx->data) free(ctx->data);
    if (ctx->image) DestroyImage(ctx->image);
    if (ctx->image_info) DestroyImageInfo(ctx->image_info);
}

static bool write_image_to_memory(ImageContext* ctx) {
    size_t length;
    ctx->data = ImageToBlob(ctx->image_info, ctx->image, &length, &ctx->image_info->exception);
    ctx->size = length;
    return ctx->data != NULL;
}

bool spoof_image_hash(const char* input_path, const char* output_path, const char* prefix) {
    // Validate inputs
    if (!input_path || !output_path || !prefix) {
        fprintf(stderr, "Invalid input parameters\n");
        return false;
    }

    // Check prefix length
    if (strlen(prefix) > MAX_PREFIX_LEN) {
        fprintf(stderr, "Prefix too long. Max %d characters.\n", MAX_PREFIX_LEN);
        return false;
    }

    // Initialize ImageMagick
    MagickCoreGenesis(NULL, MagickFalse);

    ImageContext ctx = {0};
    ctx.image_info = CloneImageInfo(NULL);
    GetImageInfoFileName(ctx.image_info, input_path);

    // Read the original image
    ctx.image = ReadImage(ctx.image_info, &ctx.image_info->exception);
    if (!ctx.image) {
        fprintf(stderr, "Error reading input image\n");
        free_image_context(&ctx);
        MagickCoreTerminus();
        return false;
    }

    unsigned char hash[SHA512_DIGEST_LENGTH];
    unsigned char* pixel_data = (unsigned char*)ctx.image->pixels;
    size_t pixel_count = ctx.image->columns * ctx.image->rows * ctx.image->channels;

    // Attempt to find a hash match
    for (int attempt = 0; attempt < MAX_ATTEMPTS; attempt++) {
        // Introduce minimal noise with more sophisticated approach
        for (size_t i = 0; i < pixel_count; i++) {
            // Cyclic noise generation: -1, 0, 1 based on attempt
            int noise_pattern[3] = {-1, 0, 1};
            int noise = noise_pattern[attempt % 3];
            
            int new_val = pixel_data[i] + noise;
            // Clamp to valid pixel range
            pixel_data[i] = (new_val < 0) ? 0 : ((new_val > 255) ? 255 : new_val);
        }

        // Write modified image to memory
        if (!write_image_to_memory(&ctx)) {
            fprintf(stderr, "Memory writing failed\n");
            free_image_context(&ctx);
            MagickCoreTerminus();
            return false;
        }

        // Calculate SHA-512 hash
        calculate_sha512(ctx.data, ctx.size, hash);

        // Check if hash matches prefix
        if (hex_prefix_match(hash, prefix)) {
            // Write to output file
            FILE* out = fopen(output_path, "wb");
            if (!out) {
                fprintf(stderr, "Cannot open output file\n");
                free_image_context(&ctx);
                MagickCoreTerminus();
                return false;
            }
            fwrite(ctx.data, 1, ctx.size, out);
            fclose(out);

            printf("Success after %d attempts!\n", attempt + 1);
            free_image_context(&ctx);
            MagickCoreTerminus();
            return true;
        }

        // Free previous blob to prevent memory leaks
        if (ctx.data) {
            free(ctx.data);
            ctx.data = NULL;
        }
    }

    fprintf(stderr, "Failed to generate matching hash\n");
    free_image_context(&ctx);
    MagickCoreTerminus();
    return false;
}

int main(int argc, char* argv[]) {
    if (argc != 4) {
        fprintf(stderr, "Usage: %s <hex_prefix> <input_image> <output_image>\n", argv[0]);
        return 1;
    }

    const char* prefix = argv[1];
    const char* input_path = argv[2];
    const char* output_path = argv[3];

    // Remove '0x' prefix if present
    if (strncmp(prefix, "0x", 2) == 0) {
        prefix += 2;
    }

    return spoof_image_hash(input_path, output_path, prefix) ? 0 : 1;
}