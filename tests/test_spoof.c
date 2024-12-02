#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include "unity.h"
#include "../src/spoof.h"

void setUp(void) {
    // set stuff up here
}

void tearDown(void) {
    // clean stuff up here
}

void test_hex_prefix_match_valid_prefix(void) {
    unsigned char hash[SHA512_DIGEST_LENGTH] = {
        0x24, 0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67,
        // Fill rest with some data
    };
    
    TEST_ASSERT_TRUE(hex_prefix_match(hash, "24"));
    TEST_ASSERT_TRUE(hex_prefix_match(hash, "24ab"));
    TEST_ASSERT_FALSE(hex_prefix_match(hash, "25"));
}

void test_calculate_sha512(void) {
    const char* test_data = "Hello, World!";
    unsigned char expected_hash[SHA512_DIGEST_LENGTH];
    unsigned char calculated_hash[SHA512_DIGEST_LENGTH];
    
    // Use OpenSSL to calculate reference hash
    SHA512_CTX sha512;
    SHA512_Init(&sha512);
    SHA512_Update(&sha512, test_data, strlen(test_data));
    SHA512_Final(expected_hash, &sha512);
    
    // Test our implementation
    calculate_sha512((unsigned char*)test_data, strlen(test_data), calculated_hash);
    
    TEST_ASSERT_EQUAL_MEMORY(expected_hash, calculated_hash, SHA512_DIGEST_LENGTH);
}

void test_spoof_image_hash_basic(void) {
    // Prepare test image
    const char* input_image = "tests/test_data/sample.jpg";
    const char* output_image = "tests/test_data/spoofed.jpg";
    
    // Create a test image if it doesn't exist
    system("convert -size 100x100 xc:white tests/test_data/sample.jpg");
    
    // Attempt to spoof hash
    int result = spoof_image_hash(input_image, output_image, "24");
    
    TEST_ASSERT_TRUE(result);
    TEST_ASSERT_TRUE(access(output_image, F_OK) == 0);
    
    // Verify hash of output image
    char command[256];
    char hash_output[256];
    
    snprintf(command, sizeof(command), "sha512sum %s", output_image);
    FILE* pipe = popen(command, "r");
    TEST_ASSERT_NOT_NULL(pipe);
    
    if (fgets(hash_output, sizeof(hash_output), pipe) != NULL) {
        TEST_ASSERT_TRUE(strncmp(hash_output, "24", 2) == 0);
    }
    
    pclose(pipe);
    
    // Clean up
    unlink(input_image);
    unlink(output_image);
}

void test_invalid_input(void) {
    // Test with non-existent input file
    int result = spoof_image_hash("non_existent.jpg", "output.jpg", "24");
    TEST_ASSERT_FALSE(result);
    
    // Test with invalid prefix
    result = spoof_image_hash("tests/test_data/sample.jpg", "output.jpg", "24242424242424242424");
    TEST_ASSERT_FALSE(result);
}

int main(void) {
    UNITY_BEGIN();
    
    RUN_TEST(test_hex_prefix_match_valid_prefix);
    RUN_TEST(test_calculate_sha512);
    RUN_TEST(test_spoof_image_hash_basic);
    RUN_TEST(test_invalid_input);
    
    return UNITY_END();
}