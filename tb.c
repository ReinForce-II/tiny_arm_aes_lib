#include "asimd_aes.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define TEST_SIZE (16 * 1024 * 1024)
#define VALIDATION_LEN 32

int main() {
    uint8_t key[16], iv[16];
    uint8_t round_keys[11 * 16];

    uint8_t *input, *output;
    input = (uint8_t *)malloc(TEST_SIZE);
    if (!input) {
        return -1;
    }
    output = (uint8_t *)malloc(TEST_SIZE);
    if (!output) {
        free(input);
        return -1;
    }

    memset(key, 0, sizeof(key));
    memset(iv, 0, sizeof(iv));
    memset(input, 0, sizeof(input));

    aes_key_schedule((uint32_t *)key, (uint32_t *)round_keys);
    uint8x16_t v_round_keys[11];
    for (uint32_t i = 0; i < 11; i++) {
        v_round_keys[i] = vld1q_u8(round_keys + i * 16);
    }
    uint64_t clock_0 = clock();
    asimd_aes_enc_ecb(v_round_keys, input, output, TEST_SIZE);
    uint64_t clock_1 = clock();
    asimd_aes_enc_cbc(v_round_keys, iv, input, output, TEST_SIZE);
    uint64_t clock_2 = clock();
    asimd_aes_enc_cfb8(v_round_keys, iv, input, output, TEST_SIZE);
    uint64_t clock_3 = clock();

    memset(input, 0, VALIDATION_LEN);
    asimd_aes_enc_ecb(v_round_keys, input, output, VALIDATION_LEN);
    uint8_t va_ecb[] = {0x66, 0xe9, 0x4b, 0xd4, 0xef, 0x8a, 0x2c, 0x3b,
                        0x88, 0x4c, 0xfa, 0x59, 0xca, 0x34, 0x2b, 0x2e,
                        0x66, 0xe9, 0x4b, 0xd4, 0xef, 0x8a, 0x2c, 0x3b,
                        0x88, 0x4c, 0xfa, 0x59, 0xca, 0x34, 0x2b, 0x2e};
    if (memcmp(va_ecb, output, VALIDATION_LEN)) {
        printf("ECB: FAIL\n");
    } else {
        printf("ECB: PASS\n");
    }
    memset(input, 0, VALIDATION_LEN);
    asimd_aes_enc_cbc(v_round_keys, iv, input, output, VALIDATION_LEN);
    uint8_t va_cbc[] = {0x66, 0xe9, 0x4b, 0xd4, 0xef, 0x8a, 0x2c, 0x3b,
                        0x88, 0x4c, 0xfa, 0x59, 0xca, 0x34, 0x2b, 0x2e,
                        0xf7, 0x95, 0xbd, 0x4a, 0x52, 0xe2, 0x9e, 0xd7,
                        0x13, 0xd3, 0x13, 0xfa, 0x20, 0xe9, 0x8d, 0xbc};
    if (memcmp(va_cbc, output, VALIDATION_LEN)) {
        printf("CBC: FAIL\n");
    } else {
        printf("CBC: PASS\n");
    }
    memset(input, 0, VALIDATION_LEN);
    asimd_aes_enc_cfb8(v_round_keys, iv, input, output, VALIDATION_LEN);
    uint8_t va_cfb8[] = {0x66, 0x16, 0xf9, 0x2e, 0x42, 0xa8, 0xf1, 0x1a,
                         0x91, 0x16, 0x68, 0x57, 0x8e, 0xc3, 0xaa, 0x0f,
                         0x93, 0x00, 0x4a, 0xab, 0x22, 0xb1, 0x2b, 0x26,
                         0xd1, 0x28, 0x96, 0x73, 0x1c, 0xd1, 0x12, 0xf6};
    if (memcmp(va_cfb8, output, VALIDATION_LEN)) {
        printf("CFB8: FAIL\n");
    } else {
        printf("CFB8: PASS\n");
    }

    free(input);
    free(output);

    printf(
        "ECB: %.3fMB/s\nCBC: %.3fMB/s\nCFB: %.3fMB/s\n",
        TEST_SIZE / 1024 / 1024 / ((clock_1 - clock_0) * 1.0 / CLOCKS_PER_SEC),
        TEST_SIZE / 1024 / 1024 / ((clock_2 - clock_1) * 1.0 / CLOCKS_PER_SEC),
        TEST_SIZE / 1024 / 1024 / ((clock_3 - clock_2) * 1.0 / CLOCKS_PER_SEC));

    return 0;
}
