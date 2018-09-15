#include "asimd_aes.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define TEST_SIZE (16 * 1024 * 1024)

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

    free(input);
    free(output);

    printf(
        "ECB: %.3fMB/s\nCBC: %.3fMB/s\nCFB: %.3fMB/s\n",
        TEST_SIZE / 1024 / 1024 / ((clock_1 - clock_0) * 1.0 / CLOCKS_PER_SEC),
        TEST_SIZE / 1024 / 1024 / ((clock_2 - clock_1) * 1.0 / CLOCKS_PER_SEC),
        TEST_SIZE / 1024 / 1024 / ((clock_3 - clock_2) * 1.0 / CLOCKS_PER_SEC));

    return 0;
}
