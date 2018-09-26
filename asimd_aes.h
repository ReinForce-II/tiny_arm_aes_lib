
#if !defined(__ASIMD_AES_H__)
#define __ASIMD_AES_H__

#include <arm_neon.h>
#include <stdint.h>

void aes_key_schedule(uint32_t *key, uint32_t *rdkey);
void asimd_aes_enc_ecb(const uint8x16_t rdkeys[], const uint8_t input[],
                       uint8_t output[], uint32_t length);
void asimd_aes_enc_cbc(const uint8x16_t rdkeys[], const uint8_t iv[],
                       const uint8_t input[], uint8_t output[],
                       uint32_t length);
void asimd_aes_enc_cfb(const uint8x16_t rdkeys[], const uint8_t iv[],
                       const uint8_t input[], uint8_t output[],
                       uint32_t length);
void asimd_aes_enc_cfb8(const uint8x16_t rdkeys[], const uint8_t iv[],
                        const uint8_t input[], uint8_t output[],
                        uint32_t length);

#endif // __ASIMD_AES_H__
