#ifndef MAIN_HPP
#define MAIN_HPP

#include <stdint.h>
#include <sys/types.h>

typedef struct
{
	uint32_t modulus[64];			// 256
	uint32_t reserved1[64];			// 256
	uint32_t publicExponent;		// 4
	uint32_t montgomeryParams[64];	// 256
	uint32_t reserved2[64];			// 256
	uint32_t montgomeryCoefficient;	// 4
	uint32_t modulusSize;			// 4
} rsa_key_t;

typedef struct __attribute__((packed)) // sizeof=0x100
{
	uint16_t magic;				// 0 v
	uint16_t block_size;		// 2 v
	uint16_t encrypted;			// 4 v
	uint16_t unknown1;			// 6
	uint32_t unknown2;			// 8
	uint32_t sig1;				// 12 v
	uint32_t first_offset;		// 16
	uint32_t data_offset;		// 20 v
	uint32_t encrypted_size;	// 24
	uint32_t payload_size;		// 28
	uint8_t hash[32];			// 32
	uint8_t key[32];			// 64
	uint8_t iv[16];				// 96
	uint8_t padding1[24];		// 112
	char cipher[7];				// 136
	char date[20];				// 143
	uint8_t padding2[69];		// 163
	uint8_t padding3[16];		// 232
	uint16_t unknown3;			// 248
	uint16_t unknown4;			// 250 v
	uint32_t sig2;				// 252 v
} AmlogicCryptoHeader_t;		// 256

bool verify_signature_and_hash(uint32_t *key, uint8_t *encrypted_signature, uint8_t *expected_hash);
int64_t decrypt_block(uint32_t *key, uint8_t *data_ptr, uint8_t *buffer);
int64_t modular_multiply(unsigned int *modulus_data, uint8_t *a2, uint8_t *operand1_ptr, uint8_t *operand2);
int64_t subtract_modulus(int64_t modulus_ptr, int64_t result_ptr);
int64_t validate_image_header(uint8_t *image_bufer, rsa_key_t *key);

#endif // MAIN_HPP
