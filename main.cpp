#include <stdio.h>
#include <stdlib.h>
#include <math.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/err.h>

#include <string.h>
#include <stdbool.h>

#include "main.hpp"

#define LOWORD(l) ((WORD)(((DWORD_PTR)(l)) & 0xffff))

int openssl_aes_decrypt(const unsigned char *ciphertext, int ciphertext_len, const unsigned char *key, const unsigned char *iv, unsigned char *plaintext)
{
	EVP_CIPHER_CTX *ctx = NULL;
	int len = 0;
	int plaintext_len = 0;
	int ret = -1;

	if(!(ctx = EVP_CIPHER_CTX_new()))
	{
		fprintf(stderr, "Error: EVP_CIPHER_CTX_new failed\n");
		goto cleanup;
	}

	if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, NULL, NULL))
	{
		fprintf(stderr, "Error: EVP_DecryptInit_ex failed\n");
		goto cleanup;
	}

	if(1 != EVP_CIPHER_CTX_set_padding(ctx, 0))
	{
		fprintf(stderr, "Error: EVP_CIPHER_CTX_set_padding failed\n");
		goto cleanup;
	}

	if(1 != EVP_CIPHER_CTX_set_key_length(ctx, 32))
	{
		fprintf(stderr, "Error: EVP_CIPHER_CTX_set_key_length failed\n");
		goto cleanup;
	}

	if(1 != EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv))
	{
		fprintf(stderr, "Error: EVP_DecryptInit_ex (key/iv) failed\n");
		goto cleanup;
	}

	if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
	{
		fprintf(stderr, "Error: EVP_DecryptUpdate failed\n");
		goto cleanup;
	}
	plaintext_len = len;

	if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
	{
		fprintf(stderr, "Error: EVP_DecryptFinal_ex failed\n");
		unsigned long err = ERR_get_error();
		char err_msg[256];
		ERR_error_string_n(err, err_msg, sizeof(err_msg));
		fprintf(stderr, "OpenSSL error: %s\n", err_msg);
		goto cleanup;
	}
	plaintext_len += len;
	ret = plaintext_len;

cleanup:

	if(ctx)
	{
		EVP_CIPHER_CTX_free(ctx);
	}

	return ret;
}

const uint8_t SIGNATURE_STRUCTURE_TEMPLATE[] =
{
	0x30, 0x31,
	0x30, 0x0D,
	0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
	0x05, 0x00,
	0x04, 0x20
};

uint8_t *key_51C6778;
uint8_t *key_51C6340;

void compute_hash(const uint8_t *data, uint32_t size, uint8_t *hash)
{
	EVP_Digest(data, size, hash, NULL, EVP_sha256(), NULL);
}

void hex_print(const void *data, uint32_t len)
{
	uint32_t b;
	for(b = 0; b < len; ++b)
	{
		fprintf(stdout, "%02X ", (unsigned int)( ((uint8_t *)data)[b] ));
	}
	fprintf(stdout, "\n");
}

int64_t subtract_modulus(int64_t modulus_ptr, int64_t result_ptr)
{
	int64_t index;
	int64_t borrow;
	int64_t temp;

	index = 0LL;
	borrow = 0LL;
	while ( *(uint32_t *)(modulus_ptr + 1032) > (unsigned int)index )
	{
		temp = *(unsigned int *)(result_ptr + 4 * index) + borrow - *(unsigned int *)(modulus_ptr + 4 * index);
		*(uint32_t *)(result_ptr + 4 * index) = temp;
		borrow = temp >> 32;
		++index;
	}
	return modulus_ptr;
}

RSA *create_rsa_from_rsa_key_t(rsa_key_t *key)
{
	RSA *rsa = RSA_new();
	if (!rsa)
	{
		fprintf(stderr, "Ошибка: не удалось создать RSA объект.\n");
		return NULL;
	}

	BIGNUM *n = BN_new();
	BIGNUM *e = BN_new();

	if (!n || !e)
	{
		fprintf(stderr, "Ошибка: не удалось создать BIGNUM.\n");
		RSA_free(rsa);
		BN_free(n);
		BN_free(e);
		return NULL;
	}

	unsigned char modulus_bytes[256]; // 64 * 4 байта = 256 байт
	for (int i = 0; i < 64; ++i)
	{
		modulus_bytes[252 - i * 4] = (key->modulus[i] >> 24) & 0xFF;
		modulus_bytes[253 - i * 4] = (key->modulus[i] >> 16) & 0xFF;
		modulus_bytes[254 - i * 4] = (key->modulus[i] >> 8) & 0xFF;
		modulus_bytes[255 - i * 4] = key->modulus[i] & 0xFF;
	}

	BN_bin2bn(modulus_bytes, 256, n);

	BN_set_word(e, key->publicExponent);

	if (RSA_set0_key(rsa, n, e, NULL) != 1)
	{
		fprintf(stderr, "Ошибка: не удалось установить ключ в RSA объект.\n");
		RSA_free(rsa);
		BN_free(n);
		BN_free(e);
		return NULL;
	}

	return rsa;
}

void print_amlogic_crypto_header(const AmlogicCryptoHeader_t *header, const char *title)
{
	printf("----- %s -----\n", title);
	printf("magic: 0x%04X\n", header->magic);
	printf("block_size: %u\n", header->block_size);
	printf("encrypted: %u\n", header->encrypted);
	printf("unknown1: %u\n", header->unknown1);
	printf("unknown2: %u\n", header->unknown2);
	printf("sig1: 0x%08X\n", header->sig1);
	printf("first_offset: %u\n", header->first_offset);
	printf("data_offset: %u\n", header->data_offset);
	printf("encrypted_size: %u\n", header->encrypted_size);
	printf("payload_size: %u\n", header->payload_size);
	printf("hash: ");
	hex_print(header->hash, 32);
	printf("key: ");
	hex_print(header->key, 32);
	printf("iv: ");
	hex_print(header->iv, 16);
	printf("cipher: %.*s\n", (int)sizeof(header->cipher), header->cipher);
	printf("date: %.*s\n", (int)sizeof(header->date), header->date);
	printf("unknown3: %u\n", header->unknown3);
	printf("unknown4: %u\n", header->unknown4);
	printf("sig2: 0x%08X\n", header->sig2);
	printf("------------------------\n");
}

bool verify_signature_and_hash(rsa_key_t *key, const unsigned char *encrypted_signature, size_t signature_len, const unsigned char *expected_hash, size_t hash_len)
{
	bool result = false;
	int decrypted_len, index;
	size_t asn1_len, template_len = sizeof(SIGNATURE_STRUCTURE_TEMPLATE);
	RSA *rsa = create_rsa_from_rsa_key_t(key);
	unsigned char *hash_in_signature, *asn1_data;
	unsigned char decrypted_signature[RSA_size(rsa)];

	if(!rsa)
	{
		return false;
	}

	decrypted_len = RSA_public_decrypt(
		signature_len,
		encrypted_signature,
		decrypted_signature,
		rsa,
		RSA_NO_PADDING);

	if (decrypted_len == -1)
	{
		fprintf(stderr, "Ошибка при расшифровке подписи\n");
		goto cleanup;
	}

	if (decrypted_signature[0] != 0x00 || decrypted_signature[1] != 0x01)
	{
		goto cleanup;
	}

	index = 2;
	while (index < decrypted_len && decrypted_signature[index] == 0xFF)
	{
		index++;
	}

	if(index >= decrypted_len || decrypted_signature[index] != 0x00)
	{
		goto cleanup;
	}
	index++;

	asn1_data = &decrypted_signature[index];
	asn1_len = decrypted_len - index;

	if (asn1_len < template_len + hash_len)
	{
		goto cleanup;
	}

	if (memcmp(asn1_data, SIGNATURE_STRUCTURE_TEMPLATE, template_len) != 0)
	{
		goto cleanup;
	}

	hash_in_signature = asn1_data + template_len;

	if (memcmp(hash_in_signature, expected_hash, hash_len) != 0)
	{
		goto cleanup;
	}

	result = true;

cleanup:
	RSA_free(rsa);
	return result;
}

int64_t validate_image_header(uint8_t *image_bufer, rsa_key_t *key)
{
	uint8_t image_hash[32];
	uint8_t result;
	compute_hash(image_bufer, 1536, image_hash);
	result = verify_signature_and_hash(key, (image_bufer + 1536), 256, image_hash, 32);
	if ( result )
	{
		fprintf(stdout, " check pass!\n");
		return(0);
	}
	else
	{
		fprintf(stdout, " check fail with ERR = %d\n", 1376);
		return(1376);
	}
}

int64_t validate_header(AmlogicCryptoHeader_t *header)
{

	if (header == NULL)
	{
		return 1199;
	}

	if (header->sig1 != 0x434c4d41 || header->sig2 != 0x434c4d41)
	{
		return 1204;
	}

	if (header->encrypted >= 2 || header->block_size != 512)
	{
		return 1214;
	}

	if (header->unknown4 != 512)
	{
		return 1214;
	}

	if (header->data_offset != 512)
	{
		return 1225;
	}

	return 0;
}


int64_t decrypt_encrypt(uint8_t *input_buffer, uint8_t *output_buffer, rsa_key_t *key_51C6778, rsa_key_t *key_51C6340, const uint8_t *reference_hash)
{
	int64_t error_code = 0;
	unsigned int i;
	AmlogicCryptoHeader_t header[2];
	AmlogicCryptoHeader_t decrypted_header[2];
	uint8_t temp_storage[256];
	uint8_t computed_hash[32];
	uint8_t key_hash[32];
	rsa_key_t *selected_key = NULL;
	const char *selected_key_name = NULL;

	rsa_key_t *keys[] = {key_51C6778, key_51C6340};
	const char *key_names[] = {"key_51C6778", "key_51C6340"};
	size_t key_lengths[] = {516, 1036};
	size_t num_keys = sizeof(keys) / sizeof(keys[0]);
	size_t num_lengths = sizeof(key_lengths) / sizeof(key_lengths[0]);
	uint32_t decrypted_size;

	for (size_t i = 0; i < num_keys; ++i)
	{
		for (size_t j = 0; j < num_lengths; ++j)
		{
			compute_hash((uint8_t *)keys[i], key_lengths[j], key_hash);
			if (memcmp(reference_hash, key_hash, 32) == 0)
			{
				selected_key = keys[i];
				selected_key_name = key_names[i];
				break;
			}
		}
		if (selected_key != NULL)
		{
			break;
		}
	}

	if (selected_key == NULL)
	{
		printf("Error: No matching key found\n");
		return 666;
	}

	memcpy(header, input_buffer, sizeof(AmlogicCryptoHeader_t)*2);

	if (validate_header(header))
	{
		for (i = 0; i < 512; i += 4 * selected_key->modulusSize)
		{
			RSA *rsa = create_rsa_from_rsa_key_t(selected_key);
			if (!rsa)
			{
				fprintf(stderr, "RSA error\n");
				return 1;
			}
			RSA_public_decrypt(4 * selected_key->modulusSize, &input_buffer[i], temp_storage, rsa, RSA_NO_PADDING);
			RSA_free(rsa);
			memcpy(&input_buffer[i], temp_storage, 4 * selected_key->modulusSize);
		}

		memcpy(&decrypted_header, input_buffer, sizeof(AmlogicCryptoHeader_t)*2);

		error_code = validate_header(decrypted_header);

		if (error_code)
		{
			fprintf(stdout, "check fail with ERR = %li\n", error_code);
		}
		else
		{
			fprintf(stdout, "CheckPass\n");
			memcpy(input_buffer, (input_buffer+decrypted_header[0].first_offset), decrypted_header[0].block_size);
			compute_hash(input_buffer, decrypted_header[0].encrypted_size, computed_hash);
			hex_print(decrypted_header[0].hash, 32);

			if (!memcmp(computed_hash, decrypted_header[0].hash, 32))
			{
				if (decrypted_header[0].encrypted)
				{
					decrypted_size = openssl_aes_decrypt(
						input_buffer,
						decrypted_header[0].payload_size,
						decrypted_header[0].key,
						decrypted_header[0].iv,
						output_buffer);
					if (decrypted_size < 0)
					{
						fprintf(stderr, "AES decryption failed\n");
						return 1331;
					}

					if (decrypted_size != decrypted_header[0].payload_size)
					{
						fprintf(stderr, "Decrypted size mismatch\n");
						return 1331;
					}
				}
				return 0;
			}
			else
			{
				fprintf(stderr, "Hash mismatch\n");
				return 1332;
			}
		}
	}
	else
	{
		error_code = 1320;
	}

	fprintf(stdout, "fail with %li\n", error_code);
	return error_code;
}


int64_t aml_encdec(uint8_t *image_buffer, rsa_key_t *key_51C6778, rsa_key_t *key_51C6340, uint8_t flags)
{
	int64_t status_code;
	int SignatureMatch;
	int validation_result;
	uint8_t *SectionEntryPtr;
	unsigned int section_index;
	int64_t section_offset;
	uint8_t *SectionDataPtr;
	int operation_result;
	FILE *section_file;
	char section_file_name[64];
	size_t bytes_written;

	SignatureMatch = memcmp(image_buffer + 1024, "AMLSECU!", 8);
	status_code = 1423;
	if (!SignatureMatch)
	{
		validation_result = validate_image_header(image_buffer, key_51C6340);
		status_code = validation_result;
		if (!validation_result)
		{
			SectionEntryPtr = image_buffer + 1120;

			for (section_index = 0; section_index < image_buffer[1036]; ++section_index)
			{
				if (((1 << section_index) & flags) != 0 && *(uint32_t *)(SectionEntryPtr - 60))
				{
					printf("Processing section %u\n", section_index);
					section_offset = *(uint32_t *)(SectionEntryPtr - 64);
					SectionDataPtr = &image_buffer[section_offset];

					uint32_t buffer_size=*(uint32_t *)(SectionEntryPtr - 60);
					buffer_size+=512-(buffer_size%512);
					uint8_t *decrypted_buffer = (uint8_t *)malloc(buffer_size);

					if (!decrypted_buffer)
					{
						fprintf(stderr, "Memory allocation failed\n");
						return -1;
					}
					else
					{
						fprintf(stderr, "Section size %u bytes. %u bytes has been allocation successfully\n", *(uint32_t *)(SectionEntryPtr - 60), buffer_size);
					}

					operation_result = decrypt_encrypt(SectionDataPtr, decrypted_buffer, key_51C6778, key_51C6340, SectionEntryPtr);
					status_code = operation_result;
					if (operation_result)
					{
						fprintf(stderr, "decrypt_encrypt failed with error code: %d\n", operation_result);
						free(decrypted_buffer);
						return status_code;
					}

					sprintf(section_file_name, "section_%i_decrypted.bin", section_index);
					section_file = fopen(section_file_name, "wb");
					if (!section_file)
					{
						fprintf(stderr, "Failed to open file '%s'\n", section_file_name);
						free(decrypted_buffer);
						return -4;
					}
					bytes_written = fwrite(decrypted_buffer, 1, *(uint32_t *)(SectionEntryPtr - 60), section_file);
					fclose(section_file);

					if (bytes_written != *(uint32_t *)(SectionEntryPtr - 60))
					{
						fprintf(stderr, "Failed to write decrypted data to file\n");
						free(decrypted_buffer);
						return -1;
					}

					free(decrypted_buffer);
				}
				SectionEntryPtr += 96LL;
			}
			return 0LL;
		}
	}
	return status_code;
}

int main(int argc, char *argv[])
{
	rsa_key_t *key_51C6778 = (rsa_key_t *)malloc(sizeof(rsa_key_t));
	rsa_key_t *key_51C6340 = (rsa_key_t *)malloc(sizeof(rsa_key_t));
	uint8_t *image = (uint8_t *)malloc(32 * 1024 * 1024);

	FILE *key_51C6778_dump = fopen("key1", "rb");
	FILE *key_51C6340_dump = fopen("key2", "rb");
	if (!key_51C6778_dump || !key_51C6340_dump)
	{
		fprintf(stderr, "Failed to open key files\n");
		free(key_51C6778);
		free(key_51C6340);
		free(image);
		return 1;
	}
	fread(key_51C6778, 1, sizeof(rsa_key_t), key_51C6778_dump);
	fread(key_51C6340, 1, sizeof(rsa_key_t), key_51C6340_dump);
	fclose(key_51C6778_dump);
	fclose(key_51C6340_dump);

	FILE *image_file = fopen("datafile", "rb");
	if (!image_file)
	{
		fprintf(stderr, "Failed to open input file datafile\n");
		return 1;
	}
	size_t read_size = fread(image, 1, 32 * 1024 * 1024, image_file);
	fclose(image_file);
	fprintf(stdout, "%lu bytes has been read from 'datafile'\n", read_size);

	int64_t result = aml_encdec(image, key_51C6778, key_51C6340, 0xFF);

	free(key_51C6778);
	free(key_51C6340);
	free(image);

	if (result == 0)
	{
		printf("Decryption completed successfully.\n");
	}
	else
	{
		fprintf(stderr, "Decryption failed with error code: %ld\n", result);
	}

	return result == 0 ? 0 : 1;
}
