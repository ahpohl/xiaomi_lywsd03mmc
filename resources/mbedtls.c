#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <mbedtls/config.h>
#include <mbedtls/cipher.h>
#include <mbedtls/ccm.h>

#define MAX_PLAINTEXT_LEN 64
#define AES_KEY_SIZE 128

typedef struct TestVector {
  char const* name;
  unsigned char key[32];
  unsigned char plaintext[MAX_PLAINTEXT_LEN];
  unsigned char ciphertext[MAX_PLAINTEXT_LEN];
  unsigned char authdata[MAX_PLAINTEXT_LEN];
  unsigned char iv[12];
  unsigned char tag[16];
  size_t authsize;
  size_t datasize;
  size_t tagsize;
  size_t ivsize;
} TestVector;

static TestVector const testVectorCCM = {
    .name        = "AES-128 CCM BLE ADV",
    .key         = {0xE9, 0xEF, 0xAA, 0x68, 0x73, 0xF9, 0xF9, 0xC8,
                    0x7A, 0x5E, 0x75, 0xA5, 0xF8, 0x14, 0x80, 0x1C},
    .plaintext   = {0x04, 0x10, 0x02, 0xD3, 0x00},
    .ciphertext  = {0xDA, 0x61, 0x66, 0x77, 0xD5},
    .authdata    = {0x11},
    .iv          = {0x78, 0x16, 0x4E, 0x38, 0xC1, 0xA4, 0x5B, 0x05,
                    0x3D, 0x2E, 0x00, 0x00},
    .tag         = {0x92, 0x98, 0x23, 0x52},
    .authsize    = 1,
    .datasize    = 5,
    .tagsize     = 4,
    .ivsize      = 12
};

// https://www.cryptopp.com/wiki/CCM_Mode
/*
static TestVector const testVectorCCM = {
    .name        = "Gladman's Test Vector 003",
    .key         = {0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
                    0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f},
    .plaintext   = {0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
    		        0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
    		        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37},
    .ciphertext  = {0xe3, 0xb2, 0x01, 0xa9, 0xf5, 0xb7, 0x1a, 0x7a,
    		        0x9b, 0x1c, 0xea, 0xec, 0xcd, 0x97, 0xe7, 0x0b,
					0x61, 0x76, 0xaa, 0xd9, 0xa4, 0x42, 0x8a, 0xa5},
    .authdata    = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    		        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
					0x10, 0x11, 0x12, 0x13},
    .iv          = {0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    		        0x18, 0x19, 0x1a, 0x1b},
    .tag         = {0x48, 0x43, 0x92, 0xfb, 0xc1, 0xb0, 0x99, 0x51},
    .authsize    = 20,
    .datasize    = 24,
    .tagsize     = 8,
    .ivsize      = 12
};
*/

// mbedtls/tests/suites/test_suite_cipher.ccm.data
/*
static TestVector const testVectorCCM = {
    .name        = "AES-128 CCM NIST #25",
    .key         = {0xf9, 0xfd, 0xca, 0x4a, 0xc6, 0x4f, 0xe7, 0xf0,
    		        0x14, 0xde, 0x0f, 0x43, 0x03, 0x9c, 0x75, 0x71},
    .plaintext   = {0xa2, 0x65, 0x48, 0x0c, 0xa8, 0x8d, 0x5f, 0x53,
    		        0x6d, 0xb0, 0xdc, 0x6a, 0xbc, 0x40, 0xfa, 0xf0,
			        0xd0, 0x5b, 0xe7, 0xa9, 0x66, 0x97, 0x77, 0x68},
	.ciphertext  = {0x6b, 0xe3, 0x18, 0x60, 0xca, 0x27, 0x1e, 0xf4,
				    0x48, 0xde, 0x8f, 0x8d, 0x8b, 0x39, 0x34, 0x6d,
					0xaf, 0x4b, 0x81, 0xd7, 0xe9, 0x2d, 0x65, 0xb3},
	.authdata    = {0x37, 0x96, 0xcf, 0x51, 0xb8, 0x72, 0x66, 0x52,
    		        0xa4, 0x20, 0x47, 0x33, 0xb8, 0xfb, 0xb0, 0x47,
					0xcf, 0x00, 0xfb, 0x91, 0xa9, 0x83, 0x7e, 0x22,
					0xec, 0x22, 0xb1, 0xa2, 0x68, 0xf8, 0x8e, 0x2c},
    .iv          = {0x5a, 0x8a, 0xa4, 0x85, 0xc3, 0x16, 0xe9},
    .tag         = {0x38, 0xf1, 0x25, 0xfa},
    .authsize    = 32,
    .datasize    = 24,
    .tagsize     = 4,
    .ivsize      = 7
};
*/

char* as_hex(unsigned char const* a, size_t a_size)
{
    unsigned char* s = (char*) malloc(a_size * 2 + 1);
    for (size_t i = 0; i < a_size; i++) {
        sprintf(s + i * 2, "%02X", a[i]);
    }
    return s;
}

int main(int argc, char* argv[])
{
  int ret = 0;
  unsigned char plaintext[MAX_PLAINTEXT_LEN] = {0};

  ret = mbedtls_ccm_self_test(1);
  if (ret) {
	printf("AES-CCM self test failed.\n");
	return 1;
  }

  printf("Name       : %s\n", testVectorCCM.name);
  char * encoded;
  encoded = as_hex(testVectorCCM.key, AES_KEY_SIZE/8);
  printf("Key        : %s\n", encoded);
  free(encoded);
  encoded = as_hex(testVectorCCM.iv, testVectorCCM.ivsize);
  printf("Iv         : %s\n", encoded);
  free(encoded);
  encoded = as_hex(testVectorCCM.ciphertext, testVectorCCM.datasize);
  printf("Cipher     : %s\n", encoded);
  free(encoded);
  encoded = as_hex(testVectorCCM.plaintext, testVectorCCM.datasize);
  printf("Plaintext  : %s\n", encoded);
  free(encoded);
  encoded = as_hex(testVectorCCM.tag, testVectorCCM.tagsize);
  printf("Tag        : %s\n", encoded);
  free(encoded);

  mbedtls_ccm_context ctx;
  mbedtls_ccm_init(&ctx);
  ret = mbedtls_ccm_setkey(&ctx,
    MBEDTLS_CIPHER_ID_AES,
    testVectorCCM.key,
    AES_KEY_SIZE
  );
  if (ret) {
    printf("CCM setkey failed.\n");
    return 1;
  }
  ret = mbedtls_ccm_auth_decrypt(&ctx,
    testVectorCCM.datasize,
    testVectorCCM.iv,
    testVectorCCM.ivsize,
    testVectorCCM.authdata,
    testVectorCCM.datasize,
    testVectorCCM.ciphertext,
    plaintext,
    testVectorCCM.tag,
    testVectorCCM.tagsize 
  );

  printf("\n");
  if (ret) {
    if (ret == MBEDTLS_ERR_CCM_AUTH_FAILED) {
      fprintf(stderr, "MbedTLS    : Authenticated decryption failed.\n");
    } else if (ret == MBEDTLS_ERR_CCM_BAD_INPUT) {
      fprintf(stderr, "MbedTLS    : Bad input parameters to the function.\n");
    } else if (ret == MBEDTLS_ERR_CCM_HW_ACCEL_FAILED) {
      fprintf(stderr, "MbedTLS    : CCM hardware accelerator failed.\n");
    }
  } else {
    printf("MbedTLS    : Decryption successful\n");
  }

  encoded = as_hex(plaintext, testVectorCCM.datasize);
  printf("Plaintext  : %s\n", encoded);
  free(encoded);

  mbedtls_ccm_free(&ctx);

  unsigned char tag[testVectorCCM.tagsize] = testVectorCCM.ciphertext + testVectorCCM.datasize;

  return 0;
}
