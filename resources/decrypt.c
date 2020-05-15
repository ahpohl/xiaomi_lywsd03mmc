#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <math.h>
#include <mbedtls/config.h>
#include <mbedtls/cipher.h>
#include <mbedtls/ccm.h>
#include <mbedtls/error.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>

#define MAX_PLAINTEXT_LEN 64

typedef struct AESVector {
  char const* name;
  unsigned char key[32];
  unsigned char plaintext[MAX_PLAINTEXT_LEN];
  unsigned char ciphertext[MAX_PLAINTEXT_LEN];
  unsigned char authdata[MAX_PLAINTEXT_LEN];
  unsigned char iv[16];
  unsigned char tag[16];
  size_t keysize;
  size_t authsize;
  size_t datasize;
  size_t tagsize;
  size_t ivsize;
} AESVector;

char* as_hex(const uint8_t *data, uint32_t len) {
  char buf[20];
  char* res = (char*) malloc(len * 3 + 1);
  for (size_t i = 0; i < len; i++) {
    if (i + 1 != len) {
      sprintf(buf, "%02X.", data[i]);
    } else {
      sprintf(buf, "%02X ", data[i]);
    }
    strcat(res, buf);
  }
  sprintf(buf, "(%u)", len);
  strcat(res, buf);
  return res;
}

int main(int argc, char* argv[])
{
  int ret = 0;
  unsigned char plaintext[MAX_PLAINTEXT_LEN] = {0};
  unsigned char tag[MAX_PLAINTEXT_LEN] = {0};
  unsigned char cipher[MAX_PLAINTEXT_LEN] = {0};

  ret = mbedtls_ccm_self_test(1);
  if (ret) {
    char err[100] = {0};
    mbedtls_strerror(ret, err, 99);
    fprintf(stderr, "MbedTLS    : %s\n", err);
    return 1;
  }

  AESVector vector = {
      .name        = "MJYd2S 19-bytes packet",
      .key         = {0},
      .plaintext   = {0},
      .ciphertext  = {0},
      .authdata    = {0x11},
      .iv          = {0},
      .tag         = {0},
      .keysize     = 16,
      .authsize    = 1,
      .datasize    = 7,
      .tagsize     = 4,
      .ivsize      = 12
  };

  uint8_t bindkey[16] = {0x71, 0xA5, 0x55, 0x02, 0x3F, 0x95, 0xD5, 0xA6, 0x2D, 0xBD, 0xBA, 0xB3, 0xCA, 0x6B, 0xC9, 0x1D};
  uint8_t mac_address[6] = {0x50, 0xEC, 0x50, 0xCD, 0x32, 0x02};
  uint8_t raw[128] = {0};
  uint8_t* p = raw;

  char buf[256] = {0};
  printf("Enter packet XX.XX: ");
  fgets(buf, sizeof(buf), stdin);

  int raw_size = 0;
  char* tok = strtok(buf, ".");
  while (tok != NULL) {
    *p = strtoul(tok , NULL, 16);
    ++p;
    ++raw_size;
    tok = strtok(NULL, ".");
  }

  uint8_t mac_reverse[6] = {0};
  memcpy(mac_reverse,     mac_address + 5, 1);
  memcpy(mac_reverse + 1, mac_address + 4, 1);
  memcpy(mac_reverse + 2, mac_address + 3, 1);
  memcpy(mac_reverse + 3, mac_address + 2, 1);
  memcpy(mac_reverse + 4, mac_address + 1, 1);
  memcpy(mac_reverse + 5, mac_address    , 1);

  const uint8_t *v = raw;
  memcpy(vector.key, bindkey, vector.keysize);
  memcpy(vector.ciphertext, v + 5, vector.datasize);
  memcpy(vector.tag, v + 15, vector.tagsize);
  memcpy(vector.iv, mac_reverse, 6); // MAC address
  memcpy(vector.iv + 6, v + 2, 3);   // sensor type (2) + packet id (1)
  memcpy(vector.iv + 9, v + 12, 3);  // payload counter

  printf("Name       : %s\n", vector.name);
  char * encoded;
  encoded = as_hex(raw, raw_size);
  printf("Packet     : %s\n", encoded);
  free(encoded);
  encoded = as_hex(vector.key, vector.keysize);
  printf("Key        : %s\n", encoded);
  free(encoded);
  encoded = as_hex(vector.iv, vector.ivsize);
  printf("Iv         : %s\n", encoded);
  free(encoded);
  encoded = as_hex(vector.ciphertext, vector.datasize);
  printf("Cipher     : %s\n", encoded);
  free(encoded);
  encoded = as_hex(vector.tag, vector.tagsize);
  printf("Tag        : %s\n", encoded);
  free(encoded);

  mbedtls_ccm_context ctx;
  mbedtls_ccm_init(&ctx);
  ret = mbedtls_ccm_setkey(&ctx,
    MBEDTLS_CIPHER_ID_AES,
    vector.key,
    vector.keysize * 8
  );
  if (ret) {
    char err[100] = {0};
    mbedtls_strerror(ret, err, 99);
    fprintf(stderr, "MbedTLS    : %s\n", err);
    return 1;
  }

  ret = mbedtls_ccm_auth_decrypt(&ctx,
    vector.datasize,
    vector.iv,
    vector.ivsize,
    vector.authdata,
    vector.authsize,
    vector.ciphertext,
    vector.plaintext,
    vector.tag,
    vector.tagsize
  );

  printf("\n");
  if (ret) {
    char err[100] = {0};
    if (ret) {
      mbedtls_strerror(ret, err, 99);
      fprintf(stderr, "MbedTLS    : %s\n", err);
    }
  } else {
      printf("MbedTLS    : Authenticated decryption successful\n");
  }

  encoded = as_hex(vector.plaintext, vector.datasize);
  printf("Plaintext  : %s\n", encoded);
  free(encoded);

  mbedtls_ccm_free(&ctx);

  return 0;
}
