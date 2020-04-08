#include <mbedtls/ccm.h>

#if defined(ESP8266) || defined(ESP32)
#include <pgmspace.h>
#else
#include <avr/pgmspace.h>
#endif

#define MAX_PLAINTEXT_LEN 64
#define AES_KEY_SIZE 128

typedef struct TestVector
{
    const char *name;
    uint8_t key[32];
    uint8_t plaintext[MAX_PLAINTEXT_LEN];
    uint8_t ciphertext[MAX_PLAINTEXT_LEN];
    uint8_t authdata[20];
    uint8_t iv[12];
    uint8_t tag[16];
    size_t authsize;
    size_t datasize;
    size_t tagsize;
    size_t ivsize;
} TestVector;

static TestVector const testVectorCCM PROGMEM = {
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

char* as_hex(unsigned char const* a, size_t a_size)
{
    char* s = (char*) malloc(a_size * 2 + 1);
    for (size_t i = 0; i < a_size; i++) {
        sprintf(s + i * 2, "%02X", a[i]);
    }
    return s;
}

void setup() {
  Serial.begin(9600);
  Serial.println();

  int ret = 0;
  uint8_t plaintext[MAX_PLAINTEXT_LEN];

  Serial.println("Test vector for BLE ADV packet");
  char * encoded;
  encoded = as_hex(testVectorCCM.key, AES_KEY_SIZE/8);
  Serial.printf("Key        : %s\n\r", encoded);
  free(encoded);
  encoded = as_hex(testVectorCCM.iv, testVectorCCM.ivsize);
  Serial.printf("Iv         : %s\n\r", encoded);
  free(encoded);
  encoded = as_hex(testVectorCCM.ciphertext, testVectorCCM.datasize);
  Serial.printf("Cipher     : %s\n\r", encoded);
  free(encoded);
  encoded = as_hex(testVectorCCM.plaintext, testVectorCCM.datasize);
  Serial.printf("Plaintext  : %s\n\r", encoded);
  free(encoded);
  encoded = as_hex(testVectorCCM.tag, testVectorCCM.tagsize);
  Serial.printf("Tag        : %s\n\r", encoded);
  free(encoded);
  
  mbedtls_ccm_context* ctx;
  ctx = (mbedtls_ccm_context*) malloc(sizeof(mbedtls_ccm_context));
  mbedtls_ccm_init(ctx);
  ret = mbedtls_ccm_setkey(ctx,
    MBEDTLS_CIPHER_ID_AES,
    testVectorCCM.key,
    AES_KEY_SIZE
  );
  if (ret) {
    Serial.println("CCM setkey failed.");
  }
  ret = mbedtls_ccm_auth_decrypt(ctx,
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

  if (ret) {
    if (ret == MBEDTLS_ERR_CCM_AUTH_FAILED) {
      Serial.println("Authenticated decryption failed.");
    } else if (ret == MBEDTLS_ERR_CCM_BAD_INPUT) {
      Serial.println("Bad input parameters to the function.");
    } else if (ret == MBEDTLS_ERR_CCM_HW_ACCEL_FAILED) {
      Serial.println("CCM hardware accelerator failed."); 
    } 
  } else {
    Serial.println("Decryption successful");
  }
  
  encoded = as_hex(plaintext, testVectorCCM.datasize);
  Serial.printf("Plaintext  : %s\n\r", encoded);
  free(encoded);

  mbedtls_ccm_free(ctx);  
}

void loop() {
}
