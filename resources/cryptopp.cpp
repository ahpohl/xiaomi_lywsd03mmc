#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include <iostream>
#include <fstream>
#include <iomanip>

#include <cryptopp/cryptlib.h>
#include <cryptopp/filters.h>
#include <cryptopp/aes.h>
#include <cryptopp/ccm.h>
#include <cryptopp/hex.h>

#define MAX_PLAINTEXT_LEN 64
#define AES_KEY_SIZE 128

typedef struct TestVector {
  char const* name;
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

/*
static TestVector constexpr testVectorCCM = {
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
*/

// https://www.cryptopp.com/wiki/CCM_Mode
/*
static TestVector constexpr testVectorCCM = {
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

char* as_hex(unsigned char const* a, size_t a_size)
{
    char* s = (char*) malloc(a_size * 2 + 1);
    for (size_t i = 0; i < a_size; i++) {
        sprintf(s + i * 2, "%02X", a[i]);
    }
    return s;
}

int main(int argc, char* argv[])
{
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

  std::string plaintext;

  try {
    CryptoPP::CCM<CryptoPP::AES, testVectorCCM.tagsize>::Decryption d;
    d.SetKeyWithIV(testVectorCCM.key, AES_KEY_SIZE/8, testVectorCCM.iv,
    		testVectorCCM.ivsize);
    d.SpecifyDataLengths(testVectorCCM.authsize, testVectorCCM.datasize, 0);

    CryptoPP::AuthenticatedDecryptionFilter df(d,
      new CryptoPP::StringSink(plaintext));

    // The order of the following calls are important
    df.ChannelPut(CryptoPP::AAD_CHANNEL, testVectorCCM.authdata,
    		testVectorCCM.authsize);
    df.ChannelPut(CryptoPP::DEFAULT_CHANNEL, testVectorCCM.ciphertext,
    		testVectorCCM.datasize);
    df.ChannelPut(CryptoPP::DEFAULT_CHANNEL, testVectorCCM.tag,
    		testVectorCCM.tagsize);

    df.ChannelMessageEnd(CryptoPP::AAD_CHANNEL);
    df.ChannelMessageEnd(CryptoPP::DEFAULT_CHANNEL);
  }
  catch (CryptoPP::InvalidArgument& e) {
    throw std::runtime_error(e.what());
  }
  catch (CryptoPP::HashVerificationFilter::HashVerificationFailed& e) {
    throw std::runtime_error(e.what());
  }

  std::cout << std::endl;
  std::cout << "Crypto++   : decrypted and verified data" << std::endl;

  std::string enc;
  CryptoPP::StringSource ssk(plaintext, true, new CryptoPP::HexEncoder(
    new CryptoPP::StringSink(enc), true, 2, ""));
  std::cout << "Plaintext  : " << enc << std::endl;

  return 0;
}
