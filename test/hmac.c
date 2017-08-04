#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <time.h>
#include <sys/socket.h>

#include <owamp/owamp.h>
#
#include "./test_protocol.h"

//#include <I2util/util.h>
#include <I2util/hmac-sha1.h>
#include <openssl/aes.h>
#include <openssl/hmac.h>

#define HMAC_KEY "key"
#define TEST_TEXT "The quick brown fox jumps over the lazy dog"

#define HMAC_KEY_HEX "6b6579"
#define TEST_TEXT_HEX "54686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f67"

#define APP_KEY "6f12925128e26bbc" \
                "1cf55c19ed41c22e" \
                "312aea6a991454ed" \
                "ed9abea762cd05cf"

#define APP_MESSAGE "0000abcd74686973" \
                "2069732074686520" \
                "5349442100000000" \
                "0000000000000000"



void print_hmac(const char *key, const char *message, const uint8_t digest[I2HMAC_SHA1_DIGEST_SIZE]) {
    char hex[2*I2HMAC_SHA1_DIGEST_SIZE+1];
    I2HexEncode(hex, digest, I2HMAC_SHA1_DIGEST_SIZE);
    printf("HMAC_SHA1(\"%s\", \"%s\")\t= %s\n",
        key, message, hex);
}

I2HMACSha1Context gI2ctx;
 
 
void i2_hmac_test(
        const uint8_t *key,
        uint32_t key_len,
        const uint8_t *message,
        uint32_t message_len,
        uint8_t digest[I2HMAC_SHA1_DIGEST_SIZE]) {
//    I2HMACSha1Context gI2ctx = I2HMACSha1Alloc(NULL);
    I2HMACSha1Init(gI2ctx, key, key_len);
    I2HMACSha1Append(gI2ctx, message, message_len);
    memset(digest, 0, I2HMAC_SHA1_DIGEST_SIZE);
    I2HMACSha1Finish(gI2ctx, digest);
//    I2HMACSha1Free(gI2ctx);
}

void i2_hmac_test_str(const char *key, const char *message) {
    uint8_t hmac[I2HMAC_SHA1_DIGEST_SIZE];
    i2_hmac_test((const uint8_t *) key, strlen(key), (const uint8_t *) message, strlen(message), hmac);
    print_hmac(key, message, hmac);
}


void i2_hmac_test_hex(const char *key_hex, const char *message_hex) {

    assert(strlen(key_hex) % 2 == 0);
    assert(strlen(message_hex) % 2 == 0);

    size_t key_len = strlen(key_hex)/2;
    size_t message_len = strlen(message_hex)/2;
    uint8_t *key = (uint8_t *) malloc(key_len);
    uint8_t *message = (uint8_t *) malloc(message_len);
    I2HexDecode(key_hex, key, key_len);
    I2HexDecode(message_hex, message, message_len);

    uint8_t hmac[I2HMAC_SHA1_DIGEST_SIZE];
    i2_hmac_test(key, key_len, message, message_len, hmac);
    print_hmac(key_hex, message_hex, hmac);

    free(key);
    free(message);
}

void openssl_hmac_test(
        void *key,
        int key_len,
        const unsigned char *message,
        int message_len,
        uint8_t digest[I2HMAC_SHA1_DIGEST_SIZE]) {
    HMAC_CTX ctx;

    HMAC_CTX_init(&ctx);

    HMAC_Init_ex(&ctx, key, key_len, EVP_sha1(), NULL);
    HMAC_Update(&ctx, message, message_len);

    unsigned int digest_len = I2HMAC_SHA1_DIGEST_SIZE;
    memset(digest, 0, I2HMAC_SHA1_DIGEST_SIZE);
    HMAC_Final(&ctx, digest, &digest_len);
    assert(digest_len == I2HMAC_SHA1_DIGEST_SIZE);

    HMAC_CTX_cleanup(&ctx);

}

void openssl_hmac_test_hex(const char *key_hex, const char *message_hex) {

    assert(strlen(key_hex) % 2 == 0);
    assert(strlen(message_hex) % 2 == 0);

    size_t key_len = strlen(key_hex)/2;
    size_t message_len = strlen(message_hex)/2;
    uint8_t *key = (uint8_t *) malloc(key_len);
    uint8_t *message = (uint8_t *) malloc(message_len);
    I2HexDecode(key_hex, key, key_len);
    I2HexDecode(message_hex, message, message_len);

    uint8_t hmac[I2HMAC_SHA1_DIGEST_SIZE];
    i2_hmac_test((void *) key, key_len, (unsigned char *) message, message_len, hmac);
    print_hmac(key_hex, message_hex, hmac);

    free(key);
    free(message);
}
 
void openssl_hmac_test_str(const char *key, const char *message) {
    uint8_t hmac[I2HMAC_SHA1_DIGEST_SIZE];
    openssl_hmac_test((void *) key, strlen(key), (uint8_t *) message, strlen(message), hmac);
    print_hmac(key, message, hmac);
}



int main(int argc, char *argv[]) {

gI2ctx = I2HMACSha1Alloc(NULL);
 
//    openssl_hmac_test_str("", "");
//    i2_hmac_test_str("", "");
    
    openssl_hmac_test_str(HMAC_KEY, TEST_TEXT);
    i2_hmac_test_str(HMAC_KEY, TEST_TEXT);

    openssl_hmac_test_hex(HMAC_KEY_HEX, TEST_TEXT_HEX);
    i2_hmac_test_hex(HMAC_KEY_HEX, TEST_TEXT_HEX);

 

    openssl_hmac_test_hex(APP_KEY, APP_MESSAGE);
    i2_hmac_test_hex(APP_KEY, APP_MESSAGE);

I2HMACSha1Free(gI2ctx);

   return 0;

}




