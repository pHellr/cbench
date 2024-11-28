#include <sodium.h>
#include <nettle/gcm.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#include <string.h>
#include <stdio.h>
#include <immintrin.h>

/// @brief generates random message string, with termination character \0 append at the end
/// @param len input length of message
/// @return returns pointer to first char of message
unsigned char* getRandomMessage(int len){
    uint8_t c;
    unsigned char* message = (unsigned char*)malloc(len + 1);
    for(int i = 0; i < len; i++)
    {   
        //limit char to values 45-126, to ignore special characters
        c = 45+(rand()%82);

        message[i] = (char)c;
    }
    message[len] = '\0';
    return message;
}

inline static int ssl_encrypt(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *ciph,
                unsigned char *plaintext, int plaintext_len,
                unsigned char *aad, int aad_len,
                unsigned char *key,
                unsigned char *iv, int iv_len,
                unsigned char *ciphertext,
                unsigned char *tag, int tag_len)
{
    int len;

    OPENSSL_assert(ctx);                                                    // verify ctx is created correctly; abort else
    EVP_CIPHER_CTX_init(ctx);                                               // initialising ctx 
    EVP_EncryptInit_ex(ctx, ciph, NULL, NULL, NULL);                        // set cipher type
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, iv_len, NULL);        // set IV length
    EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv);                           // initialise key and IV
    EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len);                       // process assoc data for tag
    EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);     // encrypt plaintext & calculate tag
    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);                       // finalise tag, cleanup
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, tag_len, tag);           // extract tag
    EVP_CIPHER_CTX_cleanup(ctx);                                            // cleanup ctx

    if(plaintext_len == 0){
        memset(ciphertext, 0, iv_len);
    }
    return 0;
}

//nettle
#pragma region gcm_nettle

#define NETTLE_KEY_LEN 32

int nettle_initialized = 0;

struct gcm_aes256_ctx nettle_ctx;

uint8_t nettle_iv[GCM_IV_SIZE];
uint8_t nettle_key[NETTLE_KEY_LEN];
uint8_t *nettle_msg;
uint8_t *nettle_ad;
unsigned int nettle_msgLen;
unsigned int nettle_adLen;

int nettle_cleanup(){
    memset(nettle_key, 0, sizeof nettle_key);
    memset(nettle_iv, 0, sizeof nettle_iv);
    free(nettle_msg);
    free(nettle_ad);
    nettle_msgLen = 0;
    nettle_adLen = 0;
    nettle_initialized = 0;
    return 0;
}

int nettle_gcm_setup(int msgLen, int adLen){
    randombytes_buf(nettle_key, sizeof nettle_key);
    randombytes_buf(nettle_iv, sizeof nettle_iv);
    nettle_msg = getRandomMessage(msgLen + GCM_DIGEST_SIZE);
    nettle_ad = getRandomMessage(adLen);
    nettle_msgLen = msgLen;
    nettle_adLen = adLen;
    gcm_aes256_set_key(&nettle_ctx, nettle_key);
    gcm_aes256_set_iv (&nettle_ctx, GCM_IV_SIZE, nettle_iv);
    nettle_initialized = 1;
    return 0;
}

void nettle_gcm_loop(){
    unsigned int msgLen = nettle_msgLen,
     adLen = nettle_adLen;
    nettle_cleanup();
    nettle_gcm_setup(msgLen, adLen);
}

void nettle_gcm_enc(){
    gcm_aes256_update(&nettle_ctx, nettle_adLen, nettle_ad);
    gcm_aes256_encrypt(&nettle_ctx, nettle_msgLen, nettle_msg, nettle_msg);
    gcm_aes256_digest(&nettle_ctx, GCM_DIGEST_SIZE, nettle_iv);
    gcm_aes256_set_iv (&nettle_ctx, GCM_IV_SIZE, nettle_iv);
}

#pragma endregion
//endnettle

//sodium
#pragma region gcm_sodium

int sodium_initialized = 0;

unsigned char sodium_nonce[crypto_aead_aes256gcm_NPUBBYTES];
unsigned char sodium_key[crypto_aead_aes256gcm_KEYBYTES];
unsigned char *sodium_msg;
unsigned char *sodium_ad;
unsigned int sodium_msgLen;
unsigned int sodium_adLen;

int sodium_cleanup(){
    memset(sodium_key, 0, sizeof sodium_key);
    memset(sodium_nonce, 0, sizeof sodium_nonce);
    free(sodium_msg);
    free(sodium_ad);
    sodium_msgLen = 0;
    sodium_adLen = 0;
    sodium_initialized = 0;
    return 0;
}

int sodium_gcm_setup(int msgLen, int adLen){
    if (sodium_init() < 0 || crypto_aead_aes256gcm_is_available() == 0) {
        return 1;
    }
    randombytes_buf(sodium_key, sizeof sodium_key);
    randombytes_buf(sodium_nonce, sizeof sodium_nonce);
    sodium_msg = getRandomMessage(msgLen + crypto_aead_aes256gcm_ABYTES);
    sodium_ad = getRandomMessage(adLen);
    sodium_msgLen = msgLen;
    sodium_adLen = adLen;
    sodium_initialized = 1;
    return 0;
}

void sodium_gcm_loop(){
    unsigned int msgLen = sodium_msgLen,
     adLen = sodium_adLen;
    sodium_cleanup();
    sodium_gcm_setup(msgLen, adLen);
}

void sodium_gcm_enc(){
    crypto_aead_aes256gcm_encrypt(sodium_msg, NULL,
                                sodium_msg, sodium_msgLen,
                                sodium_ad, sodium_adLen,
                                NULL,  sodium_nonce, sodium_key);
}

#pragma endregion
//endsodium

//ossl gcm
#pragma region gcm_ossl

#define SSL_GCM_KEYLEN 32 //256 bit = 32 byte
#define SSL_GCM_IVLEN 12 //96 bit iv
#define SSL_GCM_TAGLEN 16 //128 bit tag

int ssl_gcm_initialized = 0;
unsigned char ssl_gcm_nonce[SSL_GCM_TAGLEN];
unsigned char ssl_gcm_key[SSL_GCM_KEYLEN];
unsigned char *ssl_gcm_msg;
unsigned char *ssl_gcm_ad;
unsigned int ssl_gcm_msgLen;
unsigned int ssl_gcm_adLen;
const EVP_CIPHER *ssl_gcm_ciph;
EVP_CIPHER_CTX *ssl_gcm_ctx;

int ssl_gcm_setup(int msgLen, int adLen){
    randombytes_buf(ssl_gcm_key, sizeof ssl_gcm_key);
    randombytes_buf(ssl_gcm_nonce, sizeof ssl_gcm_nonce);
    ssl_gcm_msg = getRandomMessage(msgLen + SSL_GCM_TAGLEN);
    ssl_gcm_ad = getRandomMessage(adLen);
    ssl_gcm_msgLen = msgLen;
    ssl_gcm_adLen = adLen;
    ssl_gcm_ciph = EVP_aes_256_gcm();
    ssl_gcm_ctx = EVP_CIPHER_CTX_new();
    ssl_gcm_initialized = 1;
    return 0;
}

int ssl_gcm_cleanup(){
    memset(ssl_gcm_key, 0, sizeof ssl_gcm_key);
    memset(ssl_gcm_nonce, 0, sizeof ssl_gcm_nonce);
    free(ssl_gcm_msg);
    free(ssl_gcm_ad);
    ssl_gcm_msgLen = 0;
    ssl_gcm_adLen = 0;
    EVP_CIPHER_CTX_free(ssl_gcm_ctx);
    ssl_gcm_initialized = 0;
    return 0;
}

void ssl_gcm_loop(){
    unsigned int msgLen = ssl_gcm_msgLen,
     adLen = ssl_gcm_adLen;
    ssl_gcm_cleanup();
    ssl_gcm_setup(msgLen, adLen);
}

void ssl_gcm_enc(){
    ssl_encrypt(ssl_gcm_ctx, ssl_gcm_ciph,
                ssl_gcm_msg, ssl_gcm_msgLen,
                ssl_gcm_ad, ssl_gcm_adLen,
                ssl_gcm_key, ssl_gcm_nonce, SSL_GCM_IVLEN,
                ssl_gcm_msg, ssl_gcm_nonce, SSL_GCM_TAGLEN);
}

#pragma endregion
//end ossl gcm

//ossl mgm
#pragma region mgm

#define SSL_MGM_IVLEN 16 //128 bit iv (also tag)
#define SN_kuznyechik_mgm "kuznyechik-mgm"

int ssl_mgm_initialized = 0;
unsigned char ssl_mgm_nonce[SSL_MGM_IVLEN];
unsigned char ssl_mgm_key[SSL_GCM_KEYLEN];
unsigned char *ssl_mgm_msg;
unsigned char *ssl_mgm_ad;
unsigned int ssl_mgm_msgLen;
unsigned int ssl_mgm_adLen;
EVP_CIPHER *ssl_mgm_ciph;
EVP_CIPHER_CTX *ssl_mgm_ctx;

int ssl_mgm_setup(int msgLen, int adLen){
    randombytes_buf(ssl_mgm_key, sizeof ssl_mgm_key);
    randombytes_buf(ssl_mgm_nonce, sizeof ssl_mgm_nonce);
    ssl_mgm_msg = getRandomMessage(msgLen + SSL_MGM_IVLEN);
    ssl_mgm_ad = getRandomMessage(adLen);
    ssl_mgm_msgLen = msgLen;
    ssl_mgm_adLen = adLen;

    OPENSSL_add_all_algorithms_conf();
    ssl_mgm_ciph = (EVP_CIPHER *)EVP_get_cipherbyname(SN_kuznyechik_mgm);
    if (!ssl_mgm_ciph) {
        printf("failed to load %s\n", SN_kuznyechik_mgm);
        return 1;
    }
    ssl_mgm_ctx = EVP_CIPHER_CTX_new();
    ssl_mgm_initialized = 1;
    return 0;
}

int ssl_mgm_cleanup(){
    memset(ssl_mgm_key, 0, sizeof ssl_mgm_key);
    memset(ssl_mgm_nonce, 0, sizeof ssl_mgm_nonce);
    free(ssl_mgm_msg);
    free(ssl_mgm_ad);
    ssl_mgm_msgLen = 0;
    ssl_mgm_adLen = 0;
    EVP_CIPHER_free(ssl_mgm_ciph);
    EVP_CIPHER_CTX_free(ssl_mgm_ctx);
    ssl_mgm_initialized = 0;
    return 0;
}
void ssl_mgm_loop(){
    unsigned int msgLen = ssl_mgm_msgLen,
     adLen = ssl_mgm_adLen;
    ssl_mgm_cleanup();
    ssl_mgm_setup(msgLen, adLen);
}

void ssl_mgm_enc(){
    ssl_encrypt(ssl_mgm_ctx, ssl_mgm_ciph,
                ssl_mgm_msg, ssl_mgm_msgLen,
                ssl_mgm_ad, ssl_mgm_adLen,
                ssl_mgm_key, ssl_mgm_nonce, SSL_MGM_IVLEN,
                ssl_mgm_msg, ssl_mgm_nonce, SSL_MGM_IVLEN);
}

#pragma endregion
//end ossl mgm

//ossl mgm block processing
#pragma region mgm_b

#define SN_kuznyechik_mgm_b "kuznyechik-mgm-b"

int ssl_mgm_b_initialized = 0;
unsigned char ssl_mgm_b_nonce[SSL_MGM_IVLEN];
unsigned char ssl_mgm_b_key[SSL_GCM_KEYLEN];
unsigned char *ssl_mgm_b_msg;
unsigned char *ssl_mgm_b_ad;
unsigned int ssl_mgm_b_msgLen;
unsigned int ssl_mgm_b_adLen;
EVP_CIPHER *ssl_mgm_b_ciph;
EVP_CIPHER_CTX *ssl_mgm_b_ctx;

int ssl_mgm_b_setup(int msgLen, int adLen){
    randombytes_buf(ssl_mgm_b_key, sizeof ssl_mgm_b_key);
    randombytes_buf(ssl_mgm_b_nonce, sizeof ssl_mgm_b_nonce);
    ssl_mgm_b_msg = getRandomMessage(msgLen + SSL_MGM_IVLEN);
    ssl_mgm_b_ad = getRandomMessage(adLen);
    ssl_mgm_b_msgLen = msgLen;
    ssl_mgm_b_adLen = adLen;
    ssl_mgm_b_ctx = EVP_CIPHER_CTX_new();

    OPENSSL_add_all_algorithms_conf();
    ssl_mgm_b_ciph = (EVP_CIPHER *)EVP_get_cipherbyname(SN_kuznyechik_mgm_b);
    if (!ssl_mgm_b_ciph) {
        printf("failed to load %s\n", SN_kuznyechik_mgm_b);
        return 1;
    }
    ssl_mgm_b_initialized = 1;
    return 0;
}

int ssl_mgm_b_cleanup(){
    memset(ssl_mgm_b_key, 0, sizeof ssl_mgm_b_key);
    memset(ssl_mgm_b_nonce, 0, sizeof ssl_mgm_b_nonce);
    free(ssl_mgm_b_msg);
    free(ssl_mgm_b_ad);
    ssl_mgm_b_msgLen = 0;
    ssl_mgm_b_adLen = 0;
    EVP_CIPHER_free(ssl_mgm_b_ciph);
    EVP_CIPHER_CTX_free(ssl_mgm_b_ctx);
    ssl_mgm_b_initialized = 0;
    return 0;
}

void ssl_mgm_b_loop(){
    unsigned int msgLen = ssl_mgm_b_msgLen,
     adLen = ssl_mgm_b_adLen;
    ssl_mgm_b_cleanup();
    ssl_mgm_b_setup(msgLen, adLen);
}

void ssl_mgm_b_enc(){
    ssl_encrypt(ssl_mgm_b_ctx, ssl_mgm_b_ciph,
                ssl_mgm_b_msg, ssl_mgm_b_msgLen,
                ssl_mgm_b_ad, ssl_mgm_b_adLen,
                ssl_mgm_b_key, ssl_mgm_b_nonce, SSL_MGM_IVLEN,
                ssl_mgm_b_msg, ssl_mgm_b_nonce, SSL_MGM_IVLEN);
}

#pragma endregion
//end ossl mgm block processing

//ossl mgm clmul
#pragma region mgm_c

#define SN_kuznyechik_mgm_c "kuznyechik-mgm-c"

int ssl_mgm_c_initialized = 0;
unsigned char ssl_mgm_c_nonce[SSL_MGM_IVLEN];
unsigned char ssl_mgm_c_key[SSL_GCM_KEYLEN];
unsigned char *ssl_mgm_c_msg;
unsigned char *ssl_mgm_c_ad;
unsigned int ssl_mgm_c_msgLen;
unsigned int ssl_mgm_c_adLen;
EVP_CIPHER *ssl_mgm_c_ciph;
EVP_CIPHER_CTX *ssl_mgm_c_ctx;

int ssl_mgm_c_setup(int msgLen, int adLen){
    randombytes_buf(ssl_mgm_c_key, sizeof ssl_mgm_c_key);
    randombytes_buf(ssl_mgm_c_nonce, sizeof ssl_mgm_c_nonce);
    ssl_mgm_c_msg = getRandomMessage(msgLen + SSL_MGM_IVLEN);
    ssl_mgm_c_ad = getRandomMessage(adLen);
    ssl_mgm_c_msgLen = msgLen;
    ssl_mgm_c_adLen = adLen;
    ssl_mgm_c_ctx = EVP_CIPHER_CTX_new();

    OPENSSL_add_all_algorithms_conf();
    ssl_mgm_c_ciph = (EVP_CIPHER *)EVP_get_cipherbyname(SN_kuznyechik_mgm_c);
    if (!ssl_mgm_c_ciph) {
        printf("failed to load %s\n", SN_kuznyechik_mgm_c);
        return 1;
    }
    ssl_mgm_c_initialized = 1;
    return 0;
}

int ssl_mgm_c_cleanup(){
    memset(ssl_mgm_c_key, 0, sizeof ssl_mgm_c_key);
    memset(ssl_mgm_c_nonce, 0, sizeof ssl_mgm_c_nonce);
    free(ssl_mgm_c_msg);
    free(ssl_mgm_c_ad);
    ssl_mgm_c_msgLen = 0;
    ssl_mgm_c_adLen = 0;
    EVP_CIPHER_free(ssl_mgm_c_ciph);
    EVP_CIPHER_CTX_free(ssl_mgm_c_ctx);
    ssl_mgm_c_initialized = 0;
    return 0;
}

void ssl_mgm_c_loop(){
    unsigned int msgLen = ssl_mgm_c_msgLen,
     adLen = ssl_mgm_c_adLen;
    ssl_mgm_c_cleanup();
    ssl_mgm_c_setup(msgLen, adLen);
}

void ssl_mgm_c_enc(){
    ssl_encrypt(ssl_mgm_c_ctx, ssl_mgm_c_ciph,
                ssl_mgm_c_msg, ssl_mgm_c_msgLen,
                ssl_mgm_c_ad, ssl_mgm_c_adLen,
                ssl_mgm_c_key, ssl_mgm_c_nonce, SSL_MGM_IVLEN,
                ssl_mgm_c_msg, ssl_mgm_c_nonce, SSL_MGM_IVLEN);
}

#pragma endregion
//end ossl mgm clmul

//ossl mgm clmul late reduction
#pragma region mgm_cl

#define SN_kuznyechik_mgm_cl "kuznyechik-mgm-cl"

int ssl_mgm_cl_initialized = 0;
unsigned char ssl_mgm_cl_nonce[SSL_MGM_IVLEN];
unsigned char ssl_mgm_cl_key[SSL_GCM_KEYLEN];
unsigned char *ssl_mgm_cl_msg;
unsigned char *ssl_mgm_cl_ad;
unsigned int ssl_mgm_cl_msgLen;
unsigned int ssl_mgm_cl_adLen;
EVP_CIPHER *ssl_mgm_cl_ciph;
EVP_CIPHER_CTX *ssl_mgm_cl_ctx;

int ssl_mgm_cl_setup(int msgLen, int adLen){
    randombytes_buf(ssl_mgm_cl_key, sizeof ssl_mgm_cl_key);
    randombytes_buf(ssl_mgm_cl_nonce, sizeof ssl_mgm_cl_nonce);
    ssl_mgm_cl_msg = getRandomMessage(msgLen + SSL_MGM_IVLEN);
    ssl_mgm_cl_ad = getRandomMessage(adLen);
    ssl_mgm_cl_msgLen = msgLen;
    ssl_mgm_cl_adLen = adLen;
    ssl_mgm_cl_ctx = EVP_CIPHER_CTX_new();

    OPENSSL_add_all_algorithms_conf();
    ssl_mgm_cl_ciph = (EVP_CIPHER *)EVP_get_cipherbyname(SN_kuznyechik_mgm_cl);
    if (!ssl_mgm_cl_ciph) {
        printf("failed to load %s\n", SN_kuznyechik_mgm_cl);
        return 1;
    }
    ssl_mgm_cl_initialized = 1;
    return 0;
}

int ssl_mgm_cl_cleanup(){
    memset(ssl_mgm_cl_key, 0, sizeof ssl_mgm_cl_key);
    memset(ssl_mgm_cl_nonce, 0, sizeof ssl_mgm_cl_nonce);
    free(ssl_mgm_cl_msg);
    free(ssl_mgm_cl_ad);
    ssl_mgm_cl_msgLen = 0;
    ssl_mgm_cl_adLen = 0;
    EVP_CIPHER_free(ssl_mgm_cl_ciph);
    EVP_CIPHER_CTX_free(ssl_mgm_cl_ctx);
    ssl_mgm_cl_initialized = 0;
    return 0;
}

void ssl_mgm_cl_loop(){
    unsigned int msgLen = ssl_mgm_cl_msgLen,
     adLen = ssl_mgm_cl_adLen;
    ssl_mgm_cl_cleanup();
    _mm_mfence();
    _mm_lfence();
    ssl_mgm_cl_setup(msgLen, adLen);
}

void ssl_mgm_cl_enc(){
    ssl_encrypt(ssl_mgm_cl_ctx, ssl_mgm_cl_ciph,
                ssl_mgm_cl_msg, ssl_mgm_cl_msgLen,
                ssl_mgm_cl_ad, ssl_mgm_cl_adLen,
                ssl_mgm_cl_key, ssl_mgm_cl_nonce, SSL_MGM_IVLEN,
                ssl_mgm_cl_msg, ssl_mgm_cl_nonce, SSL_MGM_IVLEN);
}

#pragma endregion
//end ossl mgm clmul late reduction

//ossl mgm clmul late reduction NMH
#pragma region mgm_cln

#define SN_kuznyechik_mgm_cln "kuznyechik-mgm-cln"

int ssl_mgm_cln_initialized = 0;
unsigned char ssl_mgm_cln_nonce[SSL_MGM_IVLEN];
unsigned char ssl_mgm_cln_key[SSL_GCM_KEYLEN];
unsigned char *ssl_mgm_cln_msg;
unsigned char *ssl_mgm_cln_ad;
unsigned int ssl_mgm_cln_msgLen;
unsigned int ssl_mgm_cln_adLen;
EVP_CIPHER *ssl_mgm_cln_ciph;
EVP_CIPHER_CTX *ssl_mgm_cln_ctx;

int ssl_mgm_cln_setup(int msgLen, int adLen){
    randombytes_buf(ssl_mgm_cln_key, sizeof ssl_mgm_cln_key);
    randombytes_buf(ssl_mgm_cln_nonce, sizeof ssl_mgm_cln_nonce);
    ssl_mgm_cln_msg = getRandomMessage(msgLen + SSL_MGM_IVLEN);
    ssl_mgm_cln_ad = getRandomMessage(adLen);
    ssl_mgm_cln_msgLen = msgLen;
    ssl_mgm_cln_adLen = adLen;
    ssl_mgm_cln_ctx = EVP_CIPHER_CTX_new();

    OPENSSL_add_all_algorithms_conf();
    ssl_mgm_cln_ciph = (EVP_CIPHER *)EVP_get_cipherbyname(SN_kuznyechik_mgm_cln);
    if (!ssl_mgm_cln_ciph) {
        printf("failed to load %s\n", SN_kuznyechik_mgm_cln);
        return 1;
    }
    ssl_mgm_cln_initialized = 1;
    return 0;
}

int ssl_mgm_cln_cleanup(){
    memset(ssl_mgm_cln_key, 0, sizeof ssl_mgm_cln_key);
    memset(ssl_mgm_cln_nonce, 0, sizeof ssl_mgm_cln_nonce);
    free(ssl_mgm_cln_msg);
    free(ssl_mgm_cln_ad);
    ssl_mgm_cln_msgLen = 0;
    ssl_mgm_cln_adLen = 0;
    EVP_CIPHER_free(ssl_mgm_cln_ciph);
    EVP_CIPHER_CTX_free(ssl_mgm_cln_ctx);
    ssl_mgm_cln_initialized = 0;
    return 0;
}

void ssl_mgm_cln_loop(){
    unsigned int msgLen = ssl_mgm_cln_msgLen,
     adLen = ssl_mgm_cln_adLen;
    ssl_mgm_cln_cleanup();
    ssl_mgm_cln_setup(msgLen, adLen);
}

void ssl_mgm_cln_enc(){
    ssl_encrypt(ssl_mgm_cln_ctx, ssl_mgm_cln_ciph,
                ssl_mgm_cln_msg, ssl_mgm_cln_msgLen,
                ssl_mgm_cln_ad, ssl_mgm_cln_adLen,
                ssl_mgm_cln_key, ssl_mgm_cln_nonce, SSL_MGM_IVLEN,
                ssl_mgm_cln_msg, ssl_mgm_cln_nonce, SSL_MGM_IVLEN);
}

#pragma endregion
//end ossl mgm clmul late reduction NMH

//ossl mgm clmul late reduction block optimised
#pragma region mgm_clo

#define SN_kuznyechik_mgm_clo "kuznyechik-mgm-clo"

int ssl_mgm_clo_initialized = 0;

unsigned char ssl_mgm_clo_nonce[SSL_MGM_IVLEN];
unsigned char ssl_mgm_clo_key[SSL_GCM_KEYLEN];
unsigned char *ssl_mgm_clo_msg;
unsigned char *ssl_mgm_clo_ad;
unsigned int ssl_mgm_clo_msgLen;
unsigned int ssl_mgm_clo_adLen;
EVP_CIPHER *ssl_mgm_clo_ciph;
EVP_CIPHER_CTX *ssl_mgm_clo_ctx;

int ssl_mgm_clo_setup(int msgLen, int adLen){
    randombytes_buf(ssl_mgm_clo_key, sizeof ssl_mgm_clo_key);
    randombytes_buf(ssl_mgm_clo_nonce, sizeof ssl_mgm_clo_nonce);
    ssl_mgm_clo_msg = getRandomMessage(msgLen + SSL_MGM_IVLEN);
    ssl_mgm_clo_ad = getRandomMessage(adLen);
    ssl_mgm_clo_msgLen = msgLen;
    ssl_mgm_clo_adLen = adLen;
    ssl_mgm_clo_ctx = EVP_CIPHER_CTX_new();

    OPENSSL_add_all_algorithms_conf();
    ssl_mgm_clo_ciph = (EVP_CIPHER *)EVP_get_cipherbyname(SN_kuznyechik_mgm_clo);
    if (!ssl_mgm_clo_ciph) {
        printf("failed to load %s\n", SN_kuznyechik_mgm_clo);
        return 1;
    }
    ssl_mgm_clo_initialized = 1;
    return 0;
}

int ssl_mgm_clo_cleanup(){
    memset(ssl_mgm_clo_key, 0, sizeof ssl_mgm_clo_key);
    memset(ssl_mgm_clo_nonce, 0, sizeof ssl_mgm_clo_nonce);
    free(ssl_mgm_clo_msg);
    free(ssl_mgm_clo_ad);
    ssl_mgm_clo_msgLen = 0;
    ssl_mgm_clo_adLen = 0;
    EVP_CIPHER_free(ssl_mgm_clo_ciph);
    EVP_CIPHER_CTX_free(ssl_mgm_clo_ctx);
    ssl_mgm_clo_initialized = 0;
    return 0;
}

void ssl_mgm_clo_loop(){
    unsigned int msgLen = ssl_mgm_clo_msgLen,
     adLen = ssl_mgm_clo_adLen;
    ssl_mgm_clo_cleanup();
    ssl_mgm_clo_setup(msgLen, adLen);
}

void ssl_mgm_clo_enc(){
    ssl_encrypt(ssl_mgm_clo_ctx, ssl_mgm_clo_ciph,
                ssl_mgm_clo_msg, ssl_mgm_clo_msgLen,
                ssl_mgm_clo_ad, ssl_mgm_clo_adLen,
                ssl_mgm_clo_key, ssl_mgm_clo_nonce, SSL_MGM_IVLEN,
                ssl_mgm_clo_msg, ssl_mgm_clo_nonce, SSL_MGM_IVLEN);
}

#pragma endregion
//end ossl mgm clmul late reduction block optimised

//ossl mgm clmul late reduction NMH block optimised
#pragma region mgm_clno

#define SN_kuznyechik_mgm_clno "kuznyechik-mgm-clno"

int ssl_mgm_clno_initialized = 0;
unsigned char ssl_mgm_clno_nonce[SSL_MGM_IVLEN];
unsigned char ssl_mgm_clno_key[SSL_GCM_KEYLEN];
unsigned char *ssl_mgm_clno_msg;
unsigned char *ssl_mgm_clno_ad;
unsigned int ssl_mgm_clno_msgLen;
unsigned int ssl_mgm_clno_adLen;
EVP_CIPHER *ssl_mgm_clno_ciph;
EVP_CIPHER_CTX *ssl_mgm_clno_ctx;

int ssl_mgm_clno_setup(int msgLen, int adLen){
    randombytes_buf(ssl_mgm_clno_key, sizeof ssl_mgm_clno_key);
    randombytes_buf(ssl_mgm_clno_nonce, sizeof ssl_mgm_clno_nonce);
    ssl_mgm_clno_msg = getRandomMessage(msgLen + SSL_MGM_IVLEN);
    ssl_mgm_clno_ad = getRandomMessage(adLen);
    ssl_mgm_clno_msgLen = msgLen;
    ssl_mgm_clno_adLen = adLen;
    ssl_mgm_clno_ctx = EVP_CIPHER_CTX_new();

    OPENSSL_add_all_algorithms_conf();
    ssl_mgm_clno_ciph = (EVP_CIPHER *)EVP_get_cipherbyname(SN_kuznyechik_mgm_clno);
    if (!ssl_mgm_clno_ciph) {
        printf("failed to load %s\n", SN_kuznyechik_mgm_clno);
        return 1;
    }
    ssl_mgm_clno_initialized = 1;
    return 0;
}

int ssl_mgm_clno_cleanup(){
    memset(ssl_mgm_clno_key, 0, sizeof ssl_mgm_clno_key);
    memset(ssl_mgm_clno_nonce, 0, sizeof ssl_mgm_clno_nonce);
    free(ssl_mgm_clno_msg);
    free(ssl_mgm_clno_ad);
    ssl_mgm_clno_msgLen = 0;
    ssl_mgm_clno_adLen = 0;
    EVP_CIPHER_free(ssl_mgm_clno_ciph);
    EVP_CIPHER_CTX_free(ssl_mgm_clno_ctx);
    ssl_mgm_clno_initialized = 0;
    return 0;
}

void ssl_mgm_clno_loop(){
    unsigned int msgLen = ssl_mgm_clno_msgLen,
     adLen = ssl_mgm_clno_adLen;
    ssl_mgm_clno_cleanup();
    ssl_mgm_clno_setup(msgLen, adLen);
}

void ssl_mgm_clno_enc(){
    ssl_encrypt(ssl_mgm_clno_ctx, ssl_mgm_clno_ciph,
                ssl_mgm_clno_msg, ssl_mgm_clno_msgLen,
                ssl_mgm_clno_ad, ssl_mgm_clno_adLen,
                ssl_mgm_clno_key, ssl_mgm_clno_nonce, SSL_MGM_IVLEN,
                ssl_mgm_clno_msg, ssl_mgm_clno_nonce, SSL_MGM_IVLEN);
}

#pragma endregion
//end ossl mgm clmul late reduction NMH block optimised

//ossl mgm aes
#pragma region mgm_a

#define SN_kuznyechik_mgm_a "kuznyechik-mgm-a"

int ssl_mgm_a_initialized = 0;
unsigned char ssl_mgm_a_nonce[SSL_MGM_IVLEN];
unsigned char ssl_mgm_a_key[SSL_GCM_KEYLEN];
unsigned char *ssl_mgm_a_msg;
unsigned char *ssl_mgm_a_ad;
unsigned int ssl_mgm_a_msgLen;
unsigned int ssl_mgm_a_adLen;
EVP_CIPHER *ssl_mgm_a_ciph;
EVP_CIPHER_CTX *ssl_mgm_a_ctx;

int ssl_mgm_a_setup(int msgLen, int adLen){
    randombytes_buf(ssl_mgm_a_key, sizeof ssl_mgm_a_key);
    randombytes_buf(ssl_mgm_a_nonce, sizeof ssl_mgm_a_nonce);
    ssl_mgm_a_msg = getRandomMessage(msgLen + SSL_MGM_IVLEN);
    ssl_mgm_a_ad = getRandomMessage(adLen);
    ssl_mgm_a_msgLen = msgLen;
    ssl_mgm_a_adLen = adLen;
    ssl_mgm_a_ctx = EVP_CIPHER_CTX_new();

    OPENSSL_add_all_algorithms_conf();
    ssl_mgm_a_ciph = (EVP_CIPHER *)EVP_get_cipherbyname(SN_kuznyechik_mgm_a);
    if (!ssl_mgm_a_ciph) {
        printf("failed to load %s\n", SN_kuznyechik_mgm_a);
        return 1;
    }
    ssl_mgm_a_initialized = 1;
    return 0;
}

int ssl_mgm_a_cleanup(){
    memset(ssl_mgm_a_key, 0, sizeof ssl_mgm_a_key);
    memset(ssl_mgm_a_nonce, 0, sizeof ssl_mgm_a_nonce);
    free(ssl_mgm_a_msg);
    free(ssl_mgm_a_ad);
    ssl_mgm_a_msgLen = 0;
    ssl_mgm_a_adLen = 0;
    EVP_CIPHER_free(ssl_mgm_a_ciph);
    EVP_CIPHER_CTX_free(ssl_mgm_a_ctx);
    ssl_mgm_a_initialized = 0;
    return 0;
}

void ssl_mgm_a_loop(){
    unsigned int msgLen = ssl_mgm_a_msgLen,
     adLen = ssl_mgm_a_adLen;
    ssl_mgm_a_cleanup();
    ssl_mgm_a_setup(msgLen, adLen);
}

void ssl_mgm_a_enc(){
    ssl_encrypt(ssl_mgm_a_ctx, ssl_mgm_a_ciph,
                ssl_mgm_a_msg, ssl_mgm_a_msgLen,
                ssl_mgm_a_ad, ssl_mgm_a_adLen,
                ssl_mgm_a_key, ssl_mgm_a_nonce, SSL_MGM_IVLEN,
                ssl_mgm_a_msg, ssl_mgm_a_nonce, SSL_MGM_IVLEN);
}

#pragma endregion
//end ossl mgm aes

#pragma region mgm_ab

#define SN_kuznyechik_mgm_ab "kuznyechik-mgm-ab"

int ssl_mgm_ab_initialized = 0;
unsigned char ssl_mgm_ab_nonce[SSL_MGM_IVLEN];
unsigned char ssl_mgm_ab_key[SSL_GCM_KEYLEN];
unsigned char *ssl_mgm_ab_msg;
unsigned char *ssl_mgm_ab_ad;
unsigned int ssl_mgm_ab_msgLen;
unsigned int ssl_mgm_ab_adLen;
EVP_CIPHER *ssl_mgm_ab_ciph;
EVP_CIPHER_CTX *ssl_mgm_ab_ctx;

int ssl_mgm_ab_setup(int msgLen, int adLen){
    randombytes_buf(ssl_mgm_ab_key, sizeof ssl_mgm_ab_key);
    randombytes_buf(ssl_mgm_ab_nonce, sizeof ssl_mgm_ab_nonce);
    ssl_mgm_ab_msg = getRandomMessage(msgLen + SSL_MGM_IVLEN);
    ssl_mgm_ab_ad = getRandomMessage(adLen);
    ssl_mgm_ab_msgLen = msgLen;
    ssl_mgm_ab_adLen = adLen;
    ssl_mgm_ab_ctx = EVP_CIPHER_CTX_new();

    OPENSSL_add_all_algorithms_conf();
    ssl_mgm_ab_ciph = (EVP_CIPHER *)EVP_get_cipherbyname(SN_kuznyechik_mgm_ab);
    if (!ssl_mgm_ab_ciph) {
        printf("failed to load %s\n", SN_kuznyechik_mgm_ab);
        return 1;
    }
    ssl_mgm_ab_initialized = 1;
    return 0;
}

int ssl_mgm_ab_cleanup(){
    memset(ssl_mgm_ab_key, 0, sizeof ssl_mgm_ab_key);
    memset(ssl_mgm_ab_nonce, 0, sizeof ssl_mgm_ab_nonce);
    free(ssl_mgm_ab_msg);
    free(ssl_mgm_ab_ad);
    ssl_mgm_ab_msgLen = 0;
    ssl_mgm_ab_adLen = 0;
    EVP_CIPHER_free(ssl_mgm_ab_ciph);
    EVP_CIPHER_CTX_free(ssl_mgm_ab_ctx);
    ssl_mgm_ab_initialized = 0;
    return 0;
}

void ssl_mgm_ab_loop(){
    unsigned int msgLen = ssl_mgm_ab_msgLen,
     adLen = ssl_mgm_ab_adLen;
    ssl_mgm_ab_cleanup();
    ssl_mgm_ab_setup(msgLen, adLen);
}

void ssl_mgm_ab_enc(){
    ssl_encrypt(ssl_mgm_ab_ctx, ssl_mgm_ab_ciph,
                ssl_mgm_ab_msg, ssl_mgm_ab_msgLen,
                ssl_mgm_ab_ad, ssl_mgm_ab_adLen,
                ssl_mgm_ab_key, ssl_mgm_ab_nonce, SSL_MGM_IVLEN,
                ssl_mgm_ab_msg, ssl_mgm_ab_nonce, SSL_MGM_IVLEN);
}

#pragma endregion
//end ossl mgm aes block processing

//ossl mgm aes deprecated
#pragma region mgm_ad

#define SN_kuznyechik_mgm_ad "kuznyechik-mgm-ad"

int ssl_mgm_ad_initialized = 0;

unsigned char ssl_mgm_ad_nonce[SSL_MGM_IVLEN];
unsigned char ssl_mgm_ad_key[SSL_GCM_KEYLEN];
unsigned char *ssl_mgm_ad_msg;
unsigned char *ssl_mgm_ad_ad;
unsigned int ssl_mgm_ad_msgLen;
unsigned int ssl_mgm_ad_adLen;
EVP_CIPHER *ssl_mgm_ad_ciph;
EVP_CIPHER_CTX *ssl_mgm_ad_ctx;

int ssl_mgm_ad_setup(int msgLen, int adLen){
    randombytes_buf(ssl_mgm_ad_key, sizeof ssl_mgm_ad_key);
    randombytes_buf(ssl_mgm_ad_nonce, sizeof ssl_mgm_ad_nonce);
    ssl_mgm_ad_msg = getRandomMessage(msgLen + SSL_MGM_IVLEN);
    ssl_mgm_ad_ad = getRandomMessage(adLen);
    ssl_mgm_ad_msgLen = msgLen;
    ssl_mgm_ad_adLen = adLen;
    ssl_mgm_ad_ctx = EVP_CIPHER_CTX_new();

    OPENSSL_add_all_algorithms_conf();
    ssl_mgm_ad_ciph = (EVP_CIPHER *)EVP_get_cipherbyname(SN_kuznyechik_mgm_ad);
    if (!ssl_mgm_ad_ciph) {
        printf("failed to load %s\n", SN_kuznyechik_mgm_ad);
        return 1;
    }
    ssl_mgm_ad_initialized = 1;
    return 0;
}

int ssl_mgm_ad_cleanup(){
    memset(ssl_mgm_ad_key, 0, sizeof ssl_mgm_ad_key);
    memset(ssl_mgm_ad_nonce, 0, sizeof ssl_mgm_ad_nonce);
    free(ssl_mgm_ad_msg);
    free(ssl_mgm_ad_ad);
    ssl_mgm_ad_msgLen = 0;
    ssl_mgm_ad_adLen = 0;
    EVP_CIPHER_free(ssl_mgm_ad_ciph);
    EVP_CIPHER_CTX_free(ssl_mgm_ad_ctx);
    ssl_mgm_ad_initialized = 0;
    return 0;
}

void ssl_mgm_ad_loop(){
    unsigned int msgLen = ssl_mgm_ad_msgLen,
     adLen = ssl_mgm_ad_adLen;
    ssl_mgm_ad_cleanup();
    ssl_mgm_ad_setup(msgLen, adLen);
}

void ssl_mgm_ad_enc(){
    ssl_encrypt(ssl_mgm_ad_ctx, ssl_mgm_ad_ciph,
                ssl_mgm_ad_msg, ssl_mgm_ad_msgLen,
                ssl_mgm_ad_ad, ssl_mgm_ad_adLen,
                ssl_mgm_ad_key, ssl_mgm_ad_nonce, SSL_MGM_IVLEN,
                ssl_mgm_ad_msg, ssl_mgm_ad_nonce, SSL_MGM_IVLEN);
}

#pragma endregion
//end ossl mgm aes deprecated

//ossl mgm aes clmul
#pragma region mgm_ac

#define SN_kuznyechik_mgm_ac "kuznyechik-mgm-ac"

int ssl_mgm_ac_initialized = 0;
unsigned char ssl_mgm_ac_nonce[SSL_MGM_IVLEN];
unsigned char ssl_mgm_ac_key[SSL_GCM_KEYLEN];
unsigned char *ssl_mgm_ac_msg;
unsigned char *ssl_mgm_ac_ad;
unsigned int ssl_mgm_ac_msgLen;
unsigned int ssl_mgm_ac_adLen;
EVP_CIPHER *ssl_mgm_ac_ciph;
EVP_CIPHER_CTX *ssl_mgm_ac_ctx;

int ssl_mgm_ac_setup(int msgLen, int adLen){
    randombytes_buf(ssl_mgm_ac_key, sizeof ssl_mgm_ac_key);
    randombytes_buf(ssl_mgm_ac_nonce, sizeof ssl_mgm_ac_nonce);
    ssl_mgm_ac_msg = getRandomMessage(msgLen + SSL_MGM_IVLEN);
    ssl_mgm_ac_ad = getRandomMessage(adLen);
    ssl_mgm_ac_msgLen = msgLen;
    ssl_mgm_ac_adLen = adLen;
    ssl_mgm_ac_ctx = EVP_CIPHER_CTX_new();

    OPENSSL_add_all_algorithms_conf();
    ssl_mgm_ac_ciph = (EVP_CIPHER *)EVP_get_cipherbyname(SN_kuznyechik_mgm_ac);
    if (!ssl_mgm_ac_ciph) {
        printf("failed to load %s\n", SN_kuznyechik_mgm_ac);
        return 1;
    }
    ssl_mgm_ac_initialized = 1;
    return 0;
}

int ssl_mgm_ac_cleanup(){
    memset(ssl_mgm_ac_key, 0, sizeof ssl_mgm_ac_key);
    memset(ssl_mgm_ac_nonce, 0, sizeof ssl_mgm_ac_nonce);
    free(ssl_mgm_ac_msg);
    free(ssl_mgm_ac_ad);
    ssl_mgm_ac_msgLen = 0;
    ssl_mgm_ac_adLen = 0;
    EVP_CIPHER_free(ssl_mgm_ac_ciph);
    EVP_CIPHER_CTX_free(ssl_mgm_ac_ctx);
    ssl_mgm_ac_initialized = 0;
    return 0;
}

void ssl_mgm_ac_loop(){
    unsigned int msgLen = ssl_mgm_ac_msgLen,
     adLen = ssl_mgm_ac_adLen;
    ssl_mgm_ac_cleanup();
    ssl_mgm_ac_setup(msgLen, adLen);
}

void ssl_mgm_ac_enc(){
    ssl_encrypt(ssl_mgm_ac_ctx, ssl_mgm_ac_ciph,
                ssl_mgm_ac_msg, ssl_mgm_ac_msgLen,
                ssl_mgm_ac_ad, ssl_mgm_ac_adLen,
                ssl_mgm_ac_key, ssl_mgm_ac_nonce, SSL_MGM_IVLEN,
                ssl_mgm_ac_msg, ssl_mgm_ac_nonce, SSL_MGM_IVLEN);
}

#pragma endregion
//end ossl mgm aes clmul

//ossl mgm aes clmul late reduction
#pragma region mgm_acl

#define SN_kuznyechik_mgm_acl "kuznyechik-mgm-acl"

int ssl_mgm_acl_initialized = 0;
unsigned char ssl_mgm_acl_nonce[SSL_MGM_IVLEN];
unsigned char ssl_mgm_acl_key[SSL_GCM_KEYLEN];
unsigned char *ssl_mgm_acl_msg;
unsigned char *ssl_mgm_acl_ad;
unsigned int ssl_mgm_acl_msgLen;
unsigned int ssl_mgm_acl_adLen;
EVP_CIPHER *ssl_mgm_acl_ciph;
EVP_CIPHER_CTX *ssl_mgm_acl_ctx;

int ssl_mgm_acl_setup(int msgLen, int adLen){
    randombytes_buf(ssl_mgm_acl_key, sizeof ssl_mgm_acl_key);
    randombytes_buf(ssl_mgm_acl_nonce, sizeof ssl_mgm_acl_nonce);
    ssl_mgm_acl_msg = getRandomMessage(msgLen + SSL_MGM_IVLEN);
    ssl_mgm_acl_ad = getRandomMessage(adLen);
    ssl_mgm_acl_msgLen = msgLen;
    ssl_mgm_acl_adLen = adLen;
    ssl_mgm_acl_ctx = EVP_CIPHER_CTX_new();

    OPENSSL_add_all_algorithms_conf();
    ssl_mgm_acl_ciph = (EVP_CIPHER *)EVP_get_cipherbyname(SN_kuznyechik_mgm_acl);
    if (!ssl_mgm_acl_ciph) {
        printf("failed to load %s\n", SN_kuznyechik_mgm_acl);
        return 1;
    }
    ssl_mgm_acl_initialized = 1;
    return 0;
}

int ssl_mgm_acl_cleanup(){
    memset(ssl_mgm_acl_key, 0, sizeof ssl_mgm_acl_key);
    memset(ssl_mgm_acl_nonce, 0, sizeof ssl_mgm_acl_nonce);
    free(ssl_mgm_acl_msg);
    free(ssl_mgm_acl_ad);
    ssl_mgm_acl_msgLen = 0;
    ssl_mgm_acl_adLen = 0;
    EVP_CIPHER_free(ssl_mgm_acl_ciph);
    EVP_CIPHER_CTX_free(ssl_mgm_acl_ctx);
    ssl_mgm_acl_initialized = 0;
    return 0;
}

void ssl_mgm_acl_loop(){
    unsigned int msgLen = ssl_mgm_acl_msgLen,
     adLen = ssl_mgm_acl_adLen;
    ssl_mgm_acl_cleanup();
    ssl_mgm_acl_setup(msgLen, adLen);
}

void ssl_mgm_acl_enc(){
    ssl_encrypt(ssl_mgm_acl_ctx, ssl_mgm_acl_ciph,
                ssl_mgm_acl_msg, ssl_mgm_acl_msgLen,
                ssl_mgm_acl_ad, ssl_mgm_acl_adLen,
                ssl_mgm_acl_key, ssl_mgm_acl_nonce, SSL_MGM_IVLEN,
                ssl_mgm_acl_msg, ssl_mgm_acl_nonce, SSL_MGM_IVLEN);
}

#pragma endregion
//end ossl mgm aes clmul late reduction

//ossl mgm aes clmul late reduction NMH
#pragma region mgm_acln

#define SN_kuznyechik_mgm_acln "kuznyechik-mgm-acln"

int ssl_mgm_acln_initialized = 0;
unsigned char ssl_mgm_acln_nonce[SSL_MGM_IVLEN];
unsigned char ssl_mgm_acln_key[SSL_GCM_KEYLEN];
unsigned char *ssl_mgm_acln_msg;
unsigned char *ssl_mgm_acln_ad;
unsigned int ssl_mgm_acln_msgLen;
unsigned int ssl_mgm_acln_adLen;
EVP_CIPHER *ssl_mgm_acln_ciph;
EVP_CIPHER_CTX *ssl_mgm_acln_ctx;

int ssl_mgm_acln_setup(int msgLen, int adLen){
    randombytes_buf(ssl_mgm_acln_key, sizeof ssl_mgm_acln_key);
    randombytes_buf(ssl_mgm_acln_nonce, sizeof ssl_mgm_acln_nonce);
    ssl_mgm_acln_msg = getRandomMessage(msgLen + SSL_MGM_IVLEN);
    ssl_mgm_acln_ad = getRandomMessage(adLen);
    ssl_mgm_acln_msgLen = msgLen;
    ssl_mgm_acln_adLen = adLen;
    ssl_mgm_acln_ctx = EVP_CIPHER_CTX_new();

    OPENSSL_add_all_algorithms_conf();
    ssl_mgm_acln_ciph = (EVP_CIPHER *)EVP_get_cipherbyname(SN_kuznyechik_mgm_acln);
    if (!ssl_mgm_acln_ciph) {
        printf("failed to load %s\n", SN_kuznyechik_mgm_acln);
        return 1;
    }
    ssl_mgm_acln_initialized = 1;
    return 0;
}

int ssl_mgm_acln_cleanup(){
    memset(ssl_mgm_acln_key, 0, sizeof ssl_mgm_acln_key);
    memset(ssl_mgm_acln_nonce, 0, sizeof ssl_mgm_acln_nonce);
    free(ssl_mgm_acln_msg);
    free(ssl_mgm_acln_ad);
    ssl_mgm_acln_msgLen = 0;
    ssl_mgm_acln_adLen = 0;
    EVP_CIPHER_free(ssl_mgm_acln_ciph);
    EVP_CIPHER_CTX_free(ssl_mgm_acln_ctx);
    ssl_mgm_acln_initialized = 0;
    return 0;
}

void ssl_mgm_acln_loop(){
    unsigned int msgLen = ssl_mgm_acln_msgLen,
     adLen = ssl_mgm_acln_adLen;
    ssl_mgm_acln_cleanup();
    ssl_mgm_acln_setup(msgLen, adLen);
}

void ssl_mgm_acln_enc(){
    ssl_encrypt(ssl_mgm_acln_ctx, ssl_mgm_acln_ciph,
                ssl_mgm_acln_msg, ssl_mgm_acln_msgLen,
                ssl_mgm_acln_ad, ssl_mgm_acln_adLen,
                ssl_mgm_acln_key, ssl_mgm_acln_nonce, SSL_MGM_IVLEN,
                ssl_mgm_acln_msg, ssl_mgm_acln_nonce, SSL_MGM_IVLEN);
}

#pragma endregion
//end ossl mgm aes clmul late reduction NMH

//ossl mgm aes clmul late reduction block optimised
#pragma region mgm_aclo

#define SN_kuznyechik_mgm_aclo "kuznyechik-mgm-aclo"

int ssl_mgm_aclo_initialized = 0;
unsigned char ssl_mgm_aclo_nonce[SSL_MGM_IVLEN];
unsigned char ssl_mgm_aclo_key[SSL_GCM_KEYLEN];
unsigned char *ssl_mgm_aclo_msg;
unsigned char *ssl_mgm_aclo_ad;
unsigned int ssl_mgm_aclo_msgLen;
unsigned int ssl_mgm_aclo_adLen;
EVP_CIPHER *ssl_mgm_aclo_ciph;
EVP_CIPHER_CTX *ssl_mgm_aclo_ctx;

int ssl_mgm_aclo_setup(int msgLen, int adLen){
    randombytes_buf(ssl_mgm_aclo_key, sizeof ssl_mgm_aclo_key);
    randombytes_buf(ssl_mgm_aclo_nonce, sizeof ssl_mgm_aclo_nonce);
    ssl_mgm_aclo_msg = getRandomMessage(msgLen + SSL_MGM_IVLEN);
    ssl_mgm_aclo_ad = getRandomMessage(adLen);
    ssl_mgm_aclo_msgLen = msgLen;
    ssl_mgm_aclo_adLen = adLen;
    ssl_mgm_aclo_ctx = EVP_CIPHER_CTX_new();

    OPENSSL_add_all_algorithms_conf();
    ssl_mgm_aclo_ciph = (EVP_CIPHER *)EVP_get_cipherbyname(SN_kuznyechik_mgm_aclo);
    if (!ssl_mgm_aclo_ciph) {
        printf("failed to load %s\n", SN_kuznyechik_mgm_aclo);
        return 1;
    }
    ssl_mgm_aclo_initialized = 1;
    return 0;
}

int ssl_mgm_aclo_cleanup(){
    memset(ssl_mgm_aclo_key, 0, sizeof ssl_mgm_aclo_key);
    memset(ssl_mgm_aclo_nonce, 0, sizeof ssl_mgm_aclo_nonce);
    free(ssl_mgm_aclo_msg);
    free(ssl_mgm_aclo_ad);
    ssl_mgm_aclo_msgLen = 0;
    ssl_mgm_aclo_adLen = 0;
    EVP_CIPHER_free(ssl_mgm_aclo_ciph);
    EVP_CIPHER_CTX_free(ssl_mgm_aclo_ctx);
    ssl_mgm_aclo_initialized = 0;
    return 0;
}

void ssl_mgm_aclo_loop(){
    unsigned int msgLen = ssl_mgm_aclo_msgLen,
     adLen = ssl_mgm_aclo_adLen;
    ssl_mgm_aclo_cleanup();
    ssl_mgm_aclo_setup(msgLen, adLen);
}

void ssl_mgm_aclo_enc(){
    ssl_encrypt(ssl_mgm_aclo_ctx, ssl_mgm_aclo_ciph,
                ssl_mgm_aclo_msg, ssl_mgm_aclo_msgLen,
                ssl_mgm_aclo_ad, ssl_mgm_aclo_adLen,
                ssl_mgm_aclo_key, ssl_mgm_aclo_nonce, SSL_MGM_IVLEN,
                ssl_mgm_aclo_msg, ssl_mgm_aclo_nonce, SSL_MGM_IVLEN);
}

#pragma endregion
//end ossl mgm aes clmul late reduction block optimised

//ossl mgm aes clmul late reduction NMH block optimised
#pragma region mgm_aclno

#define SN_kuznyechik_mgm_aclno "kuznyechik-mgm-aclno"

int ssl_mgm_aclno_initialized = 0;
unsigned char ssl_mgm_aclno_nonce[SSL_MGM_IVLEN];
unsigned char ssl_mgm_aclno_key[SSL_GCM_KEYLEN];
unsigned char *ssl_mgm_aclno_msg;
unsigned char *ssl_mgm_aclno_ad;
unsigned int ssl_mgm_aclno_msgLen;
unsigned int ssl_mgm_aclno_adLen;
EVP_CIPHER *ssl_mgm_aclno_ciph;
EVP_CIPHER_CTX *ssl_mgm_aclno_ctx;

int ssl_mgm_aclno_setup(int msgLen, int adLen){
    randombytes_buf(ssl_mgm_aclno_key, sizeof ssl_mgm_aclno_key);
    randombytes_buf(ssl_mgm_aclno_nonce, sizeof ssl_mgm_aclno_nonce);
    ssl_mgm_aclno_msg = getRandomMessage(msgLen + SSL_MGM_IVLEN);
    ssl_mgm_aclno_ad = getRandomMessage(adLen);
    ssl_mgm_aclno_msgLen = msgLen;
    ssl_mgm_aclno_adLen = adLen;
    ssl_mgm_aclno_ctx = EVP_CIPHER_CTX_new();
    OPENSSL_add_all_algorithms_conf();
    ssl_mgm_aclno_ciph = (EVP_CIPHER *)EVP_get_cipherbyname(SN_kuznyechik_mgm_aclno);
    if (!ssl_mgm_aclno_ciph) {
        printf("failed to load %s\n", SN_kuznyechik_mgm_aclno);
        return 1;
    }
    ssl_mgm_aclno_initialized = 1;
    return 0;
}

int ssl_mgm_aclno_cleanup(){
    memset(ssl_mgm_aclno_key, 0, sizeof ssl_mgm_aclno_key);
    memset(ssl_mgm_aclno_nonce, 0, sizeof ssl_mgm_aclno_nonce);
    free(ssl_mgm_aclno_msg);
    free(ssl_mgm_aclno_ad);
    ssl_mgm_aclno_msgLen = 0;
    ssl_mgm_aclno_adLen = 0;
    EVP_CIPHER_free(ssl_mgm_aclno_ciph);
    EVP_CIPHER_CTX_free(ssl_mgm_aclno_ctx);
    ssl_mgm_aclno_initialized = 0;
    return 0;
}

void ssl_mgm_aclno_loop(){
    unsigned int msgLen = ssl_mgm_aclno_msgLen,
     adLen = ssl_mgm_aclno_adLen;
    ssl_mgm_aclno_cleanup();
    ssl_mgm_aclno_setup(msgLen, adLen);
}

void ssl_mgm_aclno_enc(){
    ssl_encrypt(ssl_mgm_aclno_ctx, ssl_mgm_aclno_ciph,
                ssl_mgm_aclno_msg, ssl_mgm_aclno_msgLen,
                ssl_mgm_aclno_ad, ssl_mgm_aclno_adLen,
                ssl_mgm_aclno_key, ssl_mgm_aclno_nonce, SSL_MGM_IVLEN,
                ssl_mgm_aclno_msg, ssl_mgm_aclno_nonce, SSL_MGM_IVLEN);
}

#pragma endregion
//end ossl mgm aes clmul late reduction NMH block optimised

int lib_cleanup(){
    if(sodium_initialized){
        sodium_cleanup();
    }
    if(nettle_initialized){
        nettle_cleanup();
    }
    if(ssl_gcm_initialized){
        ssl_gcm_cleanup();
    }
    if(ssl_mgm_initialized){
        ssl_mgm_cleanup();
    }
    if(ssl_mgm_b_initialized){
        ssl_mgm_b_cleanup();
    }
    if(ssl_mgm_c_initialized){
        ssl_mgm_c_cleanup();
    }
    if(ssl_mgm_cl_initialized){
        ssl_mgm_cl_cleanup();
    }
    if(ssl_mgm_cln_initialized){
        ssl_mgm_cln_cleanup();
    }
    if(ssl_mgm_clo_initialized){
        ssl_mgm_clo_cleanup();
    }
    if(ssl_mgm_clno_initialized){
        ssl_mgm_clno_cleanup();
    }
    if(ssl_mgm_a_initialized){
        ssl_mgm_a_cleanup();
    }
    if(ssl_mgm_ab_initialized){
        ssl_mgm_ab_cleanup();
    }
    if(ssl_mgm_ad_initialized){
        ssl_mgm_ad_cleanup();
    }
    if(ssl_mgm_ac_initialized){
        ssl_mgm_ac_cleanup();
    }
    if(ssl_mgm_acl_initialized){
        ssl_mgm_acl_cleanup();
    }
    if(ssl_mgm_acln_initialized){
        ssl_mgm_acln_cleanup();
    }
    if(ssl_mgm_aclo_initialized){
        ssl_mgm_aclo_cleanup();
    }
    if(ssl_mgm_aclno_initialized){
        ssl_mgm_aclno_cleanup();
    }
}
