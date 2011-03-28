#ifndef __NODE_DCRYPT_DECIPHER_H__
#define __NODE_DCRYPT_DECIPHER_H__

#include <v8.h>
#include <node.h>
#include <node_object_wrap.h>
#include <node_buffer.h>

#include <openssl/evp.h>
#include <openssl/err.h>

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include "common.h"
#define EVP_F_EVP_DECRYPTFINAL 101

using namespace v8;
using namespace node;
class Decipher: node::ObjectWrap {
  public:
    static Persistent<FunctionTemplate> constructor;
    static void Initialize(Handle<Object> target);
    bool DecipherInit(char *cipherType, char *key_buf, int key_buf_len);
    bool DecipherInitIv(char *cipherType, char *key, int key_len, char *iv, int iv_len);
    int DecipherUpdate(char *data, int len, unsigned char **out, int *out_len);
    int DecipherFinal(unsigned char **out, int *out_len, bool tolerate_padding);
int local_EVP_DecryptFinal_ex(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl);    

    Decipher();
  protected:
    static Handle<Value> New(const Arguments &args);
    static Handle<Value> DecipherInit(const Arguments &args);
    static Handle<Value> DecipherInitIv(const Arguments &args);
    static Handle<Value> DecipherUpdate(const Arguments &args);
    static Handle<Value> DecipherFinal(const Arguments &args);
    static Handle<Value> DecipherFinalTolerate(const Arguments &args);
  private:
    EVP_CIPHER_CTX *ctx;
    const EVP_CIPHER *cipher;
    bool initialised_;
    unsigned char *incomplete_utf8;
    int incomplete_utf8_len;
    char incomplete_hex;
    bool incomplete_hex_flag;
    ~Decipher();

};
#endif
