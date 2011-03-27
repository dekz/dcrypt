#ifndef __NODE_DCRYPT_CIPHER_H__
#define __NODE_DCRYPT_CIPHER_H__

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

using namespace v8;
using namespace node;

class Cipher: node::ObjectWrap {
  public:
    static Persistent<FunctionTemplate> constructor;
    static void Initialize(Handle<Object> target);
    bool CipherInit(char *cipherType, char *key_buf, int key_buf_len);
    bool CipherInitIv(char *cipherType, char *key, int key_len, char *iv, int iv_len);
    int CipherUpdate(char *data, int len, unsigned char **out, int *out_len);
    int CipherFinal(unsigned char **out, int *out_len);

    Cipher();
  protected:
    static Handle<Value> New(const Arguments &args);
    static Handle<Value> CipherInit(const Arguments &args);
    static Handle<Value> CipherInitIv(const Arguments &args);
    static Handle<Value> CipherUpdate(const Arguments &args);
    static Handle<Value> CipherFinal(const Arguments &args);

  private:
    EVP_CIPHER_CTX *ctx;
    const EVP_CIPHER *cipher;
    bool initialised_;
    char *incomplete_base64;
    int incomplete_base64_len;
    ~Cipher();
};
#endif

